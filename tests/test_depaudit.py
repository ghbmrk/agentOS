# P1-6 dependency audit harness (spec A9). Tests the harness itself: strace
# parsing, the endpoint policy, the static endpoint scan, and the offline run.
# Makes no coverage claim for DEP-1–4: those are claimed by the packages whose
# scenarios pass this harness (broker P1-2 onward).
import ast
import contextlib
import errno
import grp
import inspect
import io
import json
import os
import pathlib
import pwd
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import depaudit  # noqa: E402

CONTROLS = [sys.executable, str(ROOT / "tools" / "depaudit_controls.py")]
HARNESS_CONTROLS = [sys.executable, str(ROOT / "tools" / "depaudit.py"), "_control"]

STRACE = """\
101 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.10")}, 16) = -1 ENETUNREACH (Network is unreachable)
101 connect(4, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
102 sendto(5, "\\x12", 33, MSG_NOSIGNAL, {sa_family=AF_INET6, sin6_port=htons(123), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH
102 connect(6, {sa_family=AF_INET6, sin6_port=htons(80), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28 <unfinished ...>
103 connect(7, {sa_family=AF_UNIX, sun_path="/run/systemd/resolve/io.systemd.Resolve"}, 110) = -1 ENOENT
103 connect(8, {sa_family=AF_UNIX, sun_path=@"abstract-name"}, 16) = 0
103 connect(9, {sa_family=AF_UNIX, sun_path="/WORK/tmp/sock"}, 110) = 0
104 sendmmsg(10, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16}}], 1, 0) = 1
104 connect(11, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0
105 connect(12, {sa_family=AF_VSOCK, svm_cid=VMADDR_CID_HOST, svm_port=1024}, 16) = 0
105 connect(13, {sa_family=AF_INET, sin_port=htons(80), sin_addr=something_new("x")}, 16) = 0
105 connect(14, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 0
105 connect(15, {sa_family=AF_UNSPEC, sa_data="\\0\\0"}, 16) = 0
106 connect(16, {sa_family=AF_UNIX, sun_path="@relative"}, 12) = -1 ENOENT
106 connect(17, {sa_family=AF_UNIX, sun_path="/WORK/tmp/../../var/lib/zz.sock"}, 110) = 0
106 symlink("/var/lib", "/WORK/tmp/l") = 0
106 symlinkat("sub/dir", AT_FDCWD, "/WORK/tmp/ok") = 0
106 linkat(AT_FDCWD, "/WORK/tmp/a", AT_FDCWD, "/WORK/tmp/b", 0) = 0
106 linkat(5, "x", AT_FDCWD, "/WORK/tmp/c", 0) = 0
106 mount("/var/lib", "/WORK/tmp/m", NULL, MS_BIND, NULL) = 0
"""

MANIFEST = {
    "forbidden_host_patterns": ["*agentos*"],
    "endpoints": [
        {"host": "mirror.example.net", "class": "optional", "dependency": "update mirror"},
        {"host": "198.51.100.7", "class": "inherent", "dependency": "frontier provider"},
    ],
}


class ParseTest(unittest.TestCase):
    def test_parses_every_family(self):
        ev = depaudit.parse_strace(STRACE)
        got = {(e.family, e.addr, e.port) for e in ev}
        self.assertIn(("inet", "192.0.2.10", 443), got)
        self.assertIn(("inet", "127.0.0.1", 8080), got)
        self.assertIn(("inet6", "2001:db8::1", 123), got)
        self.assertIn(("inet6", "::1", 80), got)
        self.assertIn(("unix", "/run/systemd/resolve/io.systemd.Resolve", None), got)
        self.assertIn(("abstract", "abstract-name", None), got)
        self.assertIn(("unix", "@relative", None), got)
        self.assertIn(("link", "/var/lib", None), got)
        self.assertIn(("link", "<dirfd>/x", None), got)
        self.assertIn(("mount", "mount", None), got)
        self.assertIn(("inet", "8.8.8.8", 53), got)
        self.assertFalse(any(e.addr in ("AF_NETLINK", "AF_UNSPEC") for e in ev))

    def test_fails_closed_on_unknown_or_unparsed_sockaddrs(self):
        ev = depaudit.parse_strace(STRACE)
        self.assertIn(("other", "AF_VSOCK"), {(e.family, e.addr) for e in ev})
        self.assertIn(("unparsed", "AF_INET"), {(e.family, e.addr) for e in ev})
        nested = '106 sendmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(1), {weird}}, ...}, 0) = 1'
        self.assertEqual([e.family for e in depaudit.parse_strace(nested)], ["unparsed"])

    def test_parse_dns_query_name(self):
        q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07updates\x07example\x03com\x00\x00\x01\x00\x01")
        self.assertEqual(depaudit.dns_qname(q), ("updates.example.com", 1))


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.manifest = depaudit.load_manifest(MANIFEST)

    def kinds(self, profile, names=()):
        ev = depaudit.parse_strace(STRACE.replace("/WORK", "/w"))
        return sorted({(v["kind"], v["target"]) for v in
                       depaudit.evaluate(ev, list(names), self.manifest, profile, workdir="/w")})

    def test_offline_profile_allows_only_loopback_and_own_sockets(self):
        got = self.kinds("offline", ["mirror.example.net"])
        self.assertEqual(got, [
            ("dns", "loopback:53"),
            ("dns", "mirror.example.net"),
            ("host-socket", "/run/systemd/resolve/io.systemd.Resolve"),
            ("host-socket", "/w/tmp/../../var/lib/zz.sock"),
            ("host-socket", "@relative"),
            ("ipv4", "192.0.2.10:443"),
            ("ipv4", "8.8.8.8:53"),
            ("ipv6", "[2001:db8::1]:123"),
            ("link", "/var/lib"),
            ("link", "<dirfd>/x"),
            ("mount", "mount"),
            ("unknown-family", "AF_VSOCK"),
            ("unparsed", "AF_INET"),
        ])

    def test_symlinked_socket_path_is_judged_by_where_it_resolves(self):
        ev = depaudit.parse_strace('1 connect(3, {sa_family=AF_UNIX, sun_path="/w/tmp/l/p"}, 110) = 0')
        ok = depaudit.evaluate(ev, [], self.manifest, "offline", "/w", {"/w/tmp/l/p": "/w/tmp/real/p"})
        bad = depaudit.evaluate(ev, [], self.manifest, "offline", "/w", {"/w/tmp/l/p": "/srv/p"})
        self.assertEqual((ok, [v["kind"] for v in bad]), ([], ["host-socket"]))

    def test_full_profile_allows_declared_endpoints_only(self):
        got = self.kinds("full", ["mirror.example.net", "unknown.example.org"])
        self.assertIn(("dns", "unknown.example.org"), got)
        self.assertNotIn(("dns", "mirror.example.net"), got)
        self.assertIn(("ipv4", "192.0.2.10:443"), got)

    def test_forbidden_is_never_allowed(self):
        got = self.kinds("full", ["telemetry.agentos.example"])
        self.assertIn(("forbidden", "telemetry.agentos.example"), got)

    def test_manifest_rejects_declaring_a_forbidden_host(self):
        bad = dict(MANIFEST, endpoints=[{"host": "api.agentos.dev", "class": "optional", "dependency": "x"}])
        with self.assertRaises(ValueError):
            depaudit.load_manifest(bad)

    def test_manifest_rejects_unknown_class(self):
        bad = dict(MANIFEST, endpoints=[{"host": "a.example.net", "class": "nice-to-have", "dependency": "x"}])
        with self.assertRaises(ValueError):
            depaudit.load_manifest(bad)

    def test_shipped_manifest_loads(self):
        depaudit.load_manifest(json.loads((ROOT / "assurance" / "dependencies.json").read_text()))


class JudgeTest(unittest.TestCase):
    def test_control_whose_own_call_was_never_logged_fails(self):
        t = {"expect": "violation", "expect_kinds": ["host-socket"], "must_log": [("unix", "/../")]}
        res = {"outcome": "violation", "violations": [{"kind": "host-socket"}], "logged": ["unix /a/b"]}
        self.assertFalse(depaudit._judge(t, res)[0])
        res["logged"].append("unix /w/tmp/../../x/p")
        self.assertTrue(depaudit._judge(t, res)[0])

    def test_registry_accepts_only_plain_product_scenarios(self):
        with tempfile.TemporaryDirectory() as d:
            reg = pathlib.Path(d, "t.json")
            for t in ({"name": "x", "cmd": ["true"], "keep": ["/"]},
                      {"name": "x", "cmd": ["true"], "env": {"A": "1"}},
                      {"name": "x", "cmd": ["true"], "must_log": []},
                      {"name": "x", "cmd": ["true"], "writes": ["/"]}):
                reg.write_text(json.dumps({"targets": [t]}))
                with self.assertRaises(ValueError):
                    depaudit.load_registry(reg)
            reg.write_text(json.dumps({"targets": [{"name": "x", "cmd": ["true"]}]}))
            self.assertEqual(len(depaudit.load_registry(reg)), 1)


class StaticScanTest(unittest.TestCase):
    def scan(self, files):
        with tempfile.TemporaryDirectory() as d:
            for rel, text in files.items():
                p = pathlib.Path(d, rel)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            return depaudit.static_scan(pathlib.Path(d), depaudit.load_manifest(MANIFEST))

    def test_undeclared_url_in_shipping_code_is_flagged(self):
        v = self.scan({"broker/net.go": 'const u = "https://collector.vendor.io/v1"\n'})
        self.assertEqual([(x["kind"], x["target"]) for x in v], [("undeclared", "collector.vendor.io")])
        self.assertEqual(v[0]["location"], "broker/net.go:1")

    def test_forbidden_url_is_flagged_even_if_declared(self):
        m = self.scan({"src/a.py": 'U = "https://ping.agentos.example/x"\n'})
        self.assertEqual(m[0]["kind"], "forbidden")

    def test_declared_reserved_comments_and_tests_pass(self):
        v = self.scan({
            "broker/ok.go": 'var m = "https://mirror.example.net/pool"\n// see https://pkg.go.dev/net\n',
            "broker/docs.go": 'x := "http://localhost:8080/" + "https://a.example/" + "http://h.test/"\n',
            "broker/net_test.go": 'u := "https://collector.vendor.io"\n',
            "broker/testdata/f.json": '{"u": "https://collector.vendor.io"}\n',
            "spikes/x.py": 'U = "https://anything.io"\n',
        })
        self.assertEqual(v, [])

    def test_inert_literal_exempts_only_its_file_and_host(self):
        m = depaudit.load_manifest({"inert_literals": [
            {"file": "broker/vendor/x/png.go", "host": "meta.example.io", "why": "metadata"}]})
        with tempfile.TemporaryDirectory() as d:
            for rel in ("broker/vendor/x/png.go", "broker/vendor/x/net.go"):
                p = pathlib.Path(d, rel)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('var c = "http://meta.example.io/" + "https://other.vendor.io/"\n')
            v = sorted((x["location"], x["target"]) for x in depaudit.static_scan(pathlib.Path(d), m))
        self.assertEqual(v, [("broker/vendor/x/net.go:1", "meta.example.io"), ("broker/vendor/x/net.go:1", "other.vendor.io"),
                             ("broker/vendor/x/png.go:1", "other.vendor.io")])
        for bad in ({"file": "broker/net.go", "host": "h.io", "why": "x"},
                    {"file": "broker/x/vendor/y.go", "host": "h.io", "why": "x"},
                    {"file": "x/broker/vendor/y.go", "host": "h.io", "why": "x"},
                    {"file": "broker/vendor/../net.go", "host": "h.io", "why": "x"},
                    {"file": "broker/vendor/x.go", "host": "h.io"},
                    {"file": "broker/vendor/x.go", "host": "ping.agentos.io", "why": "x"}):
            with self.assertRaises(ValueError):
                depaudit.load_manifest({"forbidden_host_patterns": ["*agentos*"], "inert_literals": [bad]})


class ScratchDirTest(unittest.TestCase):
    # HK-1a (briefs/HK-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_cleanup_retries_when_a_late_writer_fills_the_directory(self):
        real, calls = shutil.rmtree, []

        def flaky(path, *a, **kw):
            calls.append(path)
            if len(calls) < 3:
                raise OSError(errno.ENOTEMPTY, "Directory not empty", "go-build1")
            return real(path, *a, **kw)
        stats = {"cleanup_retries": 0}
        with mock.patch.object(depaudit.shutil, "rmtree", flaky), \
                mock.patch.object(depaudit.time, "sleep"):
            with depaudit._scratch_dir("depaudit-test-", stats=stats) as d:
                pathlib.Path(d, "f").write_text("x")
        self.assertEqual(len(calls), 3)
        self.assertFalse(os.path.exists(d))
        # DEP-2c (briefs/DEP-2.md; a local ID with no SPEC row, so no REQ marker)
        self.assertEqual(stats["cleanup_retries"], 2)

    def test_cleanup_outlasts_a_real_straggler_writing_into_it(self):
        with depaudit._scratch_dir("depaudit-test-") as d:
            os.makedirs(os.path.join(d, "go-build1"))
            # Detached, as a tracee that strace let go of: it keeps creating files for ~1s.
            subprocess.Popen(["sh", "-c", 'for i in 1 2 3 4 5 6 7 8 9 10; do touch "$0/go-build1/f$i"; sleep 0.1; done',
                              d], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.assertFalse(os.path.exists(d))

    def test_a_directory_that_never_empties_still_raises(self):
        def stuck(path, *a, **kw):
            raise OSError(errno.ENOTEMPTY, "Directory not empty", "go-build1")
        with mock.patch.object(depaudit.shutil, "rmtree", stuck), mock.patch.object(depaudit.time, "sleep"):
            with self.assertRaises(OSError):
                with depaudit._scratch_dir("depaudit-test-"):
                    pass
        # leave nothing behind for the next test run
        for d in pathlib.Path(tempfile.gettempdir()).glob("depaudit-test-*"):
            shutil.rmtree(d, ignore_errors=True)

    def test_other_cleanup_errors_are_not_retried(self):
        calls = []

        def denied(path, *a, **kw):
            calls.append(path)
            raise PermissionError(errno.EACCES, "denied", path)
        with mock.patch.object(depaudit.shutil, "rmtree", denied), mock.patch.object(depaudit.time, "sleep"):
            with self.assertRaises(PermissionError):
                with depaudit._scratch_dir("depaudit-test-"):
                    pass
        self.assertEqual(len(calls), 1)
        for d in pathlib.Path(tempfile.gettempdir()).glob("depaudit-test-*"):
            shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(depaudit.sandbox_available(), "needs user+net namespaces and strace")
class OfflineRunTest(unittest.TestCase):
    def run_control(self, mode):
        return depaudit.run_target({"name": mode, "cmd": CONTROLS + [mode], "profile": "offline"},
                                   depaudit.load_manifest(MANIFEST))

    def test_clean_subject_passes(self):
        res = self.run_control("clean")
        self.assertEqual((res["outcome"], res["violations"]), ("pass", []), res)

    def test_phone_home_attempts_are_all_logged(self):
        res = self.run_control("phones-home")
        self.assertEqual(res["outcome"], "violation")
        kinds = {v["kind"] for v in res["violations"]}
        self.assertLessEqual({"dns", "forbidden", "ipv4", "host-socket"}, kinds, res)
        if depaudit._ipv6_available():
            self.assertIn("ipv6", kinds, res)

    def test_subject_that_needs_network_fails_its_scenario(self):
        self.assertEqual(self.run_control("needs-network")["outcome"], "scenario-failed")

    def test_host_sockets_are_masked_not_just_logged(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            import socket
            probe = socket.socket(socket.AF_UNIX)
            probe.bind(os.path.join(d, "p.sock"))
            probe.listen()
            os.chmod(d, 0o755)
            res = depaudit.run_target({"name": "hs", "cmd": CONTROLS + ["host-socket"],
                                       "env": {"DEPAUDIT_PROBE": os.path.join(d, "p.sock")}},
                                      depaudit.load_manifest(MANIFEST))
            probe.close()
        self.assertEqual(res["outcome"], "violation", res)
        self.assertIn("/tmp", res["masked"])

    # HK-1a (briefs/HK-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_a_process_that_escaped_strace_and_its_group_is_killed_with_the_run(self):
        # strace letting go of a tracee that had called setsid(): killing the process group
        # misses it, and it would write into the work directory while it is being removed.
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            os.chmod(d, 0o755)
            script = pathlib.Path(d, "strace")
            script.write_text(textwrap.dedent("""\
                #!%s
                import subprocess, sys
                subprocess.Popen(["sh", "-c", 'sleep 1; touch "$0/late"', %r], start_new_session=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                """) % (sys.executable, d))
            script.chmod(0o755)
            res = depaudit.run_target({"name": "escape", "cmd": ["true"], "writes": [d],
                                       "env": {"PATH": d + os.pathsep + os.environ["PATH"]}},
                                      depaudit.load_manifest(MANIFEST))
            time.sleep(2)
            self.assertFalse(os.path.exists(os.path.join(d, "late")), res)

    def test_shipped_registry_passes(self):
        self.assertEqual(depaudit.main(["run", "--targets", str(ROOT / "assurance" / "dep-targets.json")]), 0)

    def test_registry_cannot_relax_a_product_scenario(self):
        with tempfile.TemporaryDirectory() as d:
            reg = pathlib.Path(d, "t.json")
            for t in ({"name": "x", "cmd": ["true"], "expect": "violation"},
                      {"name": "x", "cmd": ["true"], "control": True}):
                reg.write_text(json.dumps({"targets": [t]}))
                self.assertEqual(depaudit.main(["run", "--targets", str(reg)]), 2, t)


@unittest.skipUnless(depaudit.sandbox_available(), "needs user+net namespaces and strace")
class StraceFaultTest(unittest.TestCase):
    """A strace of its own accord failing (PTRACE_LISTEN EIO in the recovery-offline
    scenario) is the harness's fault, not the scenario's: rerun it, never relax it."""

    def fake_strace(self, d, faults, later_cmd=None, rc=1, msg="strace: PTRACE_LISTEN: Input/output error"):
        """A strace that runs the real one and then fails like one hit by EIO, `faults`
        times, exiting rc; later_cmd (if given) replaces the traced command after the fault."""
        script = pathlib.Path(d, "strace")
        script.write_text(textwrap.dedent("""\
            #!%(py)s
            import os, sys
            d, real = %(d)r, %(real)r
            n = int(open(d + "/count").read()) if os.path.exists(d + "/count") else 0
            open(d + "/count", "w").write(str(n + 1))
            argv = sys.argv[1:]
            if n >= %(faults)d:
                os.execv(real, [real] + argv)
            i = argv.index("--")
            if n > 0 and %(later)r:
                argv = argv[:i + 1] + %(later)r
            os.spawnv(os.P_WAIT, real, [real] + argv)
            sys.stderr.write(%(msg)r + "\\n")
            sys.exit(%(rc)d)
            """) % {"py": sys.executable, "d": d, "real": shutil.which("strace"), "faults": faults,
                    "later": later_cmd, "rc": rc, "msg": msg})
        script.chmod(0o755)
        return d

    def run_with(self, mode, faults, later_cmd=None, **fault):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            os.chmod(d, 0o755)
            self.fake_strace(d, faults, later_cmd, **fault)
            res = depaudit.run_target({"name": mode, "cmd": CONTROLS + [mode], "profile": "offline", "writes": [d],
                                       "env": {"PATH": d + os.pathsep + os.environ["PATH"]}},
                                      depaudit.load_manifest(MANIFEST))
            return res, int(pathlib.Path(d, "count").read_text())

    # HK-1b (briefs/HK-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_one_strace_fault_is_rerun_and_the_scenario_judged_on_the_rerun(self):
        res, runs = self.run_with("clean", faults=1)
        self.assertEqual((res["outcome"], res["violations"], runs), ("pass", [], 2), res)

    def test_strace_fault_every_time_is_an_error_not_a_pass(self):
        res, runs = self.run_with("clean", faults=99)
        self.assertEqual(res["outcome"], "error", res)
        self.assertEqual(runs, depaudit.STRACE_ATTEMPTS)

    def test_strace_fault_is_a_fault_even_when_strace_exits_zero(self):
        # strace's exit status is the main tracee's: a fault on a child it then let go of
        # can end 0 with a partial trace (message format as strace's ptrace_restart prints it).
        res, runs = self.run_with("clean", faults=99, rc=0,
                                  msg="strace: ptrace(PTRACE_LISTEN,pid:42,sig:0): Input/output error")
        self.assertEqual((res["outcome"], runs), ("error", depaudit.STRACE_ATTEMPTS), res)

    def test_strace_fault_after_a_partial_stderr_line_is_a_fault(self):
        # The tracee shares strace's stderr: its unterminated output can sit before the message.
        res, runs = self.run_with("clean", faults=99, rc=0,
                                  msg="partial line strace: ptrace(PTRACE_LISTEN,pid:42,sig:0): Input/output error")
        self.assertEqual((res["outcome"], runs), ("error", depaudit.STRACE_ATTEMPTS), res)

    # HK-1c (briefs/HK-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_a_leak_seen_before_a_strace_fault_is_not_forgotten(self):
        res, runs = self.run_with("phones-home", faults=1, later_cmd=["true"])
        self.assertEqual(runs, 2)
        self.assertEqual(res["outcome"], "violation", res)
        self.assertLessEqual({"dns", "forbidden", "ipv4", "host-socket"}, {v["kind"] for v in res["violations"]}, res)

    def test_a_leak_from_a_last_faulting_attempt_is_counted_once(self):
        res, runs = self.run_with("phones-home", faults=99)
        self.assertEqual(res["outcome"], "error", res)
        keys = [(v["kind"], v["target"]) for v in res["violations"]]
        self.assertIn("forbidden", {k for k, _ in keys}, res)
        self.assertEqual(len(keys), len(set(keys)) * depaudit.STRACE_ATTEMPTS, res)

    def test_a_scenario_that_fails_on_its_own_is_not_rerun(self):
        res, runs = self.run_with("needs-network", faults=0)
        self.assertEqual((res["outcome"], runs), ("scenario-failed", 1), res)


@unittest.skipUnless(depaudit.sandbox_available(), "needs user+net namespaces and strace")
class EvidenceTest(unittest.TestCase):
    """The verdict's inputs are out of the tracee's reach (DEP-2)."""

    # DEP-2a (briefs/DEP-2.md; a local ID with no SPEC row, so no REQ marker)
    def test_rewriting_the_evidence_after_a_connect_still_ends_violation(self):
        res = depaudit.run_target({"name": "tamper", "cmd": HARNESS_CONTROLS + ["tamper-evidence"]},
                                  depaudit.load_manifest(MANIFEST))
        self.assertEqual(res["outcome"], "violation", res)
        self.assertEqual([(v["kind"], v["target"]) for v in res["violations"]], [("ipv4", "192.0.2.10:443")], res)

    def test_a_tracee_cannot_erase_strace_fault_message(self):
        # strace reports a fault, then the scenario truncates the stderr it shares with strace.
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            os.chmod(d, 0o755)
            script = pathlib.Path(d, "strace")
            script.write_text(textwrap.dedent("""\
                #!%s
                import os, sys
                sys.stderr.write("strace: ptrace(PTRACE_LISTEN,pid:42,sig:0): Input/output error\\n")
                sys.stderr.flush()
                argv = sys.argv[1:]
                argv = argv[:argv.index("--") + 1] + ["sh", "-c", ': > "$TMPDIR/../stderr"']
                os.execv(%r, [%r] + argv)
                """) % (sys.executable, shutil.which("strace"), shutil.which("strace")))
            script.chmod(0o755)
            res = depaudit.run_target({"name": "erase", "cmd": ["true"], "keep": [d],
                                       "env": {"PATH": d + os.pathsep + os.environ["PATH"]}},
                                      depaudit.load_manifest(MANIFEST))
        self.assertEqual((res["outcome"], res["attempts"], res["faults"]), ("error", 3, 3), res)

    def test_a_forged_result_is_not_taken(self):
        # A sandbox whose output is more than the one result line is an error, not a verdict.
        with mock.patch.object(depaudit, "_run_sandboxed", return_value=(0, b'{"rc": 0}\n{"rc": 0}\n', b"")):
            res = depaudit.run_target({"name": "forged", "cmd": ["true"]}, depaudit.load_manifest(MANIFEST))
        self.assertEqual(res["outcome"], "error", res)

    # DEP-2b (briefs/DEP-2.md; a local ID with no SPEC row, so no REQ marker). The control first
    # tries to clear read-only with mount_setattr and open_tree_attr (Security on #437).
    def test_kept_paths_are_read_only_unless_declared(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as ro, tempfile.TemporaryDirectory(dir="/tmp") as rw:
            os.chmod(ro, 0o755)
            os.chmod(rw, 0o777)  # the scenario runs as SCENARIO_ID (DEP-3)
            res = depaudit.run_target({"name": "writes", "cmd": HARNESS_CONTROLS + ["write-kept"], "keep": [ro],
                                       "writes": [rw], "env": {"DEPAUDIT_KEEP_RO": ro, "DEPAUDIT_KEEP_RW": rw}},
                                      depaudit.load_manifest(MANIFEST))
            self.assertEqual(os.listdir(ro), [])
        self.assertEqual(res["outcome"], "pass", res)

    # DEP-2b (briefs/DEP-2.md; a local ID with no SPEC row, so no REQ marker). With CAP_SYS_PTRACE
    # the scenario could attach to _inner or strace, which keep CAP_SYS_ADMIN, and clear ro
    # through them (B1, Security re-sign on #437).
    def test_the_scenario_cannot_ptrace_its_privileged_ancestors(self):
        res = depaudit.run_target({"name": "ptrace", "cmd": HARNESS_CONTROLS + ["ptrace-ancestors"]},
                                  depaudit.load_manifest(MANIFEST))
        self.assertEqual(res["outcome"], "pass", res)

    # DEP-2b (local ID, no REQ marker). Run as real root without a user namespace, the
    # scenario's kept caps (CAP_DAC_READ_SEARCH's open_by_handle_at, CAP_SYS_MODULE, ...)
    # act on the host and can reach kept paths (B2, Security re-sign 2 on #437).
    def test_the_scenario_runs_in_its_own_user_namespace(self):
        res = depaudit.run_target({"name": "userns", "cmd": HARNESS_CONTROLS + ["own-user-namespace"],
                                   "env": depaudit._expected_maps_env()},
                                  depaudit.load_manifest(MANIFEST))
        self.assertEqual(res["outcome"], "pass", res)

    def test_the_built_in_controls_include_the_evidence_and_write_controls(self):
        names = {t["name"] for t in depaudit.control_targets("/tmp/a/p", "/tmp/b/p", "/tmp/c")}
        self.assertLessEqual({"control-evidence-tamper", "control-kept-read-only", "control-no-ptrace-ancestors",
                              "control-own-user-namespace"},
                             names)


@unittest.skipUnless(depaudit.sandbox_available(), "needs user+net namespaces and strace")
class UidBoundaryTest(unittest.TestCase):
    """DEP-3 (briefs/DEP-3.md; local IDs DEP-3a-c with no SPEC row, so no REQ marker): the
    scenario runs under a uid and gid of its own, so the evidence is out of its reach by uid,
    not only by the capability drop (tools/ASSUMPTIONS.md D9)."""

    def control(self, name):
        return next(t for t in depaudit.control_targets("/tmp/a/p", "/tmp/b/p", "/tmp/c") if t["name"] == name)

    def judged(self, name, **kw):
        t = self.control(name)
        res = depaudit.run_target(t, depaudit.load_manifest(MANIFEST), **kw)
        return depaudit._judge(t, res), res

    # DEP-3a: the scenario's uid and gid differ from _inner's and strace's.
    def test_the_scenario_uid_is_not_inner_or_strace(self):
        (ok, why), res = self.judged("control-distinct-uid")
        self.assertTrue(ok, (why, res))

    # DEP-3b: drain, partial line and ptrace of _inner, tried after a connect, leave the
    # connect counted, with DROP_CAPS as shipped and with it emptied (uid alone).
    def test_the_evidence_channels_are_closed_with_the_capability_drop(self):
        (ok, why), res = self.judged("control-evidence-channels")
        self.assertTrue(ok, (why, res))
        self.assert_both_connects_logged(res)

    def test_the_evidence_channels_are_closed_by_uid_alone(self):
        (ok, why), res = self.judged("control-evidence-channels", drop_caps=False)
        self.assertTrue(ok, (why, res))
        self.assertEqual([v["target"] for v in res["violations"]], ["192.0.2.10:443"], res)
        self.assert_both_connects_logged(res)

    # DEP-7a (briefs/DEP-7.md; a local ID with no SPEC row, so no REQ marker): the connect
    # before the channels and the one after are both logged. The control makes no other traced
    # call, so the run's event count is the connect count; a lost second connect fails here.
    def assert_both_connects_logged(self, res):
        self.assertEqual(res["events"], 2, "connects before and after the evidence channels: %r" % (res,))

    # DEP-3c: the maps are exactly the ones _inner intends, not merely not the identity map.
    def test_the_user_namespace_maps_are_exact(self):
        (ok, why), res = self.judged("control-own-user-namespace")
        self.assertTrue(ok, (why, res))

    def test_the_built_in_controls_include_the_uid_controls(self):
        names = {t["name"] for t in depaudit.control_targets("/tmp/a/p", "/tmp/b/p", "/tmp/c")}
        self.assertLessEqual({"control-distinct-uid", "control-evidence-channels"}, names)


REJECTING_STRACE = textwrap.dedent("""\
    #!%s
    import os, sys
    for a, b in zip(sys.argv, sys.argv[1:]):
        if a == "-e" and b.startswith("trace=") and "mount" in b[6:].split(","):
            sys.exit("strace: invalid system call 'mount'")
    os.execv(%r, [%r] + sys.argv[1:])
    """)


def run_unavailable(env=None, **patches):
    """cmd_run with a fresh sandbox probe; returns (exit code, stderr). No target may run."""
    saved = depaudit._SANDBOX
    depaudit._SANDBOX = None
    err = io.StringIO()
    try:
        with mock.patch.dict(os.environ, env or {}), mock.patch.multiple(depaudit, **patches) if patches \
                else contextlib.nullcontext(), \
                mock.patch.object(depaudit, "run_target", side_effect=AssertionError("a target ran")), \
                contextlib.redirect_stderr(err):
            code = depaudit.main(["run", "--targets", os.devnull])
    finally:
        depaudit._SANDBOX = saved
    return code, err.getvalue()


def path_without(*absent):
    """A PATH directory with every sandbox binary found now except those named."""
    d = tempfile.TemporaryDirectory()
    for name in ("unshare", "setpriv", "strace", "newuidmap", "newgidmap", "python3", "sh"):
        if name not in absent and shutil.which(name):
            os.symlink(shutil.which(name), os.path.join(d.name, name))
    return d


class UnavailableTest(unittest.TestCase):
    """DEP-6c, DEP-6d and DEP-6e (briefs/DEP-6.md; local IDs with no SPEC row, so no REQ
    marker): `depaudit run` exits 2 up front, naming the need that failed and its remedy."""

    def test_a_kernel_without_mount_setattr_exits_2_up_front(self):
        # An unassigned syscall number: the kernel itself answers ENOSYS (DEP-6c).
        code, err = run_unavailable(_SYS_MOUNT_SETATTR=1000)
        self.assertEqual(code, 2, err)
        self.assertIn("mount_setattr", err)
        self.assertIn("5.12", err)

    def test_the_mount_setattr_probe_finds_the_real_call(self):
        self.assertTrue(depaudit._has_mount_setattr())

    def test_a_missing_binary_is_named(self):
        with path_without("unshare") as d:
            code, err = run_unavailable({"PATH": d})
        self.assertEqual(code, 2, err)
        self.assertRegex(err, r"missing on PATH: unshare\b")

    def test_a_missing_newuidmap_names_its_package(self):
        # DEP-6e (lens on #562 UX 2): the remedy, per cause.
        with path_without("newuidmap", "newgidmap") as d:
            code, err = run_unavailable({"PATH": d})
        self.assertEqual(code, 2, err)
        self.assertRegex(err, r"missing on PATH: .*newuidmap")
        self.assertIn("apt-get install uidmap", err)

    @unittest.skipUnless(all(shutil.which(n) for n in ("unshare", "setpriv", "strace", "newuidmap", "newgidmap")),
                         "needs every sandbox binary, so the subordinate range is the first need to fail")
    def test_a_missing_subordinate_range_is_named_with_its_remedy(self):
        # DEP-6d and DEP-6e (lens on #562 UX 1 and 2): _id_maps()'s reason, not a bare exit 2.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub")
            pathlib.Path(path).write_text("someone:5000:10\n")
            code, err = run_unavailable(SUBUID=path, SUBGID=path)
        self.assertEqual(code, 2, err)
        self.assertIn("no subordinate uid and gid range for uid %d" % os.geteuid(), err)
        self.assertIn("usermod --add-subuids", err)
        self.assertIn("D13", err)
        # Security 4a on #568 point 1: no fixed range, which can overlap another user's.
        self.assertNotRegex(err, r"--add-sub[ug]ids \d")
        self.assertIn("/etc/subuid", err)
        self.assertIn("/etc/subgid", err)

    def test_a_failing_mount_setattr_in_the_sandbox_is_one_line(self):
        # DEP-6c: _inner refuses with the path and errno, before any command, not a traceback.
        def refuse(path):
            raise OSError(errno.EPERM, "mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY) failed with EPERM "
                          "(Operation not permitted) on %s" % path)
        with tempfile.TemporaryDirectory() as k, mock.patch.object(depaudit, "_mount"), \
                mock.patch.object(depaudit, "MASKED_DIRS", ()), \
                mock.patch.object(depaudit, "_set_read_only", side_effect=refuse), \
                self.assertRaises(SystemExit) as cm:
            depaudit._mask_or_refuse([k], set())
        self.assertRegex(str(cm.exception.code), r"^depaudit: sandbox not run, .*EPERM.*on %s" % k)

    def test_the_subordinate_range_remedy_names_no_fixed_range(self):
        # Security 4a on #568 point 1: a fixed range can overlap another user's (D13); unskipped.
        with mock.patch.object(depaudit, "_has_mount_setattr", return_value=True), \
                mock.patch.object(depaudit.shutil, "which", return_value="/bin/x"), \
                mock.patch.object(depaudit, "_unshare_flags", side_effect=OSError("no range")):
            why = depaudit._sandbox_missing()
        self.assertTrue(why.startswith("no range; "), why)
        self.assertNotRegex(why, r"\d+-\d+")
        self.assertIn("--add-subuids START-END --add-subgids START-END", why)
        self.assertIn("overlaps no other owner's line in /etc/subuid or /etc/subgid", why)
        self.assertIn("D13", why)
        # Security re-sign on #568 point 1: START=0 or a login uid would map the scenario onto
        # root or that user, so the text sets a floor and excludes every account. DEP-8e: it
        # states what the code checks, and the code checks overlap, not "above".
        self.assertRegex(why, r"START at least \d+ \(max\(100000, SUB_UID_MIN\)")
        self.assertIn("getent passwd", why)
        self.assertNotIn("above every", why)

    def test_inner_refuses_through_mask_or_refuse(self):
        # L3 on #568 point 2: _inner must not call _mask_host_sockets bare, or the traceback is back.
        src = inspect.getsource(depaudit._inner)
        self.assertIn("_mask_or_refuse(", src)
        self.assertNotIn("_mask_host_sockets(", src)


class KeptMountsTest(unittest.TestCase):
    """DEP-6b (briefs/DEP-6.md; a local ID with no SPEC row, so no REQ marker): the control's
    mount check reads /proc/self/mounts and statvfs, sharing no code with writable_mounts."""

    # source mount-point fstype options dump pass
    TEXT = "\n".join("t %s tmpfs %s 0 0" % e for e in [
        ("/", "rw,relatime"),
        ("/k", "ro,relatime"),
        ("/k/sub", "rw,nosuid"),
        ("/k/w", "rw"),
        ("/k/w/inner", "rw"),
        ("/k/w/ro2", "rw"),
        ("/k/ro", "ro"),
        ("/kx", "rw"),
        ("/k/a\\040b", "rw"),
        ("/k/gone", "rw"),
        ("/k/denied", "rw"),
        ("/k/lands-ro", "rw"),
    ]) + "\n"

    @staticmethod
    def statvfs(path):
        if path == "/k/gone":
            raise FileNotFoundError(errno.ENOENT, "gone", path)
        if path == "/k/denied":
            raise PermissionError(errno.EACCES, "denied", path)
        return mock.Mock(f_flag=os.ST_RDONLY if path == "/k/lands-ro" else 0)

    def check(self, text=None):
        # /k/w/ro2 is read-only inside a writes path inside a read-only kept path: the closest
        # declared path decides (D10), so it is checked (L3 on #557 point 1).
        return depaudit.kept_rw_mounts(self.TEXT if text is None else text, ["/k", "/k/w/ro2"], ["/k/w"],
                                       self.statvfs)

    def test_rw_mounts_under_read_only_kept_paths_are_found(self):
        self.assertEqual(self.check(), ["/k/sub", "/k/w/ro2", "/k/a b", "/k/denied"])

    def test_a_bug_in_writable_mounts_does_not_blind_it(self):
        with mock.patch.object(depaudit, "writable_mounts", return_value=[]), \
                mock.patch.object(depaudit, "_reaches_rw", return_value=False):
            self.assertIn("/k/sub", self.check())

    def test_the_mounted_root_is_checked(self):
        self.assertEqual(depaudit.kept_rw_mounts("p /proc proc rw 0 0\n", ["/"], [], self.statvfs), ["/proc"])

    def test_an_unparsable_line_fails_closed(self):
        for line in ("garbage", "t /k/b\\x tmpfs rw 0 0"):
            with self.subTest(line=line):
                self.assertEqual(len(self.check(line + "\n")), 1)
                self.assertIn("unparsed", self.check(line + "\n")[0])

    def test_it_reads_its_own_source(self):
        src = inspect.getsource(depaudit.kept_rw_mounts)
        for shared in ("writable_mounts", "_reaches_rw", "_OCTAL", "mountinfo"):
            self.assertNotIn(shared, src)

    def test_the_kept_read_only_control_uses_it(self):
        # L3 point 1 and Security 4a point 2 on #568: the control reads the second source.
        src = inspect.getsource(depaudit._control)
        self.assertIn("kept_rw_mounts(", src)
        self.assertIn("/proc/self/mounts", src)
        self.assertNotIn("writable_mounts", src)
        self.assertNotIn("mountinfo", src)


class IdMapTest(unittest.TestCase):
    """DEP-3a and DEP-3c (local IDs, no REQ marker): the map comes from the runner's
    subordinate range, and without one the sandbox is unavailable, never the old map."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.uid_path = os.path.join(self.dir.name, "subuid")
        self.gid_path = os.path.join(self.dir.name, "subgid")
        # DEP-8: the account sources and login.defs are patched, so no case depends on the
        # host's accounts; self.host.close() undoes it for the cases that use the real ones.
        self.real_lookup = getattr(depaudit, "_nss_lookup", None)
        self.host = contextlib.ExitStack()
        self.addCleanup(self.host.close)
        self.host.enter_context(mock.patch.object(depaudit, "LOGIN_DEFS", os.path.join(self.dir.name, "login.defs"),
                                                  create=True))
        self.host.enter_context(mock.patch("pwd.getpwall", return_value=[]))
        self.host.enter_context(mock.patch("grp.getgrall", return_value=[]))
        self.host.enter_context(mock.patch.object(depaudit, "_nss_lookup", return_value=(0, False), create=True))

    def ranges(self, text, gid_text=None):
        """One file for both, or with gid_text a SUBGID file of its own (DEP-7e)."""
        pathlib.Path(self.uid_path).write_text(text)
        gid_path = self.uid_path
        if gid_text is not None:
            gid_path = self.gid_path
            pathlib.Path(gid_path).write_text(gid_text)
        return mock.patch.multiple(depaudit, SUBUID=self.uid_path, SUBGID=gid_path)

    def available(self, env=None):
        saved = depaudit._SANDBOX
        depaudit._SANDBOX = None
        try:
            with mock.patch.dict(os.environ, env or {}):
                return depaudit.sandbox_available()
        finally:
            depaudit._SANDBOX = saved

    def test_the_map_is_the_runner_and_its_first_subordinate_id(self):
        with self.ranges("someone:5000:10\n%d:300000:65536\n%d:400000:1\n" % (os.geteuid(), os.geteuid())):
            uid_map, gid_map = depaudit._id_maps()
        self.assertEqual(uid_map, [(0, os.geteuid(), 1), (depaudit.SCENARIO_ID, 300000, 1)])
        self.assertEqual(gid_map, [(0, os.getegid(), 1), (depaudit.SCENARIO_ID, 300000, 1)])
        self.assertNotEqual(depaudit.SCENARIO_ID, 0)

    def test_no_subordinate_range_means_no_map(self):
        with self.ranges("someone:5000:10\n"), self.assertRaises(OSError):
            depaudit._id_maps()

    # DEP-7e (briefs/DEP-7.md; a local ID with no SPEC row, so no REQ marker): a uid range with
    # no gid range, or the reverse, is no map: _id_maps' own guard raises, so no None reaches
    # the map text and the sandbox is unavailable by design.
    def half_ranges(self):
        mine = "%d:300000:65536\n" % os.geteuid()
        return (("subuid only", mine, "someone:5000:10\n"), ("subgid only", "someone:5000:10\n", mine))

    def test_a_range_on_one_side_only_means_no_map(self):
        for name, uid_text, gid_text in self.half_ranges():
            with self.subTest(name), self.ranges(uid_text, gid_text), self.assertRaises(OSError):
                depaudit._id_maps()

    @unittest.skipUnless(all(shutil.which(n) for n, _ in depaudit._NEEDS), "needs every sandbox binary")
    def test_a_range_on_one_side_only_makes_the_sandbox_unavailable(self):
        for name, uid_text, gid_text in self.half_ranges():
            with self.subTest(name), self.ranges(uid_text, gid_text):
                self.assertFalse(self.available())
                self.assertIn("no subordinate uid and gid range", depaudit.SANDBOX_WHY)

    @unittest.skipUnless(shutil.which("unshare") and shutil.which("strace") and shutil.which("setpriv"),
                         "needs unshare, strace and setpriv")
    def test_without_a_subordinate_range_the_sandbox_is_unavailable(self):
        with self.ranges("someone:5000:10\n"):
            self.assertFalse(self.available())

    @unittest.skipUnless(shutil.which("unshare") and shutil.which("strace") and shutil.which("setpriv"),
                         "needs unshare, strace and setpriv")
    def test_a_failing_newuidmap_makes_the_sandbox_unavailable(self):
        os.chmod(self.dir.name, 0o755)
        for name in ("newuidmap", "newgidmap"):
            stub = pathlib.Path(self.dir.name, name)
            stub.write_text("#!/bin/sh\necho 'newuidmap: stub refuses' >&2\nexit 1\n")
            stub.chmod(0o755)
        self.assertFalse(self.available({"PATH": self.dir.name + os.pathsep + os.environ["PATH"]}))

    # DEP-8a-e (briefs/DEP-8.md; local IDs with no SPEC row, so no REQ marker; A9 through
    # DEP-3a): a range that maps the scenario onto an id someone else owns is no usable range.
    def mine(self, start, count=65536):
        return "%d:%d:%d\n" % (os.geteuid(), start, count)

    def defs(self, text):
        pathlib.Path(depaudit.LOGIN_DEFS).write_text(text)

    def refused(self, uid_text, gid_text=None, *needles):
        with self.ranges(uid_text, gid_text), self.assertRaises(OSError) as cm:
            depaudit._id_maps()
        why = str(cm.exception)
        for needle in needles:
            self.assertIn(needle, why)
        return why

    def refused_gid_side(self, gid_text, *needles):
        """Refused for the gid range in SUBGID, with SUBUID clean."""
        why = self.refused(self.mine(300000), gid_text, self.gid_path, *needles)
        self.assertNotIn(self.uid_path + " ", why)
        return why

    def maps(self, uid_text, gid_text=None):
        with self.ranges(uid_text, gid_text):
            return depaudit._id_maps()

    def test_8a_a_start_below_the_floor_is_refused(self):
        for start in (0, 1000, 99999):
            with self.subTest(start=start):
                self.refused(self.mine(start), None, "start %d is below the floor 100000" % start, "SUB_UID_MIN")

    def test_8a_a_start_at_the_floor_maps(self):
        uid_map, gid_map = self.maps(self.mine(100000))
        self.assertEqual(uid_map[1], (depaudit.SCENARIO_ID, 100000, 1))
        self.assertEqual(gid_map[1], (depaudit.SCENARIO_ID, 100000, 1))

    def test_8a_login_defs_raises_the_floor(self):
        self.defs("# comment\nSUB_UID_MIN\t\t 524288\n")
        self.refused(self.mine(200000), None, "below the floor 524288 (SUB_UID_MIN)")

    def test_8a_login_defs_cannot_lower_the_floor(self):
        self.defs("SUB_UID_MIN 65536\nSUB_GID_MIN 65536\n")
        self.refused(self.mine(99999), None, "below the floor 100000")

    def test_8a_the_gid_floor_is_sub_gid_min(self):
        self.defs("SUB_GID_MIN 300000\n")
        self.refused(self.mine(200000), self.mine(200000), self.gid_path, "below the floor 300000 (SUB_GID_MIN)")

    def test_8a_an_unparsable_login_defs_value_is_a_reason(self):
        self.defs("SUB_UID_MIN abc\n")
        self.refused(self.mine(200000), None, depaudit.LOGIN_DEFS, "SUB_UID_MIN")

    def test_8b_an_enumerated_account_in_the_range_is_refused(self):
        alice = pwd.struct_passwd(("alice", "x", 150000, 150000, "", "/", "/bin/sh"))
        with mock.patch("pwd.getpwall", return_value=[alice]):
            self.refused(self.mine(100000), None, "uid 150000 (alice)")

    def test_8b_an_account_outside_the_range_does_not_block(self):
        far = pwd.struct_passwd(("far", "x", 4294967294, 4294967294, "", "/", "/bin/sh"))
        with mock.patch("pwd.getpwall", return_value=[far]):
            self.assertEqual(self.maps(self.mine(100000))[0][1], (depaudit.SCENARIO_ID, 100000, 1))

    def test_8b_the_runners_own_euid_is_refused_with_no_entry(self):
        with mock.patch("os.geteuid", return_value=120000):
            self.refused(self.mine(100000), None, "uid 120000 (the runner)")

    def test_8b_the_runners_own_egid_is_refused_with_no_entry(self):
        with mock.patch("os.getegid", return_value=120000):
            self.refused_gid_side(self.mine(100000), "gid 120000 (the runner)")

    def test_8b_an_enumerated_group_in_the_range_is_refused(self):
        staff = grp.struct_group(("staff", "x", 150000, []))
        with mock.patch("grp.getgrall", return_value=[staff]):
            self.refused_gid_side(self.mine(100000), "gid 150000 (staff)")

    def test_8b_an_unenumerated_account_found_by_id_is_refused(self):
        # SSSD or LDAP with enumerate = false: getpwall() is silent, a lookup by id finds it.
        found = lambda call, ident: (0, call == "getpwuid_r" and ident == 200000)  # noqa: E731
        with mock.patch.object(depaudit, "_nss_lookup", side_effect=found, create=True):
            self.refused(self.mine(200000), None, "uid 200000", "getpwuid_r")

    def test_8b_an_unenumerated_group_found_by_id_is_refused(self):
        found = lambda call, ident: (0, call == "getgrgid_r" and ident == 200000)  # noqa: E731
        with mock.patch.object(depaudit, "_nss_lookup", side_effect=found, create=True):
            self.refused_gid_side(self.mine(200000), "gid 200000", "getgrgid_r")

    def test_8b_a_failed_lookup_by_id_is_refused_never_free(self):
        for call, side in (("getpwuid_r", None), ("getgrgid_r", "gid")):
            for err in (errno.EIO, errno.EAGAIN):
                fail = lambda c, ident, call=call, err=err: (err, False) if c == call else (0, False)  # noqa: E731
                with self.subTest(call=call, err=errno.errorcode[err]), \
                        mock.patch.object(depaudit, "_nss_lookup", side_effect=fail, create=True):
                    needles = ("%s(200000) failed with %s" % (call, errno.errorcode[err]),)
                    if side:
                        self.refused_gid_side(self.mine(200000), *needles)
                    else:
                        self.refused(self.mine(200000), None, *needles)

    def test_8b_the_lookup_by_id_follows_the_glibc_contract(self):
        # Unpatched, against the host's real NSS: a free id is (0, False), the runner's own (0, True).
        self.assertIsNotNone(self.real_lookup, "no _nss_lookup")
        self.assertEqual(self.real_lookup("getpwuid_r", os.geteuid()), (0, True))
        self.assertEqual(self.real_lookup("getpwuid_r", 4294967200), (0, False))
        self.assertEqual(self.real_lookup("getgrgid_r", os.getegid()), (0, True))
        self.assertEqual(self.real_lookup("getgrgid_r", 4294967200), (0, False))

    def test_8b_the_range_ends_at_or_below_4294967294(self):
        self.assertEqual(self.maps(self.mine(4294967200, 95))[0][1], (depaudit.SCENARIO_ID, 4294967200, 1))
        self.refused(self.mine(4294967200, 96), None, "4294967295")

    def test_8b_smoke_the_real_runners_own_id_as_the_start_is_refused(self):
        # Unpatched host. On CI (euid 1001) the floor refuses it first (LATER DEP-8 l1).
        self.host.close()
        with self.ranges(self.mine(os.geteuid(), 1)), self.assertRaises(OSError):
            depaudit._id_maps()

    def test_8c_an_overlap_with_another_owner_is_refused(self):
        for other in ("alice:150000:65536", "alice:165535:1", "alice:99999:2"):
            with self.subTest(other):
                self.refused(other + "\n" + self.mine(100000), None, "overlaps " + other)

    def test_8c_a_range_that_only_touches_another_maps(self):
        for other in ("alice:165536:65536", "alice:99999:1"):
            with self.subTest(other):
                self.assertEqual(self.maps(other + "\n" + self.mine(100000))[0][1],
                                 (depaudit.SCENARIO_ID, 100000, 1))

    def test_8c_an_overlap_in_subgid_is_refused(self):
        self.refused_gid_side("alice:150000:65536\n" + self.mine(100000), "overlaps alice:150000:65536")

    def test_8c_a_line_that_does_not_parse_strictly_is_refused(self):
        for bad in ("alice: 150000:65536", "alice:0x24000:65536", "alice:0303240:65536", "alice:0x186a0:65536",
                    "alice:150000:065536", "alice:150000:6553\u00b2", "alice:+150000:65536", " alice:150000:1"):
            with self.subTest(bad):
                self.refused(bad + "\n" + self.mine(100000), None, self.uid_path, repr(bad), "does not parse")

    def test_8d_a_bad_first_line_is_the_result(self):
        self.refused(self.mine(0) + self.mine(300000), None, "range 0:65536 for %d" % os.geteuid())

    def test_8e_an_unusable_range_names_the_rule_and_the_remedy(self):
        self.defs("SUB_UID_MIN 524288\nSUB_GID_MIN 300000\n")
        with self.ranges(self.mine(0)), mock.patch.object(depaudit, "_has_mount_setattr", return_value=True), \
                mock.patch.object(depaudit.shutil, "which", return_value="/bin/x"):
            self.assertFalse(self.available())
        why = depaudit.SANDBOX_WHY
        self.assertIn("range 0:65536 for %d in %s is not usable: start 0 is below the floor 524288" % (
            os.geteuid(), self.uid_path), why)
        self.assert_remedy(why, "replace it")
        self.assertNotIn("add one", why)

    def test_8e_a_missing_range_says_add_one_with_the_same_rules(self):
        self.defs("SUB_UID_MIN 524288\nSUB_GID_MIN 300000\n")
        with self.ranges("someone:5000:10\n"), mock.patch.object(depaudit, "_has_mount_setattr", return_value=True), \
                mock.patch.object(depaudit.shutil, "which", return_value="/bin/x"):
            self.assertFalse(self.available())
        self.assertIn("no subordinate uid and gid range", depaudit.SANDBOX_WHY)
        self.assert_remedy(depaudit.SANDBOX_WHY, "add one")

    def assert_remedy(self, why, verb):
        self.assertIn("; %s: " % verb, why)
        for needle in ("524288 (SUB_UID_MIN", "300000 (SUB_GID_MIN", "getent passwd", "getent group",
                       "a lookup by id", "the runner's own", "/etc/subuid or /etc/subgid", "D13"):
            self.assertIn(needle, why)
        self.assertNotIn("above every", why)


class ReadOnlyRefusalTest(unittest.TestCase):
    """DEP-7f (briefs/DEP-7.md; a local ID with no SPEC row, so no REQ marker): EACCES counts as
    a read-only refusal only where statvfs says the mount is read-only; EROFS always does."""

    def refused(self, code, f_flag=0):
        statvfs = mock.Mock(return_value=mock.Mock(f_flag=f_flag))
        with mock.patch.object(depaudit.os, "statvfs", statvfs):
            got = depaudit._refused_read_only(OSError(code, os.strerror(code)), "/k")
        return got, statvfs

    def test_eacces_on_a_writable_mount_is_not_read_only(self):
        got, statvfs = self.refused(errno.EACCES, f_flag=0)
        self.assertFalse(got)
        statvfs.assert_called_once_with("/k")

    def test_eacces_on_a_read_only_mount_is_read_only(self):
        self.assertTrue(self.refused(errno.EACCES, f_flag=os.ST_RDONLY)[0])

    def test_erofs_is_read_only_without_statvfs(self):
        got, statvfs = self.refused(errno.EROFS)
        self.assertTrue(got)
        statvfs.assert_not_called()

    def test_any_other_errno_is_not_read_only(self):
        for code in (errno.EPERM, errno.ENOENT, errno.EIO):
            with self.subTest(errno=errno.errorcode[code]):
                self.assertFalse(self.refused(code, f_flag=os.ST_RDONLY)[0])


class HandBackTest(unittest.TestCase):
    """DEP-7g (briefs/DEP-7.md; a local ID with no SPEC row, so no REQ marker): _inner kills and
    reaps the namespace before any file goes back to uid 0, through one helper."""

    def test_the_namespace_ends_before_the_chown_back(self):
        calls = []
        with mock.patch.object(depaudit, "_end_namespace", lambda: calls.append("end")), \
                mock.patch.object(depaudit, "_chown_tree", lambda p, i: calls.append(("chown", p, i))):
            depaudit._hand_back(["a", "b"])
        self.assertEqual(calls, ["end", ("chown", "a", 0), ("chown", "b", 0)])

    @staticmethod
    def calls(node, name):
        return [n for n in ast.walk(node) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name) and n.func.id == name]

    def test_inner_hands_back_only_through_the_helper(self):
        inner = ast.parse(textwrap.dedent(inspect.getsource(depaudit._inner))).body[0]
        top = [s.value for s in inner.body if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)]
        self.assertEqual(len(self.calls(inner, "_hand_back")), 1, "_inner calls _hand_back once")
        self.assertTrue(any(c is self.calls(inner, "_hand_back")[0] for c in top),
                        "_inner calls _hand_back only under a condition")
        self.assertEqual(self.calls(inner, "_end_namespace"), [], "_inner ends the namespace only in _hand_back")
        module = ast.parse(pathlib.Path(depaudit.__file__).read_text())
        back = [c for f in ast.walk(module) if isinstance(f, ast.FunctionDef) and f.name != "_hand_back"
                for c in self.calls(f, "_chown_tree")
                if not (isinstance(c.args[1], ast.Name) and c.args[1].id == "SCENARIO_ID")]
        self.assertEqual([c.lineno for c in back], [], "lines of depaudit.py that chown back outside _hand_back")


class TracerChannelTest(unittest.TestCase):
    """DEP-7b and DEP-7c (briefs/DEP-7.md; local IDs with no SPEC row, so no REQ marker): only a
    PermissionError counts as refused; an open or signal that works, or a target that is not
    there, is reported, so the control ends scenario-failed."""

    def probe(self, open_=None, kill=None):
        def refuse(*a):
            raise PermissionError(errno.EACCES, "denied")
        with mock.patch.object(depaudit.os, "open", open_ or refuse), \
                mock.patch.object(depaudit.os, "kill", kill or refuse):
            return depaudit._tracer_channels(4242)

    def test_refusals_report_nothing(self):
        self.assertEqual(self.probe(), [])

    def test_an_opened_stderr_is_reported(self):
        r, w = os.pipe()
        os.set_blocking(r, False)  # as the probe's O_NONBLOCK open would be
        self.addCleanup(os.close, w)
        wrong = self.probe(open_=lambda *a: r)
        self.assertEqual(len(wrong), 1, wrong)
        self.assertIn("/proc/4242/fd/2", wrong[0])

    def test_a_missing_stderr_is_reported(self):
        def gone(*a):
            raise FileNotFoundError(errno.ENOENT, "gone")
        wrong = self.probe(open_=gone)
        self.assertEqual(len(wrong), 1, wrong)
        self.assertIn("/proc/4242/fd/2", wrong[0])

    def test_a_signal_that_works_is_reported(self):
        sent = []
        wrong = self.probe(kill=lambda pid, sig: sent.append((pid, sig)))
        self.assertEqual(sent, [(4242, 0), (1, 0)])
        self.assertEqual(len(wrong), 2, wrong)
        self.assertIn("pid 4242", wrong[0])
        self.assertIn("pid 1", wrong[1])

    def test_a_missing_pid_is_not_a_refusal(self):
        def lost(pid, sig):
            raise ProcessLookupError(errno.ESRCH, "no such process")
        wrong = self.probe(kill=lost)
        self.assertEqual(len(wrong), 2, wrong)

    def test_the_control_runs_them_on_its_strace_parent(self):
        src = inspect.getsource(depaudit._evidence_channels)
        self.assertIn("_tracer_channels(", src)
        self.assertIn("os.getppid()", src)


# A scenario, run through run_target inside an outer `unshare -r -m`, after a tmpfs is
# mounted on <keep>/sub there: the sandbox's rbind of the kept path carries that submount.
SUBMOUNT_HELPER = textwrap.dedent("""\
    import json, os, subprocess, sys
    sys.path.insert(0, %r)
    import depaudit
    keep, rw = sys.argv[1], sys.argv[2]
    # This namespace maps only 0 (the runner) and SCENARIO_ID, so newuidmap here may give the
    # sandbox only those: a private /etc/subuid and /etc/subgid say so (DEP-3).
    ranges = os.path.join(rw, "subids")
    with open(ranges, "w") as f:
        f.write("root:{0}:1\\n0:{0}:1\\n".format(depaudit.SCENARIO_ID))
    for path in (depaudit.SUBUID, depaudit.SUBGID):
        subprocess.run(["mount", "--bind", ranges, path], check=True)
    sub = os.path.join(keep, "sub")
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", sub], check=True)
    manifest = depaudit.load_manifest(json.loads(sys.argv[3]))
    out = {}
    out["write"] = depaudit.run_target(
        {"name": "write-sub", "cmd": ["sh", "-c", 'echo x > "$0/f"', sub], "keep": [keep]}, manifest)
    out["written"] = os.listdir(sub)
    out["control"] = depaudit.run_target(
        {"name": "write-kept", "cmd": %r + ["write-kept"], "keep": [keep], "writes": [rw],
         "env": {"DEPAUDIT_KEEP_RO": keep, "DEPAUDIT_KEEP_RW": rw}}, manifest)
    print(json.dumps(out))
    """) % (str(ROOT / "tools"), HARNESS_CONTROLS)


@unittest.skipUnless(depaudit.sandbox_available(), "needs user+net namespaces and strace")
class SubmountTest(unittest.TestCase):
    """DEP-4a (briefs/DEP-4.md; a local ID with no SPEC row, so no REQ marker): every mount
    at or under a read-only kept path is read-only before the command runs (D10)."""

    def test_a_submount_of_a_kept_path_is_read_only(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as keep, tempfile.TemporaryDirectory(dir="/tmp") as rw:
            os.chmod(keep, 0o755)
            os.chmod(rw, 0o755)
            os.mkdir(os.path.join(keep, "sub"))
            # The outer namespace carries the sandbox's own two ids, so the sandbox can map them again.
            uids, gids = depaudit._id_maps()
            outer = ["--map-user=0", "--map-group=0", "--map-users=%d:%d:%d" % uids[1],
                     "--map-groups=%d:%d:%d" % gids[1]]
            os.chmod(rw, 0o777)
            p = subprocess.run(["unshare"] + outer + ["-m", "--", sys.executable, "-c", SUBMOUNT_HELPER,
                                keep, rw, json.dumps(MANIFEST)], capture_output=True, text=True, timeout=300)
            self.assertEqual(p.returncode, 0, p.stderr[-2000:])
            out = json.loads(p.stdout.splitlines()[-1])
        write = out["write"]
        # The write fails read-only, or the attempt is a sandbox error; never a pass with the file written.
        self.assertEqual(out["written"], [], write)
        self.assertTrue(write["outcome"] == "error" or "Read-only file system" in write.get("stderr_tail", ""), write)
        # control-kept-read-only, with the submount under its read-only keep entry, still passes.
        self.assertEqual(out["control"]["outcome"], "pass", out["control"])


    @unittest.skipUnless(os.path.isfile("/etc/nsswitch.conf") and not os.path.islink("/etc/nsswitch.conf"),
                         "needs a regular /etc/nsswitch.conf, which the sandbox binds over")
    def test_a_rw_mount_left_under_a_read_only_kept_path_is_a_sandbox_error(self):
        # The sandbox binds its own nsswitch.conf over /etc's after the kept paths are made
        # read-only; with /etc kept read-only, that bind is an rw mount under it.
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            os.chmod(d, 0o755)
            res = depaudit.run_target({"name": "etc", "cmd": ["touch", os.path.join(d, "ran")], "keep": ["/etc"],
                                       "writes": [d]}, depaudit.load_manifest(MANIFEST))
            self.assertEqual(os.listdir(d), [])
        self.assertEqual(res["outcome"], "error", res)
        self.assertRegex(res["detail"], "rw mount under a read-only kept path: .*/etc/nsswitch.conf")
        # DEP-6e (briefs/DEP-6.md; local ID, no REQ marker): the error gives the next step.
        self.assertRegex(res["detail"], r"bind it read-only, or drop the keep entry \(tools/ASSUMPTIONS\.md D10\)")


class MountinfoTest(unittest.TestCase):
    """DEP-4a (local ID, no REQ marker): the check that reads /proc/self/mountinfo."""

    # id parent major:minor root mount-point options - fstype source super-options
    TEXT = "\n".join("%d 1 0:%d / %s %s - tmpfs tmpfs rw" % (i + 20, i, mp, opts) for i, (mp, opts) in enumerate([
        ("/", "rw,relatime"),
        ("/k", "ro,relatime"),
        ("/k/sub", "rw,nosuid"),
        ("/k/w", "rw"),
        ("/k/w/inner", "rw"),
        ("/k/w/ro2", "rw"),
        ("/k/ro", "ro"),
        ("/kx", "rw"),
        ("/k/a\\040b", "rw"),
        ("/sp\\040ace", "rw"),
        ("/sp\\040ace/fine", "ro"),
    ])) + "\n"

    def check(self, text, writable_now=lambda mp: True):
        return depaudit.writable_mounts(text, ["/k", "/k/w/ro2", "/sp ace"], ["/k/w"], writable_now)

    def test_rw_mounts_under_read_only_kept_paths_are_found(self):
        self.assertEqual(self.check(self.TEXT), ["/k/sub", "/k/w/ro2", "/k/a b", "/sp ace"])

    def test_a_read_only_kept_path_that_is_itself_rw_is_found(self):
        self.assertEqual(self.check("20 1 0:1 / /k rw - ext4 /dev/x rw\n"), ["/k"])

    def test_writes_paths_and_their_submounts_stay_writable(self):
        got = self.check(self.TEXT)
        self.assertNotIn("/k/w", got)
        self.assertNotIn("/k/w/inner", got)

    def test_a_rw_entry_hidden_under_a_read_only_mount_is_not_reachable(self):
        # An entry the path no longer reaches (overmounted, or under a masking tmpfs): the
        # mount the path does reach is what the scenario can write, and it is read-only.
        self.assertEqual(self.check("20 1 0:1 / /k/sub rw - tmpfs t rw\n", lambda mp: False), [])

    def test_an_unparsable_line_fails_closed(self):
        self.assertEqual(self.check("garbage\n"), ["unparsed mountinfo line: 'garbage'"])

    def test_the_mounted_root_is_checked(self):
        self.assertEqual(depaudit.writable_mounts("20 1 0:1 / /proc rw - proc proc rw\n", ["/"], [],
                                                  lambda mp: True), ["/proc"])

    def statvfs(self, result):
        def fake(path):
            if isinstance(result, Exception):
                raise result
            return mock.Mock(f_flag=result)
        return mock.patch.object(depaudit.os, "statvfs", fake)

    def test_a_mount_point_that_no_longer_resolves_is_not_reachable(self):
        with self.statvfs(FileNotFoundError(errno.ENOENT, "gone")):
            self.assertFalse(depaudit._reaches_rw("/k/sub"))

    def test_any_other_lookup_error_counts_as_writable(self):
        for err in (PermissionError(errno.EACCES, "denied"), NotADirectoryError(errno.ENOTDIR, "x"),
                    OSError(errno.EIO, "io")):
            with self.subTest(err=err), self.statvfs(err):
                self.assertTrue(depaudit._reaches_rw("/k/sub"))

    def test_a_path_that_lands_on_a_read_only_mount_is_not_reachable_rw(self):
        with self.statvfs(os.ST_RDONLY | os.ST_NOSUID):
            self.assertFalse(depaudit._reaches_rw("/k/sub"))
        with self.statvfs(os.ST_NOSUID):
            self.assertTrue(depaudit._reaches_rw("/k/sub"))


@unittest.skipUnless(depaudit.sandbox_available(), "needs user+net namespaces and strace")
class StraceNamesTest(unittest.TestCase):
    """DEP-4b (briefs/DEP-4.md; a local ID with no SPEC row, so no REQ marker): an strace that
    cannot name a TRACED syscall makes the sandbox unavailable, so `depaudit run` exits 2."""

    def available_with_path(self, path):
        saved = depaudit._SANDBOX
        depaudit._SANDBOX = None
        try:
            with mock.patch.dict(os.environ, {"PATH": path}):
                return depaudit.sandbox_available()
        finally:
            depaudit._SANDBOX = saved

    def test_an_strace_that_cannot_name_a_traced_syscall_is_refused(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            os.chmod(d, 0o755)
            script = pathlib.Path(d, "strace")
            script.write_text(textwrap.dedent("""\
                #!%s
                import os, sys
                for a, b in zip(sys.argv, sys.argv[1:]):
                    if a == "-e" and b.startswith("trace=") and "mount" in b[6:].split(","):
                        sys.exit("strace: invalid system call 'mount'")
                os.execv(%r, [%r] + sys.argv[1:])
                """) % (sys.executable, shutil.which("strace"), shutil.which("strace")))
            script.chmod(0o755)
            self.assertFalse(self.available_with_path(d + os.pathsep + os.environ["PATH"]))

    def test_the_real_strace_names_every_traced_syscall(self):
        self.assertTrue(self.available_with_path(os.environ["PATH"]))

    def test_a_rejected_strace_name_is_on_the_exit_2_line(self):
        # DEP-6d: the probe's stderr tail reaches the FAIL line.
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            os.chmod(d, 0o755)
            pathlib.Path(d, "strace").write_text(REJECTING_STRACE % (sys.executable, shutil.which("strace"),
                                                                    shutil.which("strace")))
            pathlib.Path(d, "strace").chmod(0o755)
            code, err = run_unavailable({"PATH": d + os.pathsep + os.environ["PATH"]})
        self.assertEqual(code, 2, err)
        self.assertIn("invalid system call 'mount'", err)


class TracedTest(unittest.TestCase):
    """DEP-6a (briefs/DEP-6.md; a local ID with no SPEC row, so no REQ marker): TRACED per
    architecture, each branch run on any machine."""

    ALL = ("connect", "sendto", "sendmsg", "sendmmsg") + depaudit._LINKS + depaudit._MOUNTS

    def test_aarch64_marks_exactly_symlink_and_link(self):
        names = depaudit._traced("aarch64").split(",")
        self.assertEqual(sorted(n for n in names if n.startswith("?")), ["?link", "?symlink"])
        self.assertEqual(sorted(n.lstrip("?") for n in names), sorted(self.ALL))

    def test_x86_64_and_an_unlisted_machine_mark_nothing(self):
        for machine in ("x86_64", "riscv64"):
            with self.subTest(machine=machine):
                names = depaudit._traced(machine).split(",")
                self.assertEqual([n for n in names if "?" in n], [])
                self.assertEqual(sorted(names), sorted(self.ALL))

    def test_traced_is_the_running_machine_list(self):
        self.assertEqual(depaudit.TRACED, depaudit._traced(os.uname().machine))


class CarryTest(unittest.TestCase):
    """run_target's merge of attempts, without a sandbox."""
    LEAK = {"kind": "forbidden", "target": "x.agentos.example", "count": 1, "first": "connect"}

    def run_attempts(self, *attempts):
        with mock.patch.object(depaudit, "_attempt", side_effect=list(attempts)) as m:
            res = depaudit.run_target({"name": "t", "cmd": ["true"]}, depaudit.load_manifest(MANIFEST))
        return res, m.call_count

    # HK-1c (briefs/HK-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_a_leak_before_a_fault_survives_a_later_sandbox_error(self):
        res, n = self.run_attempts(({"name": "t", "outcome": "error", "violations": [self.LEAK]}, True),
                                   ({"name": "t", "outcome": "error", "violations": [], "detail": "sandbox exit 1"},
                                    False))
        self.assertEqual((res["outcome"], res["violations"], n), ("error", [self.LEAK], 2), res)

    def test_a_leak_before_a_fault_turns_a_clean_rerun_into_a_violation(self):
        res, n = self.run_attempts(({"name": "t", "outcome": "error", "violations": [self.LEAK]}, True),
                                   ({"name": "t", "outcome": "pass", "violations": []}, False))
        self.assertEqual((res["outcome"], res["violations"], n), ("violation", [self.LEAK], 2), res)

    # DEP-2c (briefs/DEP-2.md; a local ID with no SPEC row, so no REQ marker)
    def test_the_result_counts_attempts_and_faults(self):
        res, _ = self.run_attempts(({"name": "t", "outcome": "error", "violations": []}, True),
                                   ({"name": "t", "outcome": "pass", "violations": []}, False))
        self.assertEqual((res["attempts"], res["faults"], res["cleanup_retries"]), (2, 1, 0), res)

    def test_the_run_line_shows_attempts_faults_and_cleanup_retries(self):
        res = {"name": "c", "outcome": "pass", "violations": [], "events": 0,
               "attempts": 2, "faults": 1, "cleanup_retries": 3}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(depaudit, "sandbox_available", return_value=True), \
                mock.patch.object(depaudit, "control_targets", return_value=[{"name": "c", "cmd": ["true"]}]), \
                mock.patch.object(depaudit, "run_target", return_value=res), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            reg = pathlib.Path(d, "t.json")
            reg.write_text(json.dumps({"targets": []}))
            depaudit.main(["run", "--targets", str(reg), "--report", str(pathlib.Path(d, "r.json"))])
            report = json.loads(pathlib.Path(d, "r.json").read_text())
        self.assertIn("2 attempt(s), 1 strace fault(s), 3 cleanup retr(ies)", out.getvalue())
        self.assertEqual({k: report["targets"][0][k] for k in ("attempts", "faults", "cleanup_retries")},
                         {"attempts": 2, "faults": 1, "cleanup_retries": 3})


class RepoTest(unittest.TestCase):
    def test_repo_static_scan_is_clean(self):
        self.assertEqual(depaudit.main(["static"]), 0)


if __name__ == "__main__":
    unittest.main()
