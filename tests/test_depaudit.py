# P1-6 dependency audit harness (spec A9). Tests the harness itself: strace
# parsing, the endpoint policy, the static endpoint scan, and the offline run.
# Makes no coverage claim for DEP-1–4: those are claimed by the packages whose
# scenarios pass this harness (broker P1-2 onward).
import errno
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import depaudit  # noqa: E402

CONTROLS = [sys.executable, str(ROOT / "tools" / "depaudit_controls.py")]

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
                      {"name": "x", "cmd": ["true"], "must_log": []}):
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
    # REQ: HK-1a
    def test_cleanup_retries_when_a_late_writer_fills_the_directory(self):
        real, calls = shutil.rmtree, []

        def flaky(path, *a, **kw):
            calls.append(path)
            if len(calls) < 3:
                raise OSError(errno.ENOTEMPTY, "Directory not empty", "go-build1")
            return real(path, *a, **kw)
        with mock.patch.object(depaudit.shutil, "rmtree", flaky), \
                mock.patch.object(depaudit.time, "sleep"):
            with depaudit._scratch_dir("depaudit-test-") as d:
                pathlib.Path(d, "f").write_text("x")
        self.assertEqual(len(calls), 3)
        self.assertFalse(os.path.exists(d))

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

    def fake_strace(self, d, faults, later_cmd=None):
        """A strace that runs the real one and then fails like one hit by EIO, `faults`
        times; later_cmd (if given) replaces the traced command after the fault."""
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
            sys.stderr.write("strace: PTRACE_LISTEN: Input/output error\\n")
            sys.exit(1)
            """) % {"py": sys.executable, "d": d, "real": shutil.which("strace"), "faults": faults,
                    "later": later_cmd})
        script.chmod(0o755)
        return d

    def run_with(self, mode, faults, later_cmd=None):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            os.chmod(d, 0o755)
            self.fake_strace(d, faults, later_cmd)
            res = depaudit.run_target({"name": mode, "cmd": CONTROLS + [mode], "profile": "offline", "keep": [d],
                                       "env": {"PATH": d + os.pathsep + os.environ["PATH"]}},
                                      depaudit.load_manifest(MANIFEST))
            return res, int(pathlib.Path(d, "count").read_text())

    # REQ: HK-1b
    def test_one_strace_fault_is_rerun_and_the_scenario_judged_on_the_rerun(self):
        res, runs = self.run_with("clean", faults=1)
        self.assertEqual((res["outcome"], res["violations"], runs), ("pass", [], 2), res)

    def test_strace_fault_every_time_is_an_error_not_a_pass(self):
        res, runs = self.run_with("clean", faults=99)
        self.assertEqual(res["outcome"], "error", res)
        self.assertEqual(runs, depaudit.STRACE_ATTEMPTS)

    # REQ: HK-1c
    def test_a_leak_seen_before_a_strace_fault_is_not_forgotten(self):
        res, runs = self.run_with("phones-home", faults=1, later_cmd=["true"])
        self.assertEqual(runs, 2)
        self.assertEqual(res["outcome"], "violation", res)
        self.assertLessEqual({"dns", "forbidden", "ipv4", "host-socket"}, {v["kind"] for v in res["violations"]}, res)

    def test_a_scenario_that_fails_on_its_own_is_not_rerun(self):
        res, runs = self.run_with("needs-network", faults=0)
        self.assertEqual((res["outcome"], runs), ("scenario-failed", 1), res)


class RepoTest(unittest.TestCase):
    def test_repo_static_scan_is_clean(self):
        self.assertEqual(depaudit.main(["static"]), 0)


if __name__ == "__main__":
    unittest.main()
