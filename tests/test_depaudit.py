# P1-6 dependency audit harness (spec A9). Tests the harness itself: strace
# parsing, the endpoint policy, the static endpoint scan, and the offline run.
# Makes no coverage claim for DEP-1–4: those are claimed by the packages whose
# scenarios pass this harness (broker P1-2 onward).
import json
import os
import pathlib
import sys
import tempfile
import unittest

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
        self.assertIn(("unix", "@abstract-name", None), got)
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
            ("ipv4", "192.0.2.10:443"),
            ("ipv4", "8.8.8.8:53"),
            ("ipv6", "[2001:db8::1]:123"),
            ("unknown-family", "AF_VSOCK"),
            ("unparsed", "AF_INET"),
        ])

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


class RepoTest(unittest.TestCase):
    def test_repo_static_scan_is_clean(self):
        self.assertEqual(depaudit.main(["static"]), 0)


if __name__ == "__main__":
    unittest.main()
