"""Tests for tools/netguardcheck.py: every broker dialer is hooked into the home-network address
guard (DEV-net-a acceptance 5).

REQ: DEV-2, REV-5, ARC-6, CAP-2, CAP-13
All paths and code are synthetic.
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import netguardcheck  # noqa: E402

IMPORT = '"github.com/ghbmrk/agentos/broker/netguard"'


class Tree:
    def __init__(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.td.name)
        self.allow = self.root / "allow.txt"

    def go(self, rel, body):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("package x\n" + body)

    def run(self, allow=""):
        self.allow.write_text(allow)
        return netguardcheck.check(self.root, self.allow)


class Check(unittest.TestCase):
    def tree(self):
        t = Tree()
        self.addCleanup(t.td.cleanup)
        return t

    def test_new_unhooked_dialer_fails(self):
        t = self.tree()
        t.go("broker/newthing/dial.go", "func f() { d := &net.Dialer{}; d.DialContext(ctx, \"tcp\", a) }\n")
        out = t.run()
        self.assertEqual(len(out), 1)
        self.assertIn("broker/newthing/dial.go", out[0])
        self.assertIn("not hooked", out[0])

    def test_each_dial_form_is_found(self):
        for form in ("net.Dial(\"tcp\", a)", "tls.Dial(\"tcp\", a, nil)", "smtp.DialTLS(a)", "&http.Transport{}",
                     "http.DefaultClient.Do(r)", "http.Get(u)", "(&http.Client{}).Get(u)", "new(http.Client)",
                     "&net.Resolver{PreferGo: true, Dial: dial}", "net.DialTimeout(\"tcp\", a, 1)"):
            t = self.tree()
            t.go("broker/a/a.go", f"func f() {{ {form} }}\n")
            self.assertEqual(len(t.run()), 1, form)

    def test_client_naming_its_transport_is_judged_by_the_transport(self):
        t = self.tree()
        t.go("broker/a/a.go", "func f() { c := &http.Client{Timeout: 1, Transport: tr}; _ = c }\n")
        self.assertEqual(t.run(), [])
        t = self.tree()
        t.go("broker/a/a.go", "func f() { c := &http.Client{Timeout: 1}; _ = c }\n")
        self.assertEqual(len(t.run()), 1)
        t = self.tree()
        t.go("broker/a/a.go", "type s struct{ c *http.Client }\nfunc f(c *http.Client) {}\n")
        self.assertEqual(t.run(), [])

    def test_hooked_file_passes(self):
        t = self.tree()
        t.go("broker/a/a.go", f"import {IMPORT}\nfunc f() {{ tr := &http.Transport{{DialContext: g.DialContext}} }}\n")
        self.assertEqual(t.run(), [])

    def test_a_comment_naming_the_guard_is_not_a_hook(self):
        # REV-LOW-tools finding 19: the quoted import path in a comment must not count.
        for text in ("// uses broker/netguard\n", f"// see {IMPORT}\n", f"/* {IMPORT} */\n"):
            t = self.tree()
            t.go("broker/a/a.go", text + "func f() { net.Dial(\"tcp\", a) }\n")
            self.assertEqual(len(t.run()), 1, text)

    def hooked(self, src):
        t = self.tree()
        t.go("broker/a/a.go", src)
        return netguardcheck.hooked(t.root / "broker/a/a.go")

    def test_hooked_reads_only_imports(self):
        # REV-LOW-tools finding 19: the production predicate, not a copy of it.
        for src in (f"// {IMPORT}\n", f"/* {IMPORT} */\n", f"/*\n{IMPORT}\n*/\n",
                    f"var s = {IMPORT}\n", f"var s = `\n{IMPORT}\n`\n",
                    f"import \"fmt\"\nvar s = {IMPORT}\n", f"import _ {IMPORT}\n",
                    f"import (\n\t\"fmt\"\n)\n\nfunc f() {{ _ = {IMPORT} }}\n",
                    f"import \"fmt\" // {IMPORT}\n", f"func f() {{}}\nimport {IMPORT}\n"):
            self.assertFalse(self.hooked(src), src)
        for src in (f"import {IMPORT}\n", f"import ng {IMPORT}\n", f"import . {IMPORT}\n",
                    f"import (\n\t\"fmt\"\n\tng {IMPORT} // guard\n)\n",
                    f"import \"fmt\"\nimport (\n\t/* x */ {IMPORT}\n)\n",
                    f"// a comment\nimport (\"fmt\"; {IMPORT})\n",
                    f"import `github.com/ghbmrk/agentos/broker/netguard`\n"):
            self.assertTrue(self.hooked(src), src)

    def test_parse_error_is_not_hooked(self):
        for src in (f"/* open\nimport {IMPORT}\n", f"import (\n\t{IMPORT}\n", f"import ({IMPORT} \"fmt\n)\n"):
            self.assertFalse(self.hooked(src), src)
            t = self.tree()
            t.go("broker/a/a.go", src + "func f() { net.Dial(\"tcp\", a) }\n")
            self.assertEqual(len(t.run()), 1, src)

    def test_sip_needs_a_real_import_and_dialer(self):
        for src in (f"// {IMPORT}\nimport \"github.com/emiago/sipgo\"\nfunc f() {{ sipgo.NewUA(); _ = sip.TransportTCP{{DialerCreate: nil}} }}\n",
                    f"import ({IMPORT}; \"github.com/emiago/sipgo\")\nfunc f() {{ sipgo.NewUA() }} // DialerCreate\n",
                    # L3 on #5850: the name in a string literal is not a use either.
                    f"import ({IMPORT}; \"github.com/emiago/sipgo\")\nfunc f() {{ sipgo.NewUA(); _ = \"DialerCreate\" }}\n",
                    f"import ({IMPORT}; \"github.com/emiago/sipgo\")\nfunc f() {{ sipgo.NewUA(); _ = `DialerCreate` }}\n"):
            t = self.tree()
            t.go("broker/sip/line.go", src)
            self.assertEqual(len(t.run()), 1, src)

    def test_unix_tests_vendor_testdata_and_netguard_are_exempt(self):
        t = self.tree()
        t.go("broker/a/a.go", "func f() { (&net.Dialer{}).DialContext(ctx, \"unix\", p) }\n")
        t.go("broker/a/b.go", "func f() { &http.Transport{\n DialContext: func() {\n  return (&net.Dialer{}).DialContext(ctx, \"unix\", p)\n }} }\n")
        t.go("broker/a/c_test.go", "func f() { net.Dial(\"tcp\", a) }\n")
        t.go("broker/vendor/x/x.go", "func f() { net.Dial(\"tcp\", a) }\n")
        t.go("broker/a/testdata/guest/main.go", "func f() { net.Dial(\"tcp\", a) }\n")
        t.go("broker/netguard/d.go", "func f() { net.Dial(\"tcp\", a) }\n")
        self.assertEqual(t.run(), [])

    def test_allowlist_covers_a_listed_file(self):
        t = self.tree()
        t.go("broker/a/a.go", "func f() { net.Dial(\"tcp\", a) }\n")
        self.assertEqual(t.run("broker/a/a.go old client; DEV-net-b\n"), [])

    def test_stale_allowlist_entries_fail(self):
        t = self.tree()
        t.go("broker/a/a.go", f"import {IMPORT}\nfunc f() {{ net.Dial(\"tcp\", a) }}\n")
        t.go("broker/b/b.go", "func f() {}\n")
        out = t.run("broker/a/a.go hooked now\nbroker/b/b.go no dialer\nbroker/gone/g.go deleted\n")
        self.assertEqual(len(out), 3, out)

    def test_allowlist_needs_a_reason(self):
        t = self.tree()
        with self.assertRaises(SystemExit):
            t.run("broker/a/a.go\n")

    def test_sip_client_without_a_guarded_dialer_fails(self):
        # A SIP user agent dials through its own transport: importing the guard
        # is not enough, the transport must be given the guard's dialer.
        t = self.tree()
        t.go("broker/sip/line.go", f"import ({IMPORT}; \"github.com/emiago/sipgo\")\nfunc f() {{ sipgo.NewUA() }}\n")
        out = t.run()
        self.assertEqual(len(out), 1)
        self.assertIn("broker/sip/line.go", out[0])
        self.assertIn("SIP", out[0])

    def test_sip_client_with_the_guarded_dialer_passes(self):
        t = self.tree()
        t.go("broker/sip/line.go", f"import ({IMPORT}; \"github.com/emiago/sipgo\")\nfunc f() {{ sipgo.NewUA(); _ = g.Dialer(); _ = sip.TransportTCP{{DialerCreate: nil}} }}\n")
        self.assertEqual(t.run(), [])

    def test_sip_client_that_only_imports_the_guard_still_fails(self):
        t = self.tree()
        t.go("broker/sip/line.go", f"import ({IMPORT}; \"github.com/emiago/sipgo\")\nfunc f() {{ sipgo.NewUA(); _ = netguard.New }}\n")
        self.assertEqual(len(t.run()), 1)

    def test_sip_in_a_test_file_or_vendor_is_exempt(self):
        t = self.tree()
        t.go("broker/sip/line_test.go", "func f() { sipgo.NewUA() }\n")
        t.go("broker/vendor/x/ua.go", "func f() { sipgo.NewUA() }\n")
        self.assertEqual(t.run(), [])

    def test_sip_client_can_be_allowlisted_with_a_reason(self):
        t = self.tree()
        t.go("broker/sim/sim.go", "func f() { sipgo.NewUA() }\n")
        self.assertEqual(t.run("broker/sim/sim.go a test simulator on loopback\n"), [])

    def test_the_repository_is_clean(self):
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "netguardcheck.py")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
