"""S5 action protocol v0: closed verb set, origin check, output redaction. Pure; no browser.

REQ: CRED-4, CRED-10
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "spikes" / "S5-browser-actions"))
import protocol as P  # noqa: E402


class Verbs(unittest.TestCase):
    def ok(self, **req):
        return P.validate({"v": 0, **req})

    def bad(self, **req):
        with self.assertRaises(P.ProtocolError):
            P.validate({"v": 0, **req})

    def test_the_closed_list(self):
        self.assertEqual(set(P.VERBS), {"navigate", "click", "type", "select",
                                        "snapshot", "screenshot", "download"})

    def test_well_formed(self):
        self.ok(verb="navigate", url="https://example.org/a?b=1")
        self.ok(verb="click", ref="e12")
        self.ok(verb="click", ref="f2e7")
        self.ok(verb="type", ref="e3", text="hi")
        self.ok(verb="type", ref="e3", text="hi", submit=True)
        self.ok(verb="select", ref="e3", option="Kenya")
        self.ok(verb="snapshot")

    def test_no_script_cookie_storage_or_header_access(self):
        for verb in ("evaluate", "eval", "exec_js", "cookies", "get_cookies", "storage",
                     "local_storage", "set_header", "headers", "devtools", "cdp", "new_tab"):
            self.bad(verb=verb)

    def test_no_extra_arguments(self):
        self.bad(verb="click", ref="e1", script="alert(1)")
        self.bad(verb="snapshot", selector="input[type=password]")
        self.bad(verb="navigate", url="https://a.example", headers={"Cookie": "x"})

    def test_refs_not_selectors(self):
        for ref in ("#id", "input[type=password]", "//input", "text=Sign in", "e1 >> x", "e"):
            self.bad(verb="click", ref=ref)

    def test_url_schemes(self):
        for url in ("javascript:alert(1)", "data:text/html,<script>", "file:///etc/passwd",
                    "chrome://settings", "view-source:https://a.example", "about:blank",
                    "https://user:pw@a.example/"):
            self.bad(verb="navigate", url=url)

    def test_types_and_version(self):
        self.bad(verb="type", ref="e1", text=1)
        self.bad(verb="type", ref="e1", text="x", submit="yes")
        self.bad(verb="type", ref="e1", text="x" * (P.MAX_TEXT + 1))
        for v in (1, False, 0.0, "0", None):
            with self.assertRaises(P.ProtocolError):
                P.validate({"v": v, "verb": "snapshot"})
        self.bad(verb="click", ref="e1\n")


class Origins(unittest.TestCase):
    def test_declared(self):
        d = ["https://www.saucedemo.com"]
        self.assertTrue(P.on_declared_origin("https://www.saucedemo.com/cart.html", d))
        self.assertTrue(P.on_declared_origin("https://www.saucedemo.com:443/", d))
        for url in ("http://www.saucedemo.com/", "https://saucedemo.com/",
                    "https://www.saucedemo.com.evil.example/", "https://www.saucedemo.com:8443/",
                    "not a url"):
            self.assertFalse(P.on_declared_origin(url, d), url)


class Redaction(unittest.TestCase):
    def test_known_formats(self):
        for secret in ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                       "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
                       "sk-ant-api03-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3",
                       "AKIA" + "ABCDEFGHIJKLMNOP"):
            text, n = P.redact_text(f"key: {secret} end")
            self.assertNotIn(secret, text)
            self.assertGreaterEqual(n, 1)

    def test_secret_query_params(self):
        text, n = P.redact_text("- /url: /reset?user=7&token=abc123&next=/home")
        self.assertIn("token=[REDACTED]", text)
        self.assertIn("user=7", text)
        self.assertEqual(n, 1)

    def test_fragment_tokens(self):
        text, n = P.redact_text("https://app.example/cb#access_token=s5FragQ7xZ2pL9&state=ok")
        self.assertEqual(text, "https://app.example/cb#access_token=[REDACTED]&state=ok")
        self.assertEqual(n, 1)
        self.assertEqual(P.redact_url("https://a.example/page#section-2"),
                         ("https://a.example/page#section-2", False))

    def test_high_entropy_path_segment(self):
        text, n = P.redact_text("https://a.example/reset/Q7xZ2pL9mW4vR8tY3nB6cD1fG5hJ0kL/done")
        self.assertEqual((text, n), ("https://a.example/reset/[REDACTED]/done", 1))

    def test_high_entropy_run(self):
        text, n = P.redact_text("session Q7xZ2pL9mW4vR8tY3nB6cD1fG5hJ0kL")
        self.assertEqual((text, n), ("session [REDACTED]", 1))

    def test_ordinary_text_untouched(self):
        for s in ("Thank you for your order!", "Sauce Labs Backpack $29.99",
                  "/wiki/Alan_Turing", "internationalization-and-localization",
                  "Check if you need a UK visa",
                  "https://github.com/microsoft/playwright/issues/12345",
                  "/microsoft/playwright/blob/main/README.md"):
            self.assertEqual(P.redact_text(s), (s, 0), s)


class SnapshotCap(unittest.TestCase):
    def test_cap(self):
        self.assertEqual(P.cap_snapshot("abc"), ("abc", False))
        text, cut = P.cap_snapshot("x" * (P.MAX_SNAPSHOT + 10))
        self.assertTrue(cut)
        self.assertTrue(text.endswith("[snapshot truncated]"))


class PasswordOmission(unittest.TestCase):
    SNAP = "\n".join([
        '- textbox "Username" [ref=e3]: standard_user',
        '- textbox "Password" [ref=e4]: s5-canary-pw',
        "- 'textbox \"Password:\" [ref=e5]': s5-canary-pw",
        '- textbox "PIN" [ref=f1e2] [active]: s5-canary-pw',
        '- textbox "Empty" [ref=e6]',
    ])

    def test_values_omitted_nodes_kept(self):
        out = P.omit_values(self.SNAP, {"e4", "e5", "f1e2", "e6"})
        self.assertNotIn("s5-canary-pw", out)
        self.assertIn("standard_user", out)
        self.assertEqual(out.count("[password omitted]"), 3)
        self.assertIn('- textbox "Empty" [ref=e6]', out)


if __name__ == "__main__":
    unittest.main()
