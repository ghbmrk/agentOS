"""S5: the v0 action protocol drives the fixture site's hard widgets, and no planted
canary (session cookie, storage, saved password, displayed key, URL token) leaves the
executor. Needs Playwright + Chromium; skipped where absent (CI runs the pure tests).

REQ: CRED-4, CRED-10
"""
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent.parent / "spikes" / "S5-browser-actions"
sys.path[:0] = [str(HERE), str(HERE / "fixture")]

try:
    import playwright  # noqa: F401
    from executor import CHROME
    HAVE_BROWSER = pathlib.Path(CHROME).exists()
except ImportError:
    HAVE_BROWSER = False


@unittest.skipUnless(HAVE_BROWSER, "Playwright/Chromium not installed")
class FixtureSite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import server
        from client import Session
        from playwright.sync_api import sync_playwright

        cls.server = server
        cls.srv = server.serve()
        cls.origin = f"http://127.0.0.1:{cls.srv.server_port}"
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = pathlib.Path(cls.tmp.name)
        state = tmp / "owner" / "state.json"
        state.parent.mkdir()
        # Owner login happens outside the protocol (live view, CH-8).
        with sync_playwright() as p:
            b = p.chromium.launch(executable_path=CHROME)
            c = b.new_context()
            c.new_page().goto(cls.origin + "/owner-login")
            c.storage_state(path=str(state))
            b.close()
        cls.ws = tmp / "ws"
        cls.s = Session([cls.origin], cls.ws, state)
        cls.s.do("navigate", url=cls.origin + "/app.html")

    @classmethod
    def tearDownClass(cls):
        cls.s.close()
        transcript = json.dumps(cls.s.log) + "".join(
            json.dumps(r) for r in cls.snapshots)
        for f in cls.ws.iterdir():
            transcript += f.read_bytes().decode("latin-1")
        cls.srv.shutdown()
        cls.tmp.cleanup()
        for canary in (cls.server.CANARY_SESSION, cls.server.CANARY_STORAGE,
                       cls.server.CANARY_PASSWORD, cls.server.CANARY_SHOWN,
                       "s5CanaryUrlTokenR2d2C3po4BB8Kx9"):
            assert canary not in transcript, f"canary leaked: {canary[:8]}..."

    snapshots = []

    def look(self):
        snap = self.s.look()
        type(self).snapshots.append(snap)
        return snap["snapshot"]

    def test_controlled_input_and_enter(self):
        self.look()
        self.s.do("type", ref=self.s.ref("textbox", "^Search$"), text="kettle", submit=True)
        self.assertIn("echo:kettle [submitted]", self.look())

    def test_native_select(self):
        self.look()
        self.s.do("select", ref=self.s.ref("combobox", "Country"), option="Kenya")
        self.assertIn("country=Kenya", self.look())

    def test_custom_listbox_by_clicks(self):
        self.look()
        self.s.do("click", ref=self.s.ref("button", "Size"))
        self.look()
        self.s.do("click", ref=self.s.ref("option", "^L$"))
        self.assertIn("Size: L", self.look())

    def test_shadow_dom_and_iframe(self):
        self.look()
        self.s.do("click", ref=self.s.ref("button", "shadow button"))
        self.s.do("type", ref=self.s.ref("textbox", "Card name"), text="A Person")
        snap = self.look()
        self.assertIn("shadow clicked", snap)
        self.assertIn("name=A Person", snap)

    def test_password_value_omitted_even_when_shown(self):
        snap = self.look()
        self.assertIn("[password omitted]", snap)
        self.s.do("click", ref=self.s.ref("button", "Show password"))
        self.assertIn("[password omitted]", self.look())
        self.assertEqual(self.s.call("screenshot")["error"], "withheld")
        self.s.do("click", ref=self.s.ref("button", "Show password"))

    def test_password_field_refuses_typing(self):
        self.look()
        res = self.s.call("type", ref=self.s.ref("textbox", "Saved password"), text="x")
        self.assertEqual(res["error"], "password_field")

    def test_displayed_secret_redacted_and_screenshot_withheld(self):
        snap = self.look()
        self.assertIn("Your API key: [REDACTED]", snap)
        self.assertEqual(self.s.call("screenshot")["error"], "withheld")

    def test_token_in_link_redacted(self):
        self.assertIn("token=[REDACTED]", self.look())

    def test_off_origin_navigation_refused(self):
        self.assertEqual(self.s.call("navigate", url="http://localhost:1/x")["error"], "off_origin")
        self.look()
        res = self.s.do("click", ref=self.s.ref("link", "Off-origin link"))
        self.assertEqual(res["refused_navigations"], ["http://localhost:1/elsewhere"])
        self.look()
        res = self.s.do("click", ref=self.s.ref("link", "Off-origin popup"))
        self.assertEqual(res["refused_navigations"], ["http://localhost:1/popup"])
        self.assertTrue(self.s.look()["url"].endswith("/app.html"))

    def test_download_lands_in_workspace_with_safe_name(self):
        self.look()
        res = self.s.do("download", ref=self.s.ref("link", "Download report"))
        self.assertRegex(res["path"], r"^[A-Za-z0-9_-][A-Za-z0-9._-]*$")
        self.assertTrue((self.ws / res["path"]).exists())

    def test_no_script_or_storage_verbs(self):
        for verb in ("evaluate", "eval", "cookies", "storage", "set_header", "devtools"):
            self.assertEqual(self.s.call(verb)["error"], "protocol")
        res = self.s.call("navigate", url="javascript:document.cookie")
        self.assertEqual(res["error"], "protocol")


if __name__ == "__main__":
    unittest.main()
