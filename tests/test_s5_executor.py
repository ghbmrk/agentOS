"""S5: the v0 action protocol drives the fixture site's hard widgets, and no planted
canary (session cookie, storage, saved password, displayed key, URL token) leaves the
executor. Needs Playwright + Chromium; skipped where absent, and fails instead when
AGENTOS_REQUIRE_BROWSER=1; run as a script it also fails on any skip (ci.yml's broker-checks job
runs it both ways, BROWSER-fixture-ci).

REQ: CRED-4, CRED-10
"""
import importlib.metadata
import io
import json
import os
import pathlib
import re
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HERE = ROOT / "spikes" / "S5-browser-actions"
sys.path[:0] = [str(HERE), str(HERE / "fixture")]

try:
    import playwright  # noqa: F401
    from executor import CHROME
    HAVE_BROWSER = pathlib.Path(CHROME).exists()
except ImportError:
    HAVE_BROWSER = False


def need_browser():
    """Skip without Playwright and Chromium, or fail when the job requires them (#5952)."""
    if not HAVE_BROWSER:
        if os.environ.get("AGENTOS_REQUIRE_BROWSER") == "1":
            raise AssertionError("AGENTOS_REQUIRE_BROWSER=1 but Playwright/Chromium not installed")
        raise unittest.SkipTest("Playwright/Chromium not installed")


class FixtureSite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_browser()
        import server
        from client import Session
        from playwright.sync_api import sync_playwright

        cls.server = server
        cls.srv, cls.evil = server.serve_pair()
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
        cls.srv.shutdown()
        cls.evil.shutdown()
        cls.tmp.cleanup()

    snapshots = []

    def setUp(self):
        self.s.do("navigate", url=self.origin + "/app.html")

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


    # --- escapes found in L3 review (redirect hops, subframes, URL fragments) ---

    def test_redirect_hop_off_origin_refused(self):
        self.s.do("navigate", url=self.origin + "/escape.html")
        self.look()
        res = self.s.do("click", ref=self.s.ref("link", "Redirect out"))
        self.assertTrue(any("/stolen" in u for u in res.get("refused_navigations", [])), res)
        res = self.s.call("navigate", url=self.origin + "/redir?to=" + self.srv.evil_origin + "/stolen")
        self.assertTrue(any("/stolen" in u for u in res.get("refused_navigations", [])), res)
        self.assertEqual(self.evil.hits, [])

    def test_redirect_hop_on_origin_keeps_cookie(self):
        self.s.do("navigate", url=self.origin + "/redir-in")
        self.assertIn("hop cookie kept", self.look())
        self.assertTrue(self.s.snap["url"].endswith("/hop-check"))

    def test_form_post_redirect_off_origin_refused(self):
        self.s.do("navigate", url=self.origin + "/escape.html")
        self.look()
        res = self.s.call("type", ref=self.s.ref("textbox", "Note"), text="agent data", submit=True)
        self.assertTrue(any("/stolen" in u for u in res.get("refused_navigations", [])), res)
        self.assertEqual(self.evil.hits, [])

    def test_off_origin_iframe_not_loaded(self):
        self.s.do("navigate", url=self.origin + "/escape.html")
        snap = self.look()
        self.assertNotIn("Card", snap)
        self.assertEqual(self.evil.hits, [])

    def test_fragment_token_redacted_in_url(self):
        self.s.do("navigate", url=self.origin + "/escape.html")
        self.look()
        self.s.do("click", ref=self.s.ref("link", "Fragment token"))
        snap = self.s.look()
        type(self).snapshots.append(snap)
        self.assertIn("access_token=[REDACTED]", snap["url"])

    def test_zz_no_canary_leaves_executor(self):
        """Runs last (alphabetical order): every response and workspace file so far."""
        transcript = "".join(self.s.raw)
        for f in self.ws.iterdir():
            transcript += f.read_bytes().decode("latin-1")
        for canary in (self.server.CANARY_SESSION, self.server.CANARY_STORAGE,
                       self.server.CANARY_PASSWORD, self.server.CANARY_SHOWN,
                       self.server.CANARY_FRAGMENT, "s5CanaryUrlTokenR2d2C3po4BB8Kx9"):
            self.assertNotIn(canary, transcript, f"canary leaked: {canary[:8]}...")
        self.assertGreater(len(self.s.raw), 20)
        self.assertEqual(self.evil.hits, [])


class RequireBrowser(unittest.TestCase):
    """BROWSER-fixture-ci (#5952, K4): the job that sets AGENTOS_REQUIRE_BROWSER=1 cannot go green
    with the fixture tests skipped; without it they still skip."""

    def test_missing_browser_fails_only_when_required(self):
        global HAVE_BROWSER
        saved, env = HAVE_BROWSER, os.environ.pop("AGENTOS_REQUIRE_BROWSER", None)
        try:
            # Each case reads need_browser()'s outcome instead of letting it raise here: a SkipTest
            # escaping this test would record it skipped, so a dropped switch could pass green.
            for have, switch, want in ((False, None, "skip"), (False, "1", "fail"), (False, "0", "skip"),
                                       (True, "1", "run"), (True, None, "run")):
                HAVE_BROWSER = have
                os.environ.pop("AGENTOS_REQUIRE_BROWSER", None)
                if switch is not None:
                    os.environ["AGENTOS_REQUIRE_BROWSER"] = switch
                self.assertEqual(outcome(), want, f"browser={have} switch={switch}")
        finally:
            HAVE_BROWSER = saved
            os.environ.pop("AGENTOS_REQUIRE_BROWSER", None)
            if env is not None:
                os.environ["AGENTOS_REQUIRE_BROWSER"] = env

    def test_strict_run_fails_on_a_skip(self):
        """The CI step runs this file as a script, which exits nonzero on any skip (the Python
        half of what require_ran.py does for Go), so a skipTest or @skip cannot pass green."""
        class T(unittest.TestCase):
            def test_ok(self):
                pass

            def test_skips(self):
                self.skipTest("no browser")

        def run(*names):
            r = unittest.TestResult()
            unittest.TestSuite(T(n) for n in names).run(r)
            return strict_code(r, io.StringIO())

        self.assertEqual(run("test_ok"), 0)
        self.assertEqual(run("test_ok", "test_skips"), 1)
        self.assertEqual(run(), 1)  # nothing ran


class ShellPin(unittest.TestCase):
    """BROWSER-fixture-ci-fu (#6064, K4): the headless shell ci.yml downloads is the build the
    pinned Playwright wheel names, so a bump of one pin without the other fails here."""

    def test_the_pinned_wheel_names_the_pinned_shell(self):
        need_browser()
        reqs = (ROOT / "tests" / "requirements-browser.txt").read_text()
        pinned = re.search(r"^playwright==(\S+)", reqs, re.M).group(1)
        self.assertEqual(importlib.metadata.version("playwright"), pinned,
                         "the installed Playwright is not tests/requirements-browser.txt's pin")
        import playwright
        names = pathlib.Path(playwright.__file__).parent / "driver" / "package" / "browsers.json"
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIsNone(shell_pin_problem(names.read_text(), ci))

    def test_one_pin_moving_alone_fails(self):
        names = json.dumps({"browsers": [
            {"name": "chromium", "revision": "1243", "browserVersion": "153.0.8010.12"},
            {"name": "chromium-headless-shell", "revision": "1243", "browserVersion": "153.0.8010.12"}]})
        url = ("CFT_SHELL_URL: https://storage.googleapis.com/chrome-for-testing-public/"
               "{}/linux64/chrome-headless-shell-linux64.zip\n")
        self.assertIsNone(shell_pin_problem(names, url.format("153.0.8010.12")))
        self.assertIn("153.0.8010.12", shell_pin_problem(names, url.format("154.0.8100.3")))
        self.assertIn("154.0.8100.3", shell_pin_problem(names.replace("153.0.8010.12", "154.0.8100.3"),
                                                        url.format("153.0.8010.12")))
        # No shell entry, two URLs, or a URL that is not a linux64 headless-shell zip: never a pass.
        self.assertIsNotNone(shell_pin_problem(names.replace("chromium-headless-shell", "x"), url.format("153.0.8010.12")))
        self.assertIsNotNone(shell_pin_problem(names, url.format("153.0.8010.12") * 2))
        self.assertIsNotNone(shell_pin_problem(names, url.format("153.0.8010.12").replace("linux64/chrome-headless", "mac-arm64/chrome-headless")))


def shell_pin_problem(browsers_json, ci_text):
    """None when ci.yml's one CFT_SHELL_URL is the chromium-headless-shell build browsers.json names."""
    want = [b.get("browserVersion") for b in json.loads(browsers_json)["browsers"]
            if b.get("name") == "chromium-headless-shell"]
    urls = re.findall(r"^\s*CFT_SHELL_URL:\s*(\S+)\s*$", ci_text, re.M)
    if len(want) != 1 or not want[0]:
        return f"browsers.json names {len(want)} chromium-headless-shell builds"
    if len(urls) != 1:
        return f"ci.yml sets CFT_SHELL_URL {len(urls)} times"
    m = re.fullmatch(r"https://storage\.googleapis\.com/chrome-for-testing-public/([0-9.]+)/linux64/"
                     r"chrome-headless-shell-linux64\.zip", urls[0])
    if not m:
        return f"CFT_SHELL_URL is not a Chrome for Testing linux64 headless shell: {urls[0]}"
    if m.group(1) != want[0]:
        return f"CFT_SHELL_URL is {m.group(1)}; the pinned Playwright names {want[0]}"
    return None


def outcome():
    try:
        need_browser()
    except unittest.SkipTest:
        return "skip"
    except AssertionError:
        return "fail"
    return "run"


def strict_code(result, err=sys.stderr):
    """0 only when tests ran, all passed, and none skipped; each skip is named on err."""
    for test, why in result.skipped:
        print(f"::error::{test.id()}: skipped ({why})", file=err)
    return 0 if result.testsRun and result.wasSuccessful() and not result.skipped else 1

if __name__ == "__main__":
    # Strict: any skip fails (ci.yml broker-checks, #5952). `python3 -m unittest` stays lenient.
    sys.exit(strict_code(unittest.main(exit=False).result))
