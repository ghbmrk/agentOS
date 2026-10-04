#!/usr/bin/env python3
"""S5 credentialed-browser executor: serves the v0 action protocol over JSON lines on stdio.

The agent side (client.py) sees only what this process writes to stdout. Inside, the
executor uses Playwright (which itself injects scripts); none of that is reachable
through the protocol.

  executor.py --origins https://www.saucedemo.com --workspace DIR [--storage-state F]

--storage-state stands in for the owner's live-view login (CH-8): the session is
loaded by the broker, never typed through the protocol.
"""
import argparse
import json
import os
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import protocol as P  # noqa: E402

CHROME = os.environ.get("S5_CHROME", "/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
MAX_DOWNLOAD = 50 * 1024 * 1024
PASSWORDISH = re.compile(r"pass(word|wd|code)?|pin\b|secret|otp", re.I)


class Executor:
    def __init__(self, origins, workspace, storage_state=None, headless=True):
        from playwright.sync_api import sync_playwright

        self.origins = origins
        self.ws = pathlib.Path(workspace)
        self.ws.mkdir(parents=True, exist_ok=True)
        self.refused = []
        self._pw = sync_playwright().start()
        self.browser = self._pw.chromium.launch(executable_path=CHROME, headless=headless)
        self.ctx = self.browser.new_context(
            storage_state=storage_state, accept_downloads=True,
            viewport={"width": 1280, "height": 900})
        self.ctx.route("**/*", self._route)
        self.page = self.ctx.new_page()
        self.ctx.on("page", self._on_page)
        self.last_snapshot_hits = 0
        self.n_shot = 0

    # CRED-10: the credentialed context never loads an undeclared origin top-level.
    def _route(self, route):
        req = route.request
        if req.is_navigation_request() and self._top_level(req) \
                and not P.on_declared_origin(req.url, self.origins):
            self.refused.append(P.redact_url(req.url)[0])
            return route.abort("blockedbyclient")
        return route.continue_()

    @staticmethod
    def _top_level(req):
        try:
            return req.frame == req.frame.page.main_frame
        except Exception:  # a popup's first request has no frame yet: top level
            return True

    def _on_page(self, page):
        # Single-tab model: a popup on a declared origin replaces the current page.
        if page is self.page:
            return
        try:
            page.wait_for_load_state("domcontentloaded", timeout=10000)
        except Exception:
            pass
        if P.on_declared_origin(page.url, self.origins):
            self.page = page
        else:
            if page.url.startswith("http"):  # blocked loads were already recorded by _route
                self.refused.append(P.redact_url(page.url)[0])
            page.close()

    def _settle(self):
        for state, t in (("domcontentloaded", 15000), ("networkidle", 3000)):
            try:
                self.page.wait_for_load_state(state, timeout=t)
            except Exception:
                pass

    def _loc(self, ref):
        loc = self.page.locator(f"aria-ref={ref}")
        if loc.count() != 1:
            raise P.ProtocolError(f"stale or unknown ref {ref}; take a new snapshot")
        return loc

    def _is_passwordish(self, loc):
        info = loc.evaluate(
            "e => [e.tagName, e.type || '', e.autocomplete || '', e.name || '', e.id || '',"
            " e.getAttribute('aria-label') || '', e.dataset.s5WasPassword || '']")
        tag, typ, ac, *names, was = info
        if tag != "INPUT":
            return False
        return typ == "password" or was == "1" or "password" in ac \
            or any(PASSWORDISH.search(n) for n in names)

    def _mark_password_fields(self):
        # Remember fields that were ever type=password, so a "show password" toggle
        # (type -> text) does not unmask them in later snapshots or screenshots.
        for f in self.page.frames:
            try:
                f.evaluate("() => document.querySelectorAll('input[type=password]')"
                           ".forEach(e => e.dataset.s5WasPassword = '1')")
            except Exception:
                pass

    # --- verbs ---------------------------------------------------------------
    def navigate(self, url):
        if not P.on_declared_origin(url, self.origins):
            return {"ok": False, "error": "off_origin",
                    "detail": "not a declared origin; use an uncredentialed context"}
        self.page.goto(url, wait_until="domcontentloaded", timeout=30000)
        self._settle()
        return {"ok": True}

    def click(self, ref):
        self._loc(ref).click(timeout=10000)
        self._settle()
        return {"ok": True}

    def type(self, ref, text, submit=False):
        loc = self._loc(ref)
        if self._is_passwordish(loc):
            return {"ok": False, "error": "password_field",
                    "detail": "credentials are entered by the owner on the live view (CH-8)"}
        loc.fill(text, timeout=10000)
        if submit:
            loc.press("Enter")
        self._settle()
        return {"ok": True}

    def select(self, ref, option):
        self._loc(ref).select_option(label=option, timeout=10000)
        self._settle()
        return {"ok": True}

    def snapshot(self):
        self._mark_password_fields()
        raw = self.page.locator("body").aria_snapshot(mode="ai", timeout=15000)
        secret_refs = set()
        for ref in set(re.findall(r'textbox[^\n]*\[ref=((?:f\d+)?e\d+)\]', raw)):
            try:
                if self._is_passwordish(self.page.locator(f"aria-ref={ref}")):
                    secret_refs.add(ref)
            except Exception:
                pass
        text = P.omit_values(raw, secret_refs)
        text, hits = P.redact_text(text)
        self.last_snapshot_hits = hits
        url, _ = P.redact_url(self.page.url)
        return {"ok": True, "url": url, "title": P.redact_text(self.page.title())[0],
                "snapshot": text, "redactions": hits, "password_fields": len(secret_refs)}

    def screenshot(self):
        snap = self.snapshot()
        if snap["redactions"]:
            return {"ok": False, "error": "withheld",
                    "detail": "page shows a value the detector matched (CRED-10)"}
        unmasked = any(self.page.locator(f"aria-ref={r}").evaluate("e => e.type !== 'password'")
                       for r in re.findall(r"\[ref=((?:f\d+)?e\d+)\]: \[password omitted\]",
                                           snap["snapshot"]))
        if unmasked:
            return {"ok": False, "error": "withheld", "detail": "an unmasked password field"}
        self.n_shot += 1
        out = self.ws / f"screenshot-{self.n_shot}.png"
        self.page.screenshot(path=str(out))
        return {"ok": True, "path": out.name, "bytes": out.stat().st_size}

    def download(self, ref):
        with self.page.expect_download(timeout=30000) as d:
            self._loc(ref).click()
        dl = d.value
        name = re.sub(r"[^A-Za-z0-9._-]", "_", dl.suggested_filename).lstrip(".")[:120] or "download"
        out = self.ws / name
        dl.save_as(str(out))
        if out.stat().st_size > MAX_DOWNLOAD:
            out.unlink()
            return {"ok": False, "error": "too_large"}
        return {"ok": True, "path": out.name, "bytes": out.stat().st_size}

    def handle(self, line):
        t0 = time.monotonic()
        try:
            req = P.validate(json.loads(line))
            args = {k: v for k, v in req.items() if k not in ("v", "verb")}
            res = getattr(self, req["verb"])(**args)
        except P.ProtocolError as e:
            res = {"ok": False, "error": "protocol", "detail": str(e)}
        except json.JSONDecodeError:
            res = {"ok": False, "error": "protocol", "detail": "not JSON"}
        except Exception as e:  # Playwright timeouts, detached elements, ...
            res = {"ok": False, "error": type(e).__name__,
                   "detail": P.redact_text(str(e).splitlines()[0][:300])[0]}
        if self.refused:
            res["refused_navigations"], self.refused = self.refused, []
            if self.page.url.startswith("chrome-error:"):
                self.page.go_back(wait_until="domcontentloaded")
        res["ms"] = round((time.monotonic() - t0) * 1000)
        return res

    def close(self):
        self.browser.close()
        self._pw.stop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--origins", nargs="+", required=True)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--storage-state")
    a = ap.parse_args()
    ex = Executor(a.origins, a.workspace, a.storage_state)
    try:
        for line in sys.stdin:
            if line.strip():
                sys.stdout.write(json.dumps(ex.handle(line)) + "\n")
                sys.stdout.flush()
    finally:
        ex.close()


if __name__ == "__main__":
    main()
