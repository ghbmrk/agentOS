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
from urllib.parse import urljoin

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import protocol as P  # noqa: E402

CHROME = os.environ.get(
    "S5_CHROME", "/opt/pw-browsers/chromium_headless_shell-1194/chrome-linux/headless_shell")
MAX_DOWNLOAD = 50 * 1024 * 1024
PASSWORDISH = re.compile(r"pass(word|wd|code)?|pin\b|secret|otp", re.I)


class Executor:
    def __init__(self, origins, workspace, storage_state=None, headless=True):
        from playwright.sync_api import sync_playwright

        self.origins = origins
        self.ws = pathlib.Path(workspace)
        self.ws.mkdir(parents=True, exist_ok=True)
        self.refused = []
        self.stubs = set()  # URLs answered with a redirect stub; never returned to
        self.last_good = "about:blank"
        self._pw = sync_playwright().start()
        # Sandboxes that force egress through a proxy: S5_PROXY (default $HTTPS_PROXY).
        proxy = os.environ.get("S5_PROXY") or os.environ.get("HTTPS_PROXY")
        self.browser = self._pw.chromium.launch(
            executable_path=CHROME, headless=headless,
            **({"proxy": {"server": proxy}} if proxy else {}))
        self.ctx = self.browser.new_context(
            storage_state=storage_state, accept_downloads=True,
            viewport={"width": 1280, "height": 900})
        self.ctx.route("**/*", self._route)
        self.inflight = set()  # navigation requests not yet finished or failed
        self.ctx.on("request", lambda r: r.is_navigation_request() and self.inflight.add(r))
        self.ctx.on("requestfinished", lambda r: self.inflight.discard(r))
        self.ctx.on("requestfailed", lambda r: self.inflight.discard(r))
        self.page = self.ctx.new_page()
        self.ctx.on("page", self._on_page)
        self.last_snapshot_hits = 0
        self.n_shot = 0

    # CRED-10: no frame of the credentialed context (top level, popup or subframe) ever
    # loads an undeclared origin, including through a redirect hop.
    def _route(self, route):
        req = route.request
        if not req.is_navigation_request():
            return route.continue_()  # the site's own subresources (ADP-10 confines egress)
        if not P.on_declared_origin(req.url, self.origins):
            self._refuse(req.url)
            return route.abort("blockedbyclient")
        # Playwright does not route redirect hops, so fetch with redirects off and check
        # each Location ourselves. A declared hop is replayed as a fresh navigation (which
        # is routed again); every hop is requested exactly once.
        resp = route.fetch(max_redirects=0)
        loc = resp.headers.get("location")
        if 300 <= resp.status < 400 and loc:
            nxt = urljoin(req.url, loc)
            if not P.on_declared_origin(nxt, self.origins):
                self._refuse(nxt)
                return route.abort("blockedbyclient")
            if resp.status in (307, 308) and req.method != "GET":
                # A method-preserving redirect of a form post cannot be replayed as a
                # navigation; refuse rather than let the browser follow it unchecked.
                self._refuse(nxt)
                return route.abort("blockedbyclient")
            # route.fetch shares the context's cookie jar, so the hop's Set-Cookie is kept.
            # A 301/302/303 after a POST continues as a GET, as browsers do.
            self.stubs.add(req.url)
            hop = json.dumps(nxt).replace("<", "\\u003c")
            return route.fulfill(status=200, content_type="text/html",
                                 body=f"<script>location.replace({hop})</script>")
        return route.fulfill(response=resp)

    def _refuse(self, url):
        self.refused.append(P.redact_text(url)[0])

    def _confine(self):
        """Post-verb check: anything that still escaped is reverted and reported."""
        main = self.page.main_frame
        if main.url.startswith("chrome-error:") or (
                main.url.startswith("http") and not P.on_declared_origin(main.url, self.origins)):
            # A refused hop leaves an error page; return to the last page the agent saw
            # (not history.back(), which would re-run a redirect stub).
            if main.url.startswith("http"):
                self._refuse(main.url)
            self.page.goto(self.last_good, wait_until="domcontentloaded")
            self._settle()
            return
        if main.url.startswith("http") and main.url not in self.stubs:
            self.last_good = main.url
        for f in self.page.frames[1:]:
            if f.url.startswith("http") and not P.on_declared_origin(f.url, self.origins):
                self._refuse(f.url)
                try:
                    f.frame_element().evaluate("e => e.remove()")
                except Exception:
                    pass

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
                self._refuse(page.url)
            page.close()

    def _settle(self, quiet_ms=300, limit_ms=15000):
        """Wait until no navigation is in flight for quiet_ms (redirect stubs and form
        posts start theirs after the action returns), then for the page to load."""
        waited = quiet = 0
        while waited < limit_ms and quiet < quiet_ms:
            self.page.wait_for_timeout(50)
            waited += 50
            quiet = 0 if self.inflight else quiet + 50
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
        return {"ok": True}

    def click(self, ref):
        self._loc(ref).click(timeout=10000)
        return {"ok": True}

    def type(self, ref, text, submit=False):
        loc = self._loc(ref)
        if self._is_passwordish(loc):
            return {"ok": False, "error": "password_field",
                    "detail": "credentials are entered by the owner on the live view (CH-8)"}
        loc.fill(text, timeout=10000)
        if submit:
            loc.press("Enter")
        return {"ok": True}

    def select(self, ref, option):
        self._loc(ref).select_option(label=option, timeout=10000)
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
        url, h_url = P.redact_text(self.page.url)
        title, h_title = P.redact_text(self.page.title())
        hits += h_url + h_title
        self.last_snapshot_hits = hits
        text, truncated = P.cap_snapshot(text)
        return {"ok": True, "url": url, "title": title, "snapshot": text, "truncated": truncated,
                "redactions": hits, "password_fields": len(secret_refs)}

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
        # Known limit: the size cap is checked after the browser has saved the file.
        if out.stat().st_size > MAX_DOWNLOAD:
            out.unlink()
            return {"ok": False, "error": "too_large"}
        # CRED-10 on downloads: a file whose text the detector matches is withheld.
        # Binary formats (PDF, images, archives) are not inspected [untested limit].
        _, hits = P.redact_text(out.read_bytes().decode("utf-8", "replace"))
        if hits:
            out.unlink()
            return {"ok": False, "error": "withheld",
                    "detail": "downloaded file contains a value the detector matched (CRED-10)"}
        return {"ok": True, "path": out.name, "bytes": out.stat().st_size}

    def handle(self, line):
        t0 = time.monotonic()
        req = {}
        try:
            req = P.validate(json.loads(line))
            args = {k: v for k, v in req.items() if k not in ("v", "verb")}
            res = getattr(self, req["verb"])(**args)
        except P.ProtocolError as e:
            res = {"ok": False, "error": "protocol", "detail": str(e)}
        except json.JSONDecodeError:
            req, res = {}, {"ok": False, "error": "protocol", "detail": "not JSON"}
        except Exception as e:  # Playwright timeouts, detached elements, ...
            res = {"ok": False, "error": type(e).__name__,
                   "detail": P.redact_text(str(e).splitlines()[0][:300])[0]}
        try:
            if req.get("verb") in ("navigate", "click", "type", "select", "download"):
                self._settle()
            self._confine()
        except Exception:
            pass
        try:
            # Every reply names the page it ended on, so the broker gate can check
            # confinement after actions too (CRED-10 G4); it stops the executor on
            # an ok reply without one.
            res["url"] = P.redact_text(self.page.url)[0]
        except Exception:
            res.pop("url", None)
        if self.refused:
            res["refused_navigations"] = list(dict.fromkeys(self.refused))
            self.refused = []
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
