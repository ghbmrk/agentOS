# S5 result (interim): fixture suite done, live run blocked on network access

**Answer so far:** on a local fixture with the hard widget patterns, **yes**: v0 drives every pattern, and no planted canary leaves the executor. The 5 real sites have **not** been run: this cloud environment's network policy refuses them (`connect_rejected` for en.wikipedia.org, www.gov.uk and others). `live.py` is ready; one command (`python3 spikes/S5-browser-actions/live.py`) fills `results.jsonl` once access is opened.

## Fixture results [Measured, Chromium 141.0.7390.37 headless, Playwright 1.63.0]

`tests/test_s5_executor.py`, 17 tests, all pass:

| Pattern | Verbs used | Result |
|---|---|---|
| React-style controlled input, submit by Enter | type (`submit`) | ✅ input event fired, Enter seen |
| Native `<select>` | select | ✅ |
| Custom listbox (button + `role=option`) | click, click | ✅ |
| Button inside open shadow DOM | click | ✅ snapshot pierces shadow roots |
| Input inside a same-origin iframe | type | ✅ refs carry the frame (`f1e3`) |
| Download with a hostile filename (`../../etc/evil name.txt`) | download | ✅ saved in the workspace under a flat, safe name |
| Off-origin link, off-origin `target=_blank` popup, off-origin `navigate` | click, navigate | ✅ all refused, reported as `refused_navigations`, page restored |
| Redirect chain declared → declared → undeclared (link and `navigate`) | click, navigate | ✅ refused at the off-origin hop; the attacker server logged **no** hit |
| Form POST answered by a 303 to an undeclared origin | type (`submit`) | ✅ refused; no hit |
| Off-origin `<iframe>` in a declared page | snapshot | ✅ never loaded, so it has no refs; no hit |
| Declared redirect hop that sets a cookie | navigate | ✅ followed, cookie kept |
| Token in a URL fragment (`#access_token=…`) | click, snapshot | ✅ `url` comes back `access_token=[REDACTED]` |
| `evaluate`, `cookies`, `storage`, `set_header`, `devtools`, `javascript:` URL | — | ✅ refused by the validator |

Canaries (all synthetic): the HttpOnly session cookie, a script-readable cookie, a local-storage value, a saved password (also after the page's "Show password" toggle), an API key the page displays without a reveal step, a token in a link's query, and a token in a URL fragment. None appears in any response line, snapshot or downloaded file (checked by a named last test over the whole transcript). The displayed key and link token come back as `[REDACTED]`; screenshots of that page are withheld (CRED-10).

Executor memory on the fixture page: **165 MB PSS** with Chromium's headless shell, 280 MB with full Chromium in headless mode (browser processes only, shared pages counted once). S3's floor budget is 0.5 GB. Real sites will be measured by `live.py`.

## Findings so far

1. **Playwright's accessibility snapshot prints password values.** `aria_snapshot()` renders `textbox "Pass": <value>` for `type=password` inputs [Measured]. So "password fields omitted" (CRED-4) is not free from the reused component; the executor must strip values itself. It does, by ref, for inputs that are or ever were `type=password`, or whose autocomplete, name, id or label says password/PIN/OTP. The "ever were" part matters: a site's own Show-password toggle turns the field into `type=text`.
2. **`type` needs a submit flag.** Search boxes without a button submit only on Enter. v0 adds `submit: bool` to `type` rather than a general `press(key)` verb. This is a widening and needs L3 review.
3. **Refs, not selectors.** Playwright's AI snapshot mode assigns refs across iframes and shadow roots, and the executor resolves them. The agent never sends a selector, so the protocol has no query language to abuse. Stale refs fail closed ("take a new snapshot").
4. **Password fields refuse `type`.** Credentials are entered by the owner on the live view (CH-8); the protocol has no path to type one.
5. **The browser makes its own connections, which page-level routing does not see.** Full Chromium (headless mode, Playwright's default flags) connected to `www.google.com` and `android.clients.google.com` within seconds of launch, on a blank page, every run [Measured: egress proxy log]. Ten extra "disable" flags did not stop it. Chromium's headless shell made **none** in the same test. So: (a) the executor runs the headless shell; (b) the live view for owner logins (CH-8) needs a headed browser, which will make such calls, so executor egress must be confined to declared origins by the broker's proxy or network namespace, outside the browser, not by the browser's own request interception.

6. **Origin confinement needs more than request interception (found by L3 review, now fixed).** The first version checked only the first request of a top-level navigation. The reviewer reproduced three escapes: a declared URL that 302s to an undeclared origin (Playwright does not route redirect hops), an off-origin iframe that got refs and accepted a typed form, and a `#access_token=` fragment returned in clear in the `url` field. Fixes:
   - Every navigation request (top level, popup, subframe) on an undeclared origin is aborted.
   - Navigations are fetched with redirects off. Each `Location` is checked, and a declared hop is replayed as a fresh, routed navigation, so every hop is requested exactly once. A 307/308 after a POST is refused, because it cannot be replayed faithfully.
   - After every verb, the executor checks the main frame and every subframe against the declared origins, returns to the last good page and reports what it refused.
   - Fragments are redacted like query strings, and every URL, title and refused URL passes through the full detector.

   [Inference, from the reviewer] Without the redirect fix, an open redirect on any declared site would let a `private` agent send data in a URL to any host, around REV-5. That is why this is a confinement requirement, not a nicety.

Expected gaps that `live.py`'s `herokuapp_gaps` task probes (no verb exists for them in v0): JavaScript dialogs (Playwright auto-dismisses them), hover-only menus, and file upload.

## Known limits (not fixed in the spike)
- **Subresources and site scripts.** The site's own XHR, fetch and beacons to other origins are not blocked. They are the site's behaviour, not agent-directed navigation. Confining them is ADP-10 and finding 5, enforced outside the browser, and it is **not exercised** here.
- **Screenshots.** The withhold decision uses a snapshot taken just before the screenshot, so the page can change in between. Secrets drawn in canvas or images are not detected.
- **Downloads.** Text downloads pass the CRED-10 detector and are withheld on a match. Binary formats (PDF, images, archives) are not inspected. The 50 MB cap is checked after the browser saves the file, not while streaming. Neither is tested.
- **Snapshot size.** Capped at 256 K characters, with a truncation marker.
- **Settling.** Each action waits for 300 ms with no navigation in flight, then for network idle (up to 3 s). That is about 0.5 s per action on the fixture.

## Not done here
- **gVisor.** The ARC-5 risk line asks S5 to measure the browser under gVisor at the floor. Fetching gVisor was refused in this environment, so it is not measured. It moves to the N95 run with S3.
- **Real accounts.** No test accounts exist. Logins use each demo site's published credentials, entered out of band. They are kept in `demo_logins.json`, not in code. They are public strings printed on those sites' own login pages, so this is a documented exception to CLAUDE.md's no-credentials rule.
- **CI.** CI has no Chromium, so `test_s5_executor.py` skips there; `test_s5_protocol.py` runs.

## Proposed SPEC.md diff
Held until the live run.

## Model usage
Within the ~3% time box so far.
