# S5 result (interim): fixture suite done, live run blocked on network access

**Answer so far:** on a local fixture with the hard widget patterns, **yes**: v0 drives every pattern, and no planted canary leaves the executor. The 5 real sites have **not** been run: this cloud environment's network policy refuses them (`connect_rejected` for en.wikipedia.org, www.gov.uk and others). `live.py` is ready; one command (`python3 spikes/S5-browser-actions/live.py`) fills `results.jsonl` once access is opened.

## Fixture results [Measured, Chromium 141.0.7390.37 headless, Playwright 1.63.0]

`tests/test_s5_executor.py`, 11 tests, all pass:

| Pattern | Verbs used | Result |
|---|---|---|
| React-style controlled input, submit by Enter | type (`submit`) | ✅ input event fired, Enter seen |
| Native `<select>` | select | ✅ |
| Custom listbox (button + `role=option`) | click, click | ✅ |
| Button inside open shadow DOM | click | ✅ snapshot pierces shadow roots |
| Input inside a same-origin iframe | type | ✅ refs carry the frame (`f1e3`) |
| Download with a hostile filename (`../../etc/evil name.txt`) | download | ✅ saved in the workspace under a flat, safe name |
| Off-origin link, off-origin `target=_blank` popup, off-origin `navigate` | click, navigate | ✅ all refused, reported as `refused_navigations`, page restored |
| `evaluate`, `cookies`, `storage`, `set_header`, `devtools`, `javascript:` URL | — | ✅ refused by the validator |

Canaries (all synthetic): the HttpOnly session cookie, a script-readable cookie, a local-storage value, a saved password (also after the page's "Show password" toggle), an API key the page displays without a reveal step, and a token in a link's query. None appears in any response line, snapshot or downloaded file. The displayed key and link token come back as `[REDACTED]`; screenshots of that page are withheld (CRED-10).

Executor memory on the fixture page: **165 MB PSS** with Chromium's headless shell, 280 MB with full Chromium in headless mode (browser processes only, shared pages counted once). S3's floor budget is 0.5 GB. Real sites will be measured by `live.py`.

## Findings so far

1. **Playwright's accessibility snapshot prints password values.** `aria_snapshot()` renders `textbox "Pass": <value>` for `type=password` inputs [Measured]. So "password fields omitted" (CRED-4) is not free from the reused component; the executor must strip values itself. It does, by ref, for inputs that are or ever were `type=password`, or whose autocomplete, name, id or label says password/PIN/OTP. The "ever were" part matters: a site's own Show-password toggle turns the field into `type=text`.
2. **`type` needs a submit flag.** Search boxes without a button submit only on Enter. v0 adds `submit: bool` to `type` rather than a general `press(key)` verb. This is a widening and needs L3 review.
3. **Refs, not selectors.** Playwright's AI snapshot mode assigns refs across iframes and shadow roots, and the executor resolves them. The agent never sends a selector, so the protocol has no query language to abuse. Stale refs fail closed ("take a new snapshot").
4. **Password fields refuse `type`.** Credentials are entered by the owner on the live view (CH-8); the protocol has no path to type one.
5. **The browser makes its own connections, which page-level routing does not see.** Full Chromium (headless mode, Playwright's default flags) connected to `www.google.com` and `android.clients.google.com` within seconds of launch, on a blank page, every run [Measured: egress proxy log]. Ten extra "disable" flags did not stop it. Chromium's headless shell made **none** in the same test. So: (a) the executor runs the headless shell; (b) the live view for owner logins (CH-8) needs a headed browser, which will make such calls, so executor egress must be confined to declared origins by the broker's proxy or network namespace, outside the browser, not by the browser's own request interception.

Expected gaps that `live.py`'s `herokuapp_gaps` task probes (no verb exists for them in v0): JavaScript dialogs (Playwright auto-dismisses them), hover-only menus, and file upload.

## Not done here
- **gVisor.** The ARC-5 risk line asks S5 to measure the browser under gVisor at the floor. Fetching gVisor was refused in this environment, so it is not measured. It moves to the N95 run with S3.
- **Real accounts.** No test accounts exist; logins use each demo site's published credentials, entered out of band.
- **CI.** CI has no Chromium, so `test_s5_executor.py` skips there; `test_s5_protocol.py` runs.

## Proposed SPEC.md diff
Held until the live run.

## Model usage
Within the ~3% time box so far.
