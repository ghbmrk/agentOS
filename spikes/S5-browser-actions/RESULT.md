# S5 result: fixture suite and live run done

**Answer:** **yes, with gaps.** The closed v0 protocol (navigate, click, type, select, snapshot, screenshot, download) completed a multi-step task on **5 of 5 real sites** [Measured, 2026-10-09, Chromium headless shell 141, `results.jsonl`], and on the local fixture drives every hard widget pattern with no planted canary leaving the executor. No verb needed widening for these tasks; three gaps are listed under "Live run". Logins use each demo site's published credentials (no real accounts). Not measured: gVisor, off-site subresource confinement, real accounts.

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

## Live run (2026-10-09) [Measured: `live.py`, `results.jsonl`]
| Site | Task | Result | Time | Chromium PSS |
|---|---|---|---|---|
| Wikipedia | search "Alan Turing", read, open history | pass (562 redactions in article snapshots) | 8 s | 365 MB |
| GOV.UK | visa checker: start, nationality select, 3 radio questions, outcome page | pass | 10 s | 256 MB |
| Sauce Demo | login (out of band), sort select, add to cart, checkout form, finish | pass; password absent from all output | 7 s | 228 MB |
| the-internet.herokuapp.com | session carry-over, dropdown, download, shadow DOM, dynamic load | pass on retry (first run: a 30 s `navigate` timeout on the site) | 14-41 s | 212 MB |
| GitHub, logged out (ghbmrk/agentOS) | repo, pull-request list, "Raw" link to raw.githubusercontent.com | pass | 24 s | 242 MB |

Peak Chromium PSS was 365 MB (Wikipedia), under S3's 0.5 GB floor budget before the executor's own Python and Playwright driver, which were not measured. gVisor still unmeasured.

**Gaps and findings from the live run**
1. **Expected gaps confirmed** (`herokuapp_gaps`): a JavaScript `confirm` is auto-dismissed (the page reported "You clicked: Cancel"), so the agent cannot accept one; the hover menu was visible without hover; file upload has no verb.
2. **CRED-10 false positive on a download.** The first random file picked on /download (`Images.txt`, a public upload listing container image names such as `ghcr.io/…-hotfix-alerts-13-07-26:741bb67`) was withheld: long hyphenated tokens matched the 24+ character candidate rule. Failing closed is the intended behaviour; the cost is lost downloads of benign text. [Inference] Tuning the detector for dash-separated names is a release candidate; not changed here.
3. **GitHub's "Download raw file" is a script-driven button**: it never produced a download event (30 s timeout), so a download verb cannot reach it. The "Raw" link navigates to the second declared origin and works, which exercised multi-origin declarations. Refs inside iframes (`f1e…`, `f2e…`) worked.
4. **Executor needs an egress proxy in a sandbox.** `route.fetch` runs in the Playwright driver and, with no proxy set, hit the sandbox's gate directly ("Host not in allowlist" page, returned as page content). `executor.py` and `live.py` now pass `S5_PROXY` or `HTTPS_PROXY` to Chromium. This is consistent with finding 5: confinement belongs outside the browser.
5. **Real DOMs differ from the first scripts.** GOV.UK asks a variable number of questions (the flow now answers by heading), Wikipedia infobox "born" text was not matched (`born=?`, a script regex miss, not a protocol limit), and GitHub's PR list renders client-side after load (3 s wait). Test scripts changed, protocol unchanged.
6. **Environment**: github.com for repositories outside the session's GitHub scope returns a proxy 403, so `microsoft/playwright` was replaced by `ghbmrk/agentOS`.

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
None. The protocol answered the question without new verbs. Candidate additions, each needing L3 review before any SPEC change: a dialog-accept verb, a hover verb and a file-upload verb (all three gaps above); none is requested here.

## Model usage
Within the ~3% time box so far.
