# S5: Credentialed browser through the narrow action protocol

**Question (BOARD S5, PLAN.md §3):** Can the closed action protocol of CRED-4 (navigate, click, type, select, accessibility snapshot, screenshot, download; no arbitrary JavaScript, no cookie/storage/header access, no devtools) drive 5 real sites?

**Kill/pivot rule:** too weak → widen verbs carefully, each new verb reviewed by L3.

**Also measured (ARC-5 risk line):** the browser executor's memory against S3's 0.5 GB floor budget. Running it under gVisor was not possible in this environment (see RESULT.md).

**Method:**
1. `protocol.py`: v0 of the protocol as a validator over JSON requests, plus the CRED-10 output detector and password-value omission. Targets are snapshot refs (`e12`), never selectors, so the agent supplies no query language.
2. `executor.py`: a broker-owned executor on Playwright + Chromium, serving the protocol on stdio. It holds the session (loaded from the owner's out-of-band login, CH-8), keeps the credentialed context on declared origins, and redacts output.
3. `client.py`: the agent side. Task scripts see only protocol responses and pick refs by role and accessible name, as a model would.
4. `fixture/`: a local site with the hard widget patterns (controlled inputs, native and custom selects, shadow DOM, iframe, popups, downloads) and planted synthetic canaries (session cookie, local storage, saved password with a show toggle, a displayed API key, a token-bearing link). Tests: `tests/test_s5_protocol.py` (pure, runs in CI), `tests/test_s5_executor.py` (needs Chromium).
5. `live.py`: five real sites, each with a multi-step task, logins only with the sites' own published demo credentials: Wikipedia (search, read, history), GOV.UK (visa checker: start, nationality select, radios, outcome), Sauce Demo (React shop: sort, add to cart, checkout form, finish), the-internet.herokuapp.com (session carry-over, dropdown, download, shadow DOM, dynamic load; plus a probe of dialogs, hover menus and file upload), GitHub logged out (repo, issues, raw download from a second declared origin).

**Time box:** one working session; ~3% of the weekly allowance.

**Out of scope:** real accounts (no test accounts were provisioned; demo logins stand in), the broker's intent gating of what a click does (ADP-2; SPEC §17 open risk 4), the uncredentialed context for off-origin links (refused here, not reopened).
