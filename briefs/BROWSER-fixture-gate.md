# BROWSER-fixture-gate: TestFixtureThroughTheGate signs in first and finds Playwright 1.63's headless shell

Board section: Defects and later findings on surviving packages. Work item #4409 (found while building CRED-4b-r3, #4406).

**Problem:** `TestFixtureThroughTheGate` (`broker/browser/fixture_test.go`) fails on main wherever it can run: its first step navigates to `/app.html`, which the fixture server now redirects to `/login.html` without the session cookie. It is skipped in CI and cloud sessions because its default glob (`/opt/pw-browsers/chromium_headless_shell-*/chrome-linux/headless_shell`) misses Playwright 1.63's layout (`chrome-headless-shell-linux64/chrome-headless-shell`). The real-driver path is unchecked anywhere (K4).

**Requirements:** K4 (the gate is exercised through a real driver).
1. The test signs in through the fixture's owner login (or passes a storage state) before `/app.html`.
2. The browser lookup matches both the old and the 1.63 layout.
3. The test runs and passes in a cloud session with the pre-installed Chromium (`/opt/pw-browsers`); CI enablement stays a separate step if the broker job lacks Python Playwright, recorded on the PR's Findings line.

**Scope:** `broker/browser/fixture_test.go`, the fixture server's test files under `broker/browser/` if the login helper lives there, `broker/browser/ASSUMPTIONS.md`, this brief. No production code.

**Acceptance tests:** `broker/browser/fixture_test.go::TestFixtureThroughTheGate` itself, run with `S5_CHROME` unset in a cloud session, passes and its snapshot holds the "Search" box; catches the login redirect and the missed glob. The PR body quotes the passing run's summary line.

**Guard files:** none.

**Dependencies:** none open.

**Tier / gate:** tier A (`broker/browser`, credential): L3 on the strongest model, lens screen, separate Security accept.

**Usage estimate:** one session, under 60k.
