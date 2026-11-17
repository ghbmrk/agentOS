# BROWSER-fixture-ci: the broker CI job runs the real-driver fixture tests instead of skipping them

Board section: Defects and later findings on surviving packages. Work item #5952 (found while building BROWSER-fixture-gate, #4409).

**Problem:** `TestFixtureThroughTheGate` and `TestFixtureRefsFollowTheDriversDocument` (`broker/browser/fixture_test.go`) and `tests/test_s5_executor.py` pass where Python Playwright 1.63 and a Chromium headless shell exist, but no CI job has them, so every run skips them. A gate change that breaks the real driver (a ref rule, the login redirect, a withheld snapshot) merges green (K4).

**Requirements:** K4 (the gate is exercised through a real driver).
1. A required CI job installs Playwright 1.63 and its dependencies by hash, and the headless shell Playwright 1.63 names, refused unless it hashes to a pin.
2. That job runs both Go fixture tests and `tests/test_s5_executor.py`, and fails, never skips, when either cannot run.
3. Without the requirement switch the tests still skip, so `go test ./...` and the unit-test job are unchanged.

**Scope:** `.github/workflows/ci.yml` (one step in `broker-checks`, a required job, so no ruleset or premerge change), `tests/requirements-browser.txt` (new), `tests/test_s5_executor.py`, `tests/test_ci_scope.py` (its machines-step mutations anchor on that step's own `require_ran.py` call), `broker/browser/ASSUMPTIONS.md`, this brief. No production code.

**Acceptance tests:** the new broker-checks step passes on the PR with `require_ran.py` reporting both Go tests passed and the executor's 17 fixture tests run; `tests/test_s5_executor.py::RequireBrowser` shows a missing browser fails under `AGENTOS_REQUIRE_BROWSER=1` and skips otherwise, and that the script run the step uses exits 1 on any skip.

**Guard files:** `.github/workflows/ci.yml` (gate file: separate Security accept).

**Dependencies:** BROWSER-fixture-gate (merged).

**Tier / gate:** tier A (`broker/browser`, CI supply chain): L3 on the strongest model, lens screen, separate Security accept.

**Usage estimate:** one session, under 80k.
