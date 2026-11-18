# BROWSER-fixture-ci-fu: the headless-shell pin moves with Playwright's, and its download is cached

Board section: Defects and later findings on surviving packages. Work item #6064 (release items from the reviews of #6056, carried to #6063, row #5952).

**Problem:** broker-checks' browser step pins Playwright by wheel hash (`tests/requirements-browser.txt`) and the Chrome for Testing headless shell by URL and hash (`CFT_SHELL_URL`, `CFT_SHELL_SHA256`), but nothing ties the two, so a Playwright bump that keeps the old shell runs a driver against a browser it was not built for (K4). The ~100 MB shell is also downloaded on every run.

**Requirements:** K4 (the gate is exercised through a real driver, on the browser its driver names).
1. A test fails when the shell `CFT_SHELL_URL` names is not the `chromium-headless-shell` build the installed, pinned Playwright wheel's `browsers.json` names, and runs (never skips) in the browser step.
2. The shell zip is cached on its pin: restored on any run, saved on a push to main only, and hash-checked after a restore before it is unzipped.
3. #6063's strict script run already fails on a skipped Python fixture test (`strict_code`), so issue item 3 needs no change.

**Scope:** `.github/workflows/ci.yml` (broker-checks: job env, a restore step, the browser step, a save step), `tests/test_s5_executor.py` (`ShellPin`), `tests/test_ci_scope.py` (the cache wiring), this brief. No production code.

**Acceptance tests:** `tests/test_s5_executor.py::ShellPin` (passes in the browser step on the pinned wheel; its pure half fails when either pin moves alone); `tests/test_ci_scope.py::WiringTest::test_the_headless_shell_cache_restores_on_prs_saves_on_main_and_is_hash_checked` (the wiring and its mutants).

**Guard files:** `.github/workflows/ci.yml` (gate file: separate Security accept).

**Dependencies:** BROWSER-fixture-ci (merged, #6063).

**Tier / gate:** tier A (CI supply chain): L3 on the strongest model, lens screen, separate Security accept.

**Usage estimate:** one session, under 80k.
