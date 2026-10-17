# Assumptions: the Codex worker test harness

What `tests/test_codex_worker.py` and its stubs rest on, beyond `guest/codex/ASSUMPTIONS.md`.

| ID | Assumption | Serves | If wrong |
|----|------------|--------|----------|
| T1 | **The one pid-namespace stall (#1527, 2026-10-14) was not the wrapper's** (#1627). Evidence, measured 2026-10-17: the shipped wrapper's pid-namespace run takes about 2s and a `$$` mutant's about 12s, every fixed wait in the stubs is bounded (at most about 48s a run, under the 60s deadline), and the module is wait-bound (about 1.3s of CPU in 57s), so load barely moves it. No load reproduced a hang: the pid-namespace test on main passed 30 of 30 (8 CPU hogs, 3 at once), the pre-#1612 code passed 40 of 40 and its whole module 32 of 32 (16 hogs, 4 and 8 at once, 88 mounts as on a CI runner), and this branch passed 30 of 30 (16 hogs, 3 at once). No CI run since #1612 shows a stall report. The one path to a hang that stayed past the deadline was the beat tool inheriting the worker's pipes, which #1612 closed (DEVNULL, own session, test-owned deadline). | CRED-5, A14 | A recurrence prints #1612's stall report with the phase and the process list; #1616 tracks it, and that report decides the next fix. |
| T2 | `stub_cli.py --skip-outlives` is used only on runs that assert descriptors, never containment: `assert_contained` requires `outlives` to be exactly False, so a skipped probe fails it. | CRED-5, A14 | A containment test using the flag fails, never passes. |
