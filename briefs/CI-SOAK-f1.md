# CI-SOAK-f1: Fixtures independent of umask and tmpfs block accounting

Board section: Harness and operating model.

**Source draft:** [#255](https://github.com/ghbmrk/agentOS/pull/255) (Codex), +14/−1, CI green on its base.

**Defect: CI-SOAK.** Three broker tests assume the runner's umask and that directories consume blocks. Under umask 0077 `TestSymlinkedSocketDirectoryIsRefused` creates its directory with the wrong mode; on tmpfs the worker fixtures in `TestCAP8OverTheCapSaysRollBackOrDestroy` and `delete_test.go` `fullWorker` land exactly on the 1 MiB cap instead of above it, so they test the wrong boundary.

**Requirements:** no new IDs; the change keeps the existing CAP-8 and socket-hardening tests testing what their markers claim.

**Scope:** `broker/sockets/hardening_test.go`, `broker/workers/delete_test.go`, `broker/workers/workers_test.go`. Test files only; no production change.

**Acceptance:** reproduce each failure first (`umask 0077` for sockets; `TMPDIR` on a tmpfs for workers), then show the same tests pass under both conditions and the default runner. PR body carries `Defect: CI-SOAK`.

**Needs:** —

## Delivery

Builder model: strongest model (risk tier A: tests inside a tier-A package; PILOT-S). Write or keep the failing test first, then the smallest change; one package per session. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening the PR; if it prints a higher tier than A, stop and hand off. Estimate/checkpoint: 8k tokens, not a ceiling (OPERATING §5). Start from current main, not the draft's base: reuse the draft's diff where it still applies and credit the PR in the body; leave the draft open (Mark, 2026-10-09).
