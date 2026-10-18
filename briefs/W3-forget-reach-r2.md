# W3-forget-reach-r2: show take-backs held only in memory when `MarkBack` fails

Board row: W3-forget-reach-r2. Source: Security 4a R1 on #569. Class: release. Tier: A (touches recall provenance and the owner path; confirm with `tools/risk_tier.py`). Builder: strongest model. Estimate: 80k tokens, checkpoint 60k; if the STATUS half passes 40k, split it.

**Why (facts, verified at main 8676ac9).** `Provenance.MarkBack` (`broker/recalltool/provenance.go:483`) writes to the store whose `MarkReset` just failed, and on a write failure keeps the record in memory only (`p.apply(r)`). After a restart `Retry` finds no back record and runs the approved take-back's `ForgetSince` again, rolling the machines back a second time and losing later work (#327 L3 1).

**Requirement:** CAP-3 (actions taken stay done; a repeat rollback loses later work). Package IDs:
- **W3-forget-reach-r2-1** a take-back recorded only in memory (both `MarkReset` and `MarkBack` failed to write) appears on `Reach.Status` (STATUS) until a write succeeds, in existing CH-12 wording class; the builder names the line and raises any new owner text as a finding instead of adding it.
- **W3-forget-reach-r2-2** `MarkBack` also writes a back-marks file under `ServiceConfig.Dir` (passed to `NewService`, which hands it to `OpenProvenance`), and `OpenProvenance` reads it on start, so a restart does not re-run `ForgetSince` when the store write fails persistently. Record the file in `broker/recalltool/ASSUMPTIONS.md`. When `ServiceConfig.Dir` is empty (nil case) there is no second place: `MarkBack` behaves as before and the residual is recorded in ASSUMPTIONS.

**Acceptance tests:**
- W3-forget-reach-r2-1: `broker/recalltool/takeback_test.go::TestStatusShowsABackHeldOnlyInMemory`: both writes fail; `Status()` names it; after a write works it clears.
- W3-forget-reach-r2-2: `broker/recalltool/takeback_test.go::TestRestartAfterFailedBackMarkDoesNotRunForgetSinceAgain`: persistent store failure, restart (new `Provenance` over the same store and `Dir`), `Retry`; the fake machines see no second `ForgetSince`. Mutant: skip the second-place write.
- W3-forget-reach-r2-2 (nil case): `broker/recalltool/takeback_test.go::TestRestartAfterFailedBackMarkWithoutADirRunsForgetSinceAgain`: same, with no `Dir`; pins the recorded residual (a second `ForgetSince` happens).

**Scope:** `broker/recalltool/provenance.go`, `broker/recalltool/reach.go`, `broker/recalltool/service.go`, `broker/recalltool/takeback_test.go`, `broker/recalltool/ASSUMPTIONS.md`, this brief.
**Dependencies:** none; r4 shares `reach.go`/`takeback_test.go`, so r2 and r4 are built in sequence by one session or the second waits (D-111).
**Done:** CI green; all three tests pass; mutant fails.
