# W3-forget-reach-r2: show take-backs held only in memory when `MarkBack` fails

Board row: W3-forget-reach-r2. Source: Security 4a R1 on #569. Class: release. Tier: A (touches recall provenance and the owner path; confirm with `tools/risk_tier.py`). Builder: strongest model. Estimate: 80k tokens, checkpoint 60k; if the STATUS half passes 40k, split it.

**Why (facts, verified at main 8676ac9).** `Provenance.MarkBack` (`broker/recalltool/provenance.go:483`) writes to the store whose `MarkReset` just failed, and on a write failure keeps the record in memory only (`p.apply(r)`). After a restart `Retry` finds no back record and runs the approved take-back's `ForgetSince` again, rolling the machines back a second time and losing later work (#327 L3 1).

**Requirement:** CAP-3 (actions taken stay done; a repeat rollback loses later work). Package IDs:
- **W3-forget-reach-r2-1** a take-back recorded only in memory (both `MarkReset` and `MarkBack` failed to write) appears on `Reach.Status` (STATUS) until a write succeeds, in existing CH-12 wording class; the builder names the line and raises any new owner text as a finding instead of adding it.
- **W3-forget-reach-r2-2** the builder picks one: write the back mark to a second place (the owed file next to the owed entries) so a restart does not re-run `ForgetSince`, or accept the residual and record it in `broker/recalltool/ASSUMPTIONS.md`. Pick with a sentence on cost; the test proves the choice.

**Acceptance tests:**
- W3-forget-reach-r2-1: `broker/recalltool/takeback_test.go::TestStatusShowsABackHeldOnlyInMemory`: both writes fail; `Status()` names it; after a write works it clears.
- W3-forget-reach-r2-2: `broker/recalltool/takeback_test.go::TestRestartAfterFailedBackMarkDoesNotRunForgetSinceAgain`: persistent store failure, restart (new `Provenance` over the same dir), `Retry`; the fake machines see no second `ForgetSince`. Mutant: skip the second-place write.

**Scope:** `broker/recalltool/provenance.go`, `broker/recalltool/reach.go`, `broker/recalltool/takeback_test.go`, `broker/recalltool/ASSUMPTIONS.md`, this brief.
**Dependencies:** none; r4 shares `reach.go`/`takeback_test.go`, so r2 and r4 are built in sequence by one session or the second waits (D-111).
**Done:** CI green; both tests pass; mutant fails.
