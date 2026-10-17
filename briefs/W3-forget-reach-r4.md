# W3-forget-reach-r4: `Retry`'s default `TakenBack` text only for approved take-backs

Board row: W3-forget-reach-r4. Source: Security 4a R3 on #569; also L3 L1. Class: release (RCH-3). Tier: A (`tools/risk_tier.py` prints A for `broker/recalltool/reach.go`). Builder: strongest model. Estimate: 40k tokens, checkpoint 30k.

**Why (facts, verified at main 8676ac9).** With `OnTakenBack` unset, `Retry` (`broker/recalltool/reach.go:259-264`) calls `r.tell(tb.Lineage, TakenBack)` for every take-back it saw not done and sees done, including ones `TakeBack` returned nil for and unasked ones, not only after `ErrCarried` as before RCH-3 (T4 in `broker/recalltool/ASSUMPTIONS.md` describes it as "now only once the reach is finished"). An unasked take-back (the owner was never asked) can therefore be told "Your agent is back to before that task".

**Requirement:** CAP-3 / CH-12 (no text claims what the owner did not approve). Package ID **W3-forget-reach-r4-1**: with the hook unset, `Retry` sends `TakenBack` only for take-backs the owner approved; an unasked one sends nothing. Alternative the builder may take with a reason: keep the behaviour and record it in ASSUMPTIONS T4; then the test pins the recorded behaviour.

**Acceptance tests:**
- W3-forget-reach-r4-1: `broker/recalltool/takeback_test.go::TestRetryWithoutAHookTellsOnlyApprovedTakeBacks`: one approved and one unasked take-back both finish in `Retry`; exactly one `TakenBack` is told. Mutant: tell for all.

**Scope:** `broker/recalltool/reach.go`, `broker/recalltool/takeback_test.go`, `broker/recalltool/ASSUMPTIONS.md`, this brief.
**Dependencies:** none. Build before r5 only if r5's test file would conflict (separate files today).
**Out of scope:** text wording (CH-12 lint), the hook path.
**Done:** CI green; test passes; mutant fails.
