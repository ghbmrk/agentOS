# ADP-8b: Wire the demo mismatch check into §11 adoption

Board section: Adapter path. Follow-up of ADP-8 (PR #208), from the L3, Potency and Security release findings on that PR (one review set, one brief).

**Requirements:** ADP-8, ADP-6. **Acceptance test:** A13.

1. Call `verb.Mismatch` on the §11 adoption path so that an adapter whose demo run mismatches is not adopted (L3 release point; Potency release point; Security release point).
2. Fill `DemoRun.Outbound` from the demo harness's observed egress, never from the adapter's own declaration (broker/verb/ASSUMPTIONS.md V3).
3. Deliver the ADP-6 half of the original ADP-8 brief (agent-drafted adapters through the change pipeline, new grants and unmapped operations asked of the owner, private-derived).
4. Test end to end against A13, with a revert mutant that drops the check.
5. Require one demo run per declared operation before calling `Mismatch`; an operation that was never exercised is not a pass. Test the missing-run case (L3 release point on #696).
6. Record each demo run's observed effect class from the harness, not a bare `Outbound` bool, and block when it is stricter than the mapped verb's class, so a payment mapped to `send` blocks too (ADP-8 "observed effects exceed its verb"; Security 4a release point on #696). Failure path: the owner pre-allows `send` (ADP-9), the adapter maps a purchase to it, and it pays with no approval.

Failure path without it: an adoption path that skips the check, or trusts the adapter's claim for `Outbound`, adopts a draft (or organize) that sends, and A13 fails while TRACE counts ADP-8 as covered.

**Needs:** ADP-8, P3-1, P2-7

**Gate:** tier A (L3 with threat check, Security), lenses (UX, Potency)
