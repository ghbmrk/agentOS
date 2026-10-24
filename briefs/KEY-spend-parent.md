# KEY-spend-parent: a lowered day cap counts the day's earlier spend

Board row: issue #2838 (release, from Security 1 on #2837 and the #2847 delta L3). Tier A; grows the trusted core (`broker/kernel/key`), so the PR names a decision row in its `Trusted-core:` line (D-159 rule 3).

## Requirements (local IDs, no SPEC row; serve KEY-3 and KEY-6)

- **KEY-spend-parent-a.** A day spend cap can count the clerk's whole account under the root instead of its own link's share (`key.LowerSpendDay`, `Caveat.M` = 1 on `spend-day`). Any other `M` on a cap is malformed. A plain `LimitSpendDay` keeps counting its own link, so a share (loops' `EvalKey`) still means a share.
- **KEY-spend-parent-b.** keycheck (assurance/keycheck) judges the same rule, and the keydiff generator and predicate-reach mutants cover it.
- **KEY-spend-parent-c.** Every key `loops.Spare.SetCap` derives carries `LowerSpendDay`: after a lowering the day's earlier spend counts toward the new cap in the kernel, and a cap set twice, or a lower key left live by a raise, adds nothing to the day (#2838 comment 6369159011).
- Out of scope: the restart condition (#2838 comment 6368577772 item 2) stays a wiring condition (`broker/loops/ASSUMPTIONS.md` L3).

## Acceptance tests

**Acceptance tests:** KEY-spend-parent-a `broker/kernel/key TestLoweredDayCapCountsTheAccount`; KEY-spend-parent-b `broker/test/keydiff TestKeyDiff` and `TestPredicateReach/cap-scope-shape`, `/cap-scope-account`; KEY-spend-parent-c `broker/loops TestTheSpareCapCountsTheDaysEarlierSpend`.

## Scope

`broker/kernel/key/key.go`, `broker/kernel/key/key_test.go`, `assurance/keycheck/src/lib.rs`, `broker/test/keydiff/`, `broker/loops/spare.go`, `broker/loops/spare_test.go`, `broker/loops/ASSUMPTIONS.md`, this brief.
