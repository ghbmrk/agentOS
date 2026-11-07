# KEY-9-reach-a: the fixed worth table and the proof ladder, CH-3 as the floor

Board section: Owner channel and approvals (SPEC §10). Work item #4529, split under its own brief clause ("a: table and floor; b: reach and the grow-narrow rule"). Part b is #4999.

**Problem:** KEY-9 (D-307) prices granting or widening a key by its reach, never below CH-3. The key-check library has no notion of a key's worth, of CH-3's proof rungs, or of a worth term for the KEY-8 hold.

**Requirements:** KEY-9 (part a). A fixed table in the key-check library (`broker/kernel/key`, the signed image, KRN-3): what each verb on the closed list reaches directly (CLK-14's effect classes as asset classes none, data, money, identity, safety); each class's rank capped or uncapped by a spend caveat; for each rank the proof a widening and an approval need and a hold lengthening; and CH-3's fifteen rows as the floor. `Price(act, worth)` is the larger of the act's CH-3 row and its column at the key's worth. Unknown verbs, classes, acts and ranks price highest.

**Out of scope (#4999):** reach over the declarations' edges, wiring the price into `State.grants`, the co-sign and the hold, grows-then-narrows, the FRM-key model's worth term. Nothing here changes a grant's outcome or a hold's length yet.

**Scope:** `broker/kernel/key/worth.go`, `broker/kernel/key/worth_test.go`, `broker/kernel/ASSUMPTIONS.md` (rows KEY-9-reach-a-1..3), this brief.

**Acceptance tests:** `broker/kernel/key/worth_test.go`: `TestEveryCH3RowIsPricedAtLeastItsProof` (each CH-3 row, typed from SPEC.md by hand, costs exactly its proof at the lowest worth and never less at any worth; catches a table edit that lowers a row), `TestWorthIsMonotone` (generated verb sets: adding a verb never lowers worth, a cap or dropping verbs never raises it, no price or hold falls as worth rises), `TestDeriveNeverRaisesWorth` (a real `Derive` narrowing prices at or below its parent), `TestUnknownPricesHighest` (fail-closed paths), `TestPricesFromReach` (representative keys), `TestTableHoldsItsRules` (every listed verb has a reach; KRN-4's high-risk verbs are worth the most uncapped).

**Tier / gate:** tier A (trusted base): L3 and a separate Security accept.
