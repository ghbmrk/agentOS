# KEY-9-reach-b2c: the worth term of the hold in the FRM-key model and in keycheck

Board section: Owner channel and approvals (SPEC §10). Work item #5674, split from #5060 (KEY-9-reach-b2), its item 3. b1 (#4999 part 1, `briefs/KEY-9-reach-b1.md`) added a worth term to the hold: `Verified.Window(vb, novel)` in `broker/kernel/key/worth.go` lengthens an irreversible step's KEY-8 window by `HoldExtra` of what the step's own verb reaches at the key's caps, except for a bare root and for a step the owner approved one by one (a passkey-signed tip, `ByOwner`, with a `uses` caveat of exactly 1). Neither second check covers that term yet: `KeyVerdict.tla` models only `Limits.Window`, and keydiff compares only `Limits.Window` (`broker/test/keydiff/diff_test.go`, the `Hold` field). This row closes both. It adds no trusted lines (the model, the vectors, the Rust checker and tests are outside `tools/trusted_core.txt`), so it needs no offset and does not wait on b2-cut.

**Requirements:** KEY-9 (the hold lengthens with worth), KEY-8, KEY-3. FRM-key (#2936): a rule change changes the model, the vectors and the code together.

1. **Model.** `broker/kernel/formal/KeyVerdict.tla` gains the worth term. The two verbs today (`organize`, `unsubscribe`) both reach rank 1 or less, where `holdExtra` is 0, so add a verb whose capped worth has a nonzero term (`buy`: money, capped rank 2, one hour; or `change-account`: identity, rank 3, four hours; one hour is the model's time unit, so both fit). `window` becomes per verb: `<<base, novelty>>` plus the term, with the exemption for a tip signed by `passkey` whose caveat is `uses` 1. The grant link is always capped (`ClerkKey`'s daily cap), so the model has no bare root; say so in `formal/ASSUMPTIONS.md` instead of modelling an uncapped key.
2. **Invariants.** `HoldsNeverShorten` holds per verb, with one carve-out the model states: the owner's one-use passkey narrowing may drop the worth term (Mark's value, #4999 comment 6705669120). Add `WorthTermMonotone`: a verb that reaches more never waits less under the same key. TLC checks both.
3. **Vectors and replay.** `vectors.py` writes the per-verb windows; `broker/kernel/key/formal_test.go` builds each key and requires `Verified.Window(vb, novel)` to equal the model's window for every verb. Regenerate `broker/kernel/key/testdata/formal/key.json`.
4. **keycheck.** `assurance/keycheck` learns the worth table (each verb's direct reach, ranks capped and uncapped, `holdExtra` by rank) and the exemption, and reports a window per verb. keydiff compares it with `Verified.Window` for every verb on the closed list. Per KD-j, each new library predicate (the reach table rows, the capped column, the exemption's two conditions, the saturating add) gets a mutant in `broker/test/keydiff/reach_test.go` that the sweep must catch.

**Scope:** `broker/kernel/formal/` (`KeyVerdict.tla`, `KeyVerdict.cfg`, `vectors.py`, `README.md`, `ASSUMPTIONS.md`), `broker/kernel/key/formal_test.go`, `broker/kernel/key/testdata/formal/`, `assurance/keycheck/` (`src/`, `testdata/`, `ASSUMPTIONS.md`), `broker/test/keydiff/` (`diff_test.go`, `reach_test.go`), this brief. Not `broker/kernel/key/worth.go`: if the model finds a defect there, stop and raise it as a blocker on the PR rather than widen scope.

**Guard files:** none.

**Acceptance tests:**
- `KeyVerdict.tla` `HoldsNeverShorten` (per verb, with the owner one-use carve-out) and `WorthTermMonotone`, checked by TLC in the `formal` workflow; catches a model or table where narrowing or a wider reach shortens a hold.
- `broker/kernel/key/formal_test.go::TestFormalKeyVerdict` compares `Verified.Window(vb, novel)` for every model verb; catches a library worth term that differs from the model, including the exemption.
- `broker/test/keydiff/diff_test.go` compares keycheck's per-verb window with `Verified.Window` for every verb on the closed list; catches a table row or exemption that differs between Go and Rust.
- `broker/test/keydiff/reach_test.go::TestPredicateReach` with the new mutants; catches a sweep that never reaches a worth-term predicate.

**Tier / gate:** tier A (`broker/kernel/key`): L3 and a separate Security accept. One session; estimate 110k tokens (TLA+ and Rust together). Needs Java 11+ with tla2tools v1.7.4 and the pinned Rust toolchain, both available in the cloud container.
