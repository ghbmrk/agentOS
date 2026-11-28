# KEY-9-reach-b2b: when a key's reach grows, narrow it to its old worth and offer the wider key

Board section: Owner channel and approvals (SPEC §10). Work item #5673, split from #5060 (KEY-9-reach-b2), its item 2. Builds on b2a, which makes a key's worth depend on declaration entries in the log. KEY-9: "When its reach grows, the kernel adds a caveat that keeps it to its old worth (KEY-3) and offers the owner the wider key at the new price."

**Requirements:** KEY-9 (grows-then-narrows), KEY-3 (narrowing is automatic, by the kernel's narrow-only sub-key), KEY-6 (widening needs the owner's proof at KEY-9's price).

1. **Worth at grant.** The fold records each live key's worth when it was granted (or last widened by the owner).
2. **Narrow before the next step.** When a `decl.reach` entry raises a live key's worth above that record, the key is refused (fail closed, a new refusal reason) until the kernel logs its narrowing: a `key.narrowed` entry (log-side, the KRN-task precedent; the issue's option A, comment 6913362031) naming the grant and the verbs it keeps, only those whose reach, graph included, stays within the old worth. `Admit`, `Next` and the send check then refuse any other verb. No key, keycheck or FRM-key change. If no verb fits, the narrowed key has no verbs and admits nothing. The narrow-only sub-key that signs it as a key link, so clerks see it too, is a release row.
3. **The offer.** The same step logs the offer, in the same `key.narrowed` entry, naming the key, its old and new worth, and the proof the wider key needs (`key.Price(key.ActGrant, new)`). Showing the offer on an owner surface is outside this row; the builder files that row on the untrusted side if none exists.

**Offset (D-310):** an estimated 120 trusted lines. Uses the room b2-cut left after b2a; checks `trusted_base.py measure` at its base and cuts any shortfall itself from b2-cut's candidate table, outside `broker/kernel/*.go`, in the same PR.

**Scope:** `broker/kernel/state.go` (worth at grant, the new refusal, the offer entry), `broker/kernel/reach.go` (from b2a: the growth check), `broker/kernel/rederive.go` (the narrowing derivation), `broker/kernel/kernel.go` (refuse until narrowed), tests beside each, `broker/kernel/ASSUMPTIONS.md`, this brief; `broker/guest/codes.go` lists the new refusal code (its codes test requires it).

**Guard files:** none.

**Acceptance tests:**
- `kernel/zz_narrow_grown_test.go::TestNarrowingNeverRaisesWorth`: a property test over generated graphs and keys; the kernel's narrowing of a key is never worth more than the key before it, and is worth at most the recorded old worth.
- `kernel/zz_narrow_grown_test.go::TestAGrownKeyIsNarrowedBeforeItsNextStep`: after an entry that grows a key's reach, a step under it is refused until the narrowing is logged, then judged under the narrowed key. Catches a step that runs at the new worth.
- `kernel/zz_narrow_grown_test.go::TestTheOfferNamesTheNewProof`: the offer entry names the new worth and `Price(ActGrant, new)` (P4 at rank 3).
- Replay: Rederive derives the same narrowing and offer from the log (KRN-6); every test above ends in `rig.replays`, and `TestAForgedNarrowingIsDropped` shows one the kernel did not derive diverges.

**Tier / gate:** tier A (trusted base): L3 and a separate Security accept. Kernel package: serial slot. Needs b2a (#5672) merged. One session; estimate 100k tokens.
