# RECALL-prov-L1: one lineage's reads must not turn off notes for others, and a long-lived agent can recover

Board section: Phase 3: compounding.

**Requirement IDs:** CAP-3 (recall provenance and limits).

**Origin.** #1046's lens review: Security S-R1, Potency P-R1, UX U-L1 and LATER row RECALL-prov-L1 (reads counted at the wrong place).

**Scope:** `broker/recalltool` (provenance.go, reach.go, tools.go, tests, ASSUMPTIONS.md), BOARD.md, LATER.md, this brief.

**Acceptance.**
1. S-R1: every limit is per lineage. `Given` refuses (`ErrReadLimit`, nothing recorded) a search that would take a lineage past `Reads`; `Check` no longer looks at reads or at any broker-wide total (`ReadsAll` and `NotesAll` are gone), so no lineage's reads or notes cost another its notes or searches. `TestRecallProvL1OneLineagesReadsDoNotCostOthersTheirNotes` (failure path: 101 reads against a cap of 20 are refused, then a light lineage still reads and notes).
2. P-R1: the owner's control `Reach.Renew` takes a lineage at its read cap back to before its first held read (the existing approved take-back, so the machines really go back before any read is forgotten) and the lineage reads again; `Provenance.ReadsFull` lists who needs it. Reads are not aged out silently: forgetting a read while a machine still holds it would let a later deletion miss that machine. `TestRecallProvL1TheOwnerRenewsALineagePastItsReadCap` (failure path B1: a note made before the renewal still goes when its source is deleted).
3. U-L1: a lineage at its read cap keeps its notes, and reusing a note key works at the notes cap. A refused search says to ask the owner to start the agent's memory over; a refused note says to reuse a key or ask the owner to delete old notes. Same test.
4. The `>` versus `>=` off-by-one of the old check is gone: a lineage holds at most `Reads` items.

**Not in scope.** The owner-channel command that calls `Renew` (BOARD row RECALL-prov-owner; W7: the owner channel is not wired); aged storage for reads (lossy structures break the reset window in `Finish`).

**Usage estimate:** 60k tokens (tier A, the session's model).
