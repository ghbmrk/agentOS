# RECALL-prov-L1: one lineage's reads must not turn off notes for others, and a long-lived agent can recover

Board section: Phase 3: compounding.

**Requirement IDs:** CAP-3 (recall provenance and limits).

**Origin.** #1046's lens review: Security S-R1, Potency P-R1, UX U-L1 and LATER row RECALL-prov-L1 (reads counted at the wrong place).

**Scope:** `broker/recalltool` (provenance.go, reach.go, tools.go, tests, ASSUMPTIONS.md), BOARD.md, LATER.md, this brief.

**Acceptance.**
1. S-R1: `Check` refuses a lineage for the broker-wide read total (`ReadsAll`) only when its own reads exceed `Reads/10`; a lineage under that floor keeps its notes however much others read. `TestRecallProvL1OneLineagesReadsDoNotCostOthersTheirNotes` (failure path: ten lineages at their caps, a light lineage still notes).
2. P-R1: the owner's control `Reach.Renew` takes a lineage past its read cap back to before its first held read (the existing approved take-back, so the machines really go back before any read is forgotten) and the lineage notes again; `Provenance.ReadsFull` lists who needs it. Reads are not aged out silently: forgetting a read while a machine still holds it would let a later deletion miss that machine. `TestRecallProvL1TheOwnerRenewsALineagePastItsReadCap` (failure path B1: a note made before the renewal still goes when its source is deleted).
3. U-L1: the limit text names steps that work: reuse an existing note key, or ask the owner to start the agent's memory over (same test).

**Not in scope.** An owner-channel command that calls `Renew` (W7: the owner channel is not wired); aged storage for reads (lossy structures break the reset window in `Finish`).

**Usage estimate:** 60k tokens (tier A, the session's model).
