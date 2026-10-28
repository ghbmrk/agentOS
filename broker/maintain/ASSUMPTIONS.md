# maintain: assumptions

Built for P3-5 (BOARD.md) against SPEC v0.12 §11A, LOOP-11, on the loop scheduler (P3-2, `broker/loops`) and the update verifier (P4-3, `broker/update`). Covers `broker/maintain`. Loop 3 itself was deleted unwired in MIG-4-untrusted-change-c1 (#2785 c1); its rows stay struck for their IDs, and the update path's rebuild on the kernel is #2579's. Each row is a reading of the spec, or a gap left for a later package, that a reviewer may want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| M1 | ~~**Scope.**~~ Deleted with Loop 3 (#2785 c1). | LOOP-11, UPD-5, CHG-3 | — |
| M2 | ~~**Never "current" when unsure (LOOP-11).**~~ Deleted with Loop 3 (#2785 c1). | LOOP-11, UPD-8 | — |
| M3 | ~~**Cadence.**~~ Deleted with Loop 3 (#2785 c1). | UPD-5, LOOP-1 | — |
| M4 | ~~**Security first, D6 as ruled (arbitrator, 2026-10-05).**~~ Deleted with Loop 3 (#2785 c1). | UPD-8, UPD-5, LOOP-3, CH-3 | — |
| M5 | ~~**A security fix behind a newer release.**~~ Deleted with Loop 3 (#2785 c1). | UPD-5, UPD-8 | — |
| M6 | ~~**Soak for ordinary stable releases (UPD-5).**~~ Deleted with Loop 3 (#2785 c1). | UPD-5, UPD-7 | — |
| M7 | ~~**Channel and pinned (UPD-4).**~~ Deleted with Loop 3 (#2785 c1). | UPD-4 | — |
| M8 | ~~**Proposed once.**~~ Deleted with Loop 3 (#2785 c1). | CHG-3, OP-2, UPD-5 | — |
| M9 | ~~**Mirrors.**~~ Deleted with Loop 3 (#2785 c1). | UPD-2, UPD-8, DEP-4 | — |
| M10 | ~~**Attestations**~~ Deleted with Loop 3 (#2785 c1). | OSS-8, UPD-8 | — |
| M11 | ~~**No model calls, no inference.**~~ Deleted with Loop 3 (#2785 c1). | LOOP-1, LOOP-2, ARC-2 | — |
| M12 | ~~**Not wired into `agentosd`.**~~ Deleted with Loop 3 (#2785 c1). | TIM-1 | — |
| M13 | ~~**Open decisions not assumed.**~~ Deleted with Loop 3 (#2785 c1). | §16 q6 | — |
| M14 | ~~**On a fork (OSS-10, OSS-9).**~~ Deleted with Loop 3 (#2785 c1). The page and alert wording (`FollowPrompt`, `FollowCheckHeading`, `FollowNameLabel`, `FollowAlert`, `EvidenceLine`) stays here; `broker/follow` sends `FollowAlert`. | OSS-10, OSS-9, UPD-8 | — |
| M15 | ~~**Dropped adoptions are offered again (SR3-4f-2-r1).**~~ Deleted with Loop 3 (#2785 c1). | UPD-1, UPD-5, UPD-8, CH-12 | — |
