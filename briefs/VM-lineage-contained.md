# VM-lineage-contained: a recall lineage held at upgrade is rolled back, never silently freed (LOG-4, CAP-3)

Work item: #3136 (lineage half of #3125; #3135 built the durable-retirement half). Tier A. Findings carried: #2823 comment 6366173391 (Security 6366077386, L3 6366093912).

## Goal

A box that upgrades while a recall rollback is pending has an agent lineage still holding a record the owner deleted. Before #2781 that lineage was contained by `recalltool.Reach.held`, rebuilt at each start from recall's tombstones: no fork, no merge, no pre-allowance (`vm.Config.Contained`, `grants.Config.Contained`). Since #2781 agentosd opens no recall, both hooks are nil, the owner's pending YES settles as not applied (FD-4), and the lineage gets fork, merge and pre-allowances back. This package makes agentosd read the recall directory left at rest (FD-3), find those lineages, and finish their rollback at start-up, so a deleted record never spreads further (LOG-4: erase fails closed; a planner session that read the erased item is rolled back).

## Decision this brief assumes (option A; coordinator to card)

LOG-4 also says the owner is asked when the session has done work since. The asking flow (recall's take-back question) was deleted with #2781 and is not rebuilt until the FORGET follow-up of #2823. So this brief cannot meet both halves of LOG-4 at once, and assumes:

- **A, roll back at start (this brief).** agentosd does the pending take-back itself: each held lineage goes back to before its first read of a deleted record (`vm.Manager.ForgetSince`, the call recall's rollback used), and the owner is told afterwards. The lineage loses its work since that read, unasked. Nothing is carried into the kernel era.
- **B, keep contained until FORGET returns.** The same reader feeds a durable `Contained` set; the lineage keeps its work but cannot fork, merge or get pre-allowances until the FORGET follow-up asks the owner. If Mark picks B, design 4 changes from "roll back" to "persist the set and keep it until settled", the FORGET follow-up of #2823 gains the clearing path, and test 1 changes accordingly; everything else stands.
- Retiring the lineage outright (destroying its machines and snapshots, #3136's other option) loses strictly more work than A for no further guarantee, so it is not offered.

## Design

1. **Where.** The recall directory is the old `-recall` default, `/var/lib/agentos/recall` (FD-3); #2781 removed the flag, so the path is a constant, overridable in tests. Absent directory: nothing is held, nothing is written (a fresh box).
2. **Reading at rest, without the old code.** `broker/recall` and `broker/recalltool` are frozen and deleted by #2579, so agentosd does not import them. A new `recallheld.go` parses three plain JSON-lines files read-only, taking no lock beyond opening them (field names: `recalltool/provenance.go` `provRecord` and `apply` at c2c29e8, lines 69-93 and 155-242):
   - `recall/meta.jsonl`: records `{"op":"tomb","id":…,"at":…}` give the deleted item IDs (other ops ignored).
   - `provenance.jsonl`, replayed in order, mirroring `apply`'s order of cases: a record with `n` (a note) is skipped; a record with `a` or `seq` > 0 (an anchor) adds nothing and drops nothing; a record with `tb` is a take-back mark, and one with `tb`, `forget` and `reset` is also a **back** {since `at`, began `reset`}; a record with `reset` and no `forget` is a **recorded reset** {since `at`, began `reset`} and removes any back with the same since; `reset` with `forget` finishes it, dropping its `ids` (none: drops nothing) and the reset. Only a record with none of `n`, `a`, `seq`, `tb`, `reset` is a read or a drop: without `forget` it adds `ids` at `at`, where an ID already read keeps its earlier time unless that time lies inside a recorded reset or back known at that point of the replay (since ≤ t < began; `undone`, `provenance.go:233-237, 277-285`), in which case it takes the new time; with `forget`, `ids` are dropped, and no `ids` drops all the lineage's reads.
   - `backs.jsonl`: replayed after `provenance.jsonl` with the same rules; in practice it holds backs. A back can sit in either file (`compact` writes backs into `provenance.jsonl`, `provenance.go:499-505`).
3. **What is held, and what the old system already settled.** A lineage's **deleted reads** are its reads of tombstoned IDs, minus any read whose time falls inside a recorded reset or back of that lineage (since ≤ `at` < began; `until` plays no part, as in `Finish` and `forgotten`, `provenance.go:776-786`, `reach.go:942-951`): those machines already went back, and the old code finished such a reset without repeating it (`Reach.settle` → `Prov.Resets` → `finishTold`, `reach.go:615-620`). A lineage with deleted reads is **held**; its **since** is the earliest of their times (zero: back to the image). A held lineage is **kept** when the owner already said NO: the journal agentosd still opens (`d.Engine().List()`) holds a `journal.ActionRecallRollback` intent, state Denied, `Permission.Reason == "not approved: owner"`, whose `Params["lineage"]` is that lineage and whose `Params["items"]` (comma-joined) covers every one of its deleted reads (`Reach.current`, `reach.go:705-742`). Match on lineage and items, not on the intent ID, since this reader's since may differ from the old one. A NO that does not cover a newer deletion does not keep it, as in the old code.
   - A torn final line (no trailing newline) is ignored, as recall's stores did. Any other unreadable line or file makes the result **unknown**.
   - **Which way each rule errs.** Rollback (A) loses work for good, so its errors must fall on not rolling back; containment (B, and A's failure path) only delays, so its errors must fall on containing.

     | Rule | Errs toward | Under A | Under B |
     |---|---|---|---|
     | Anchor records add no reads | neither | matches the old `heldBy`, which reads only `Items` (plain records, `provenance.go:524`) | same |
     | Recorded reset or back credits only reads it undid (since ≤ t < began); a re-read after it is held from the new time | fewer held, only for undone reads | required: no repeated rollback | required: an owner-freed lineage is not re-held |
     | Owner's NO read from the journal | fewer held | required: the owner's answer stands (LOG-4) | required |
     | Journal unreadable or not yet open | — | no rollback until it is read; contain meanwhile | contain |
     | Files unknown | more held | contain every lineage, roll back nothing | contain every lineage |
4. **Settling at start-up (option A).** In the agent-machine branch of `main.go`, after `vm.Open` (the journal is open by then, `daemon.Run`) and before the guest plane opens (`openGuestPlane`) or any machine is served, agentosd calls `ForgetSince(lineage, since)` for each held lineage that is neither kept nor already settled. Each success is recorded durably (`<stateDir>/recall-settled.json`, written with `durable.WriteFile`) before the next, so a restart never rolls back a settled lineage again (`ForgetSince` repeated rolls back later work too). A failed one stays held and is retried at the next start. Kept lineages are never rolled back and are not contained, as in the old code (`errKept` clears `held`, `reach.go:646-649`).
5. **Containment for whatever is not settled.** One `heldSet` is built from the files before the daemon config is finished, counting kept lineages as held until the journal is read (over-containing for a moment is the safe side). Its `Contained(lineage)` is true for a held lineage that is neither kept nor settled, and for every lineage while the result is unknown. It is set on every `vm.Config` agentosd builds (`main.go` and `setupsignin.go`) and on `cfg.Grants.Contained`, so such a lineage gets `vm.ErrContained` on fork and merge and no pre-allowance. Settling removes a lineage from the set.
6. **The owner is told.** Each settled lineage gets one owner notice through agentosd's existing notice path, naming the agent (as STATUS names lineages) and the time it went back to, sent once (the settled record says it was). While anything is contained, `cfg.Notes` adds a STATUS line naming the held agents, or, when unknown, saying the old memory directory could not be read and agents cannot fork or merge. A kept lineage is named in STATUS as still holding a record the owner deleted, as the old `Reach.Status` did.
7. **Records.** `broker/cmd/agentosd/ASSUMPTIONS.md`: amend FD-4 (`Grants.Contained` is now set) and add a row for this package (the files and journal intents read, the table of which way each rule errs, the start-up order, the unknown case).

## Not in this package

- Deleting the recall directory at rest, and the private content still in it: #2579. Note for #2579: delete it only once `recall-settled.json` covers every held lineage, or carry this reader's result forward, or a lineage contained here is freed by the deletion.
- Planner rollback after an erased read in the kernel, and the owner's question when work was done since: the FORGET follow-up of #2823.
- Any change to `broker/vm`: `ForgetSince`, `Config.Contained` and `ErrContained` exist. If a change there turns out necessary, stop and ask on #3136 (D-111).

## Scope

- New `broker/cmd/agentosd/recallheld.go` and `recallheld_test.go`.
- `broker/cmd/agentosd/main.go` (build the set, wire both `Contained` hooks and the note, settle after `vm.Open`), `broker/cmd/agentosd/setupsignin.go` (the `Contained` hook only), `broker/cmd/agentosd/ASSUMPTIONS.md`.
- `briefs/VM-lineage-contained.md`.

Waits for #3141 to merge (D-111: it holds `cmd/agentosd`), and runs in the serial agentosd chain.

**Guard files:** none (no new broker package).

## Acceptance tests

**Acceptance tests:** (all in `broker/cmd/agentosd/recallheld_test.go`, on a real `vm.Manager` with a fake runtime as `leftover_test.go` does)
- LOG-4 / CAP-3 rollback: `TestLOG4HeldLineageRolledBackAtStart`: a recall directory with a tombstone for X and lineage L reading X at t1; L has snapshots before and after t1, lineage M has its own. After start-up, L's machines are at the snapshot before t1, no snapshot of L at or after t1 is listed or loads after a reopen, the owner is told once, and M is untouched and forks. Catches an upgrade that frees L, or a rollback that reaches M.
- Not twice: `TestLOG4SettledLineageNotRolledBackAgain`: after the first start, L does new work and snapshots; a second start leaves it and sends no notice. Catches a repeated `ForgetSince` losing work.
- Fail closed: `TestLOG4UnsettledLineageStaysContained`: `ForgetSince` fails for L; L's fork and merge return `vm.ErrContained`, `Grants.Contained(L)` is true, STATUS names L, M forks; the next start settles L and frees it. Catches a failure that frees L.
- Unknown: `TestLOG4UnreadableRecallFilesContainEveryLineage`: a corrupt middle line in `provenance.jsonl` (and, separately, in `meta.jsonl`) contains every lineage and adds the STATUS line; a torn final line alone does not. Catches a parse error read as "nothing held".
- Owner's NO: `TestLOG4OwnerKeptLineageNotRolledBack`: the journal holds the owner's Denied rollback intent for L covering X; L is not rolled back, not contained, and STATUS names it; a later tombstone for Y that L also read (not covered by the NO) makes L held again. Catches a start-up overriding the owner's answer.
- Recorded reset: `TestLOG4RecordedResetNotRepeated`: provenance holds a recorded reset of L from t0, begun (`reset`) at t2 and done (`until`) at t2' > t2, covering a read of X at t0 ≤ t1 < t2; L does work after t2'; start-up does not call `ForgetSince` for L and its work stays; a read of tombstoned Z at t3 > t2' makes L held from t3; X read again at t3 makes L held from t3; a read of tombstoned Y between `reset` and `until` makes L held; the same reset written as a back in `provenance.jsonl` is credited the same way. Catches a repeated rollback, and a credit wider than the old code's.
- Replay: `TestLOG4ForgetRecordAndAnchorReplay`: a plain `forget` record dropping X leaves L not held; X read again after it makes L held with the later `at`; a `reset`+`forget` record with no `ids`, a `tb` record and an anchor record with `forget` drop nothing. Catches a reader that frees a lineage on a record `apply` does not treat as a drop.
- Fresh box: `TestLOG4NoRecallDirectoryHoldsNothing`: no directory, nothing contained, no file written.

## Estimate

About 70k tokens, one session: roughly 200 lines of code and 350 of tests. Checkpoint at 100k.
