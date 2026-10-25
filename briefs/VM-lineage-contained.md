# VM-lineage-contained: a recall lineage held at upgrade is rolled back, never silently freed (LOG-4, CAP-3)

Work item: #3136 (lineage half of #3125; #3135 built the durable-retirement half). Tier A. Findings carried: #2823 comment 6366173391 (Security 6366077386, L3 6366093912).

## Goal

A box that upgrades while a recall rollback is pending has an agent lineage still holding a record the owner deleted. Before #2781 that lineage was contained by `recalltool.Reach.held`, rebuilt at each start from recall's tombstones: no fork, no merge, no pre-allowance (`vm.Config.Contained`, `grants.Config.Contained`). Since #2781 agentosd opens no recall, both hooks are nil, the owner's pending YES settles as not applied (FD-4), and the lineage gets fork, merge and pre-allowances back. This package makes agentosd read the recall directory left at rest (FD-3), find those lineages, and finish their rollback at start-up, so a deleted record never spreads further (LOG-4: erase fails closed; a planner session that read the erased item is rolled back).

## Decision this brief assumes (option A; coordinator to card)

LOG-4 also says the owner is asked when the session has done work since. The asking flow (recall's take-back question) was deleted with #2781 and is not rebuilt until the FORGET follow-up of #2823. So this brief cannot meet both halves of LOG-4 at once, and assumes:

- **A, roll back at start (this brief).** agentosd does the pending take-back itself: each held lineage goes back to before its first read of a deleted record (`vm.Manager.ForgetSince`, the call recall's rollback used), and the owner is told afterwards. The lineage loses its work since that read, unasked. Nothing is carried into the kernel era.
- **B, keep contained until FORGET returns.** The same reader feeds a durable `Contained` set; the lineage keeps its work but cannot fork, merge or get pre-allowances until the FORGET follow-up asks the owner. If Mark picks B, design 3 changes from "roll back" to "persist the set and keep it until settled", the FORGET follow-up of #2823 gains the clearing path, and test 1 changes accordingly; everything else stands.
- Retiring the lineage outright (destroying its machines and snapshots, #3136's other option) loses strictly more work than A for no further guarantee, so it is not offered.

## Design

1. **Where.** The recall directory is the old `-recall` default, `/var/lib/agentos/recall` (FD-3); #2781 removed the flag, so the path is a constant, overridable in tests. Absent directory: nothing is held, nothing is written (a fresh box).
2. **Reading at rest, without the old code.** `broker/recall` and `broker/recalltool` are frozen and deleted by #2579, so agentosd does not import them. A new `recallheld.go` parses two plain JSON-lines files read-only, taking no lock beyond opening them:
   - `recall/meta.jsonl`: records `{"op":"tomb","id":…,"at":…}` give the deleted item IDs (other ops ignored).
   - `provenance.jsonl`: records keyed `l` (lineage), `ids`, `a` (anchor), `at`, `forget` (field names in `recalltool/provenance.go` `provRecord` at c2c29e8). Replayed in order: a record without `forget` adds `ids` and `a` to the lineage's reads at `at`; `forget` with `ids` drops them, `forget` without `ids` drops the lineage's reads.
   - A lineage is **held** when a read it still has names a tombstoned ID. Its **since** is the earliest `at` among those reads; a zero `at` gives the zero time (back to the image). Over-approximate, never under: anchors are not expanded beyond the IDs their records list, and resets are not credited. `backs.jsonl` and the rest of provenance (notes, take-back marks) are ignored.
   - A torn final line (no trailing newline) is ignored, as recall's stores did. Any other unreadable line or file makes the result **unknown**.
3. **Settling at start-up (option A).** In the agent-machine branch of `main.go`, after `vm.Open` and before the guest plane opens (`openGuestPlane`) or any machine is served, agentosd calls `ForgetSince(lineage, since)` for each held lineage not already settled. Each success is recorded durably (`<stateDir>/recall-settled.json`, written with `durable.WriteFile`) before the next, so a restart never rolls back a settled lineage again (`ForgetSince` repeated rolls back later work too). A failed one stays held and is retried at the next start.
4. **Containment for whatever is not settled.** One `heldSet` is built before the daemon config is finished. Its `Contained(lineage)` is true for a held, unsettled lineage, and for every lineage while the result is unknown. It is set on every `vm.Config` agentosd builds (`main.go` and `setupsignin.go`) and on `cfg.Grants.Contained`, so such a lineage gets `vm.ErrContained` on fork and merge and no pre-allowance. Settling removes a lineage from the set.
5. **The owner is told.** Each settled lineage gets one owner notice through agentosd's existing notice path, naming the agent (as STATUS names lineages) and the time it went back to, sent once (the settled record says it was). While anything is contained, `cfg.Notes` adds a STATUS line naming the held agents, or, when unknown, saying the old memory directory could not be read and agents cannot fork or merge.
6. **Records.** `broker/cmd/agentosd/ASSUMPTIONS.md`: amend FD-4 (`Grants.Contained` is now set) and add a row for this package (what is read, the over-approximation, the start-up order, the unknown case).

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
- Replay: `TestLOG4ForgetRecordAndAnchorReplay`: a `forget` record dropping X leaves L not held; X read again after it makes L held with the later `at`; a tombstone on an ID listed in an anchor record makes its lineage held. Catches a reader that drops or invents holds.
- Fresh box: `TestLOG4NoRecallDirectoryHoldsNothing`: no directory, nothing contained, no file written.

## Estimate

About 70k tokens, one session: roughly 200 lines of code and 350 of tests. Checkpoint at 100k.
