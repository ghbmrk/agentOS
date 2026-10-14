# Guest bridge (agentos-guest-bridge): assumptions

Rows are added per package that touches this command. A reading a later spec version could change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| TREE-fold-wipe-1 | A `managed_tree` answer that is not `unchanged` always carries a non-empty `version` (agentosd's tree hash), and the guest plane never folds it (`guest.TreeTool`, TREE-fold-evict). So a non-unchanged answer with no version, a fold stand-in included, is not a tree, and the bridge refuses it without touching its tree directory. The bridge never calls `result_read`. | ARC-2, CAP-5 | If the plane folded `managed_tree` again, every tree over 8 KiB would be refused and the agent would keep its older skills; if an empty tree could carry an empty version, the refusal would keep a stale tree instead of emptying it. |
| TREE-fold-wipe-2 | Tree polling never touches the machine's fold store (32 records, 4 MiB, shared with the agent's own held results), whether a sync succeeds or keeps failing: the plane hands `managed_tree` back whole (TREE-fold-evict, #1461). Corrected: before #1461 this held only once a sync had succeeded, and a failing sync (unwritable tree directory, ENOSPC, a bad path) folded the tree on every 30 s poll and evicted the agent's results after about 32 polls. A failing sync still refetches the whole tree every poll, up to `maxTreeAnswer` (8 MiB) of socket traffic per 30 s. | ARC-2, CAP-5, A11 | If the plane folds `managed_tree` again, a failing sync evicts the agent's held results again. |
