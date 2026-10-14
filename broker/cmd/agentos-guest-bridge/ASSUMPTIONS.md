# Guest bridge (agentos-guest-bridge): assumptions

Rows are added per package that touches this command. A reading a later spec version could change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| TREE-fold-wipe-1 | The guest plane folds any tool result over `fold.Max` (8 KiB) into a `fold.StandIn` and keeps the full text for the same machine's `result_read`. A `managed_tree` answer that is not `unchanged` always carries a non-empty `version` (agentosd's tree hash). So a non-unchanged answer with no version is either a stand-in, whose full text the bridge reads back with `result_read`, or not a tree, which the bridge refuses without touching its tree directory. | ARC-2, CAP-5 | If folding ever skips broker tools, the read-back is dead code but harmless; if an empty tree could carry an empty version, the refusal would keep a stale tree instead of emptying it. |
| TREE-fold-wipe-2 | Only a changed tree is folded: once the bridge holds a version, each 30 s poll gets a small `unchanged` answer, so polling does not fill the machine's fold store (32 records) and evict the agent's own folded results. | ARC-2 | If the broker stops answering `unchanged`, every poll would store a fold again. |
