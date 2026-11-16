# KEY-9-reach-writer: write decl.reach entries from the owner graph's declarations

Board section: Migration to the capability kernel (D-139). Work item #5814 (release item of KEY-9-reach-b2a, #5813, merged).

**Problem:** the kernel folds `decl.reach` (`broker/kernel/reach.go`) and prices grants over it, but nothing writes the entry, so every key prices on its direct reach.

**Requirements:** KEY-9, CLK-10, CLK-14.
1. `broker/owner/graph` maps each node to a `kernel.ReachNode` (ID, rooted clerk, classes as `key.Asset`; a device declares `AssetSafety` only when marked safety or access) and each reset, copy or act edge to a `kernel.ReachEdge`, and sends only additions.
2. The kernel gains an entry point that logs the entry as an unsigned, non-widening append, reachable from the untrusted side through the kernel socket (`broker/kernel/proc/kernelsock.go`'s op table).
3. The production call from agentosd that runs the writer on graph change is the integration owner of this row. It is a second, serial step in `broker/cmd/agentosd` (D-111) once that directory is free.

**Scope:** `broker/owner/graph/` (new `reach.go` and test), `broker/kernel/reach.go` and its test, `broker/kernel/proc/kernelsock.go` and its test, ASSUMPTIONS of those packages, this brief; then the agentosd call site.

**Acceptance tests:** `broker/owner/graph`: `TestReachWriterMailboxResetMakesMailGrantNeedCosign` (a graph with a mailbox reset edge to a bank, written through the writer, makes a new `read` mail grant need the co-sign); catches a writer that drops the edge (the grant prices rank 1). `broker/kernel`: `TestDeclReachAppendCannotWiden` (an entry removing a node or edge is refused whole); catches a widening append.

**Guard files:** none, unless the writer imports the kernel package from `broker/owner/graph`, in which case `broker/daemon/arc2_test.go`'s allowlist is pre-approved.

**Dependencies:** starts after open PR #5757 (KRN-clock-second-source) merges, since both touch `broker/kernel/proc/kernelsock.go`.

**Tier / gate:** tier A (kernel, owner): L3 on the strongest model, lens screen, separate Security accept.

**Usage estimate:** one session for steps 1 and 2, about 120k; the agentosd step under 60k.
