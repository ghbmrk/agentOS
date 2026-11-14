# KEY-9-reach-b2a: graph reach over declarations, read by the kernel from its own log

Board section: Owner channel and approvals (SPEC §10). Work item #5672, split from #5060 (KEY-9-reach-b2), its item 1. Today a key's reach is its own verbs' direct classes (`key.Worth`, `broker/kernel/key/worth.go`). KEY-9 says reach is everything the key can touch "directly or through the graph (CLK-10), counting any edge the graph cannot rule out". The graph lives outside the trusted core (`broker/owner/graph`), and the kernel log holds no declaration entries, so the kernel cannot see an edge.

**Requirements:** KEY-9 (graph reach), CLK-10, CLK-14 (graph facts are declaration fields), LOG-5 (typed, versioned entries), KRN-2 (no import of `broker/owner/graph`; its `Reach` is the reference, matched as data).

1. **The entry.** A new typed entry (working name `decl.reach`, v1) carries the narrowest input the kernel can fold: per declared node, its ID, the clerk whose keys root on it (if any), its asset classes as `key.Asset` values, and its control edges (`reset`, `copy`, `act`: From IDs, To ID). It is additive only: a later entry may add a class or an edge, never remove one, so the log's reach only grows and an untrusted writer can only raise a price. The fold refuses a malformed entry (unknown class or edge kind, empty ID). Removing an edge is out of this row: it lowers a price, so it needs an owner proof and a spec decision first; the builder records that as an ASSUMPTIONS row, not a work item.
2. **The closure.** `State` keeps the folded nodes and edges. A key's graph reach is the classes of every node reached from its clerk's node over control edges, an edge firing when any From is in the set (the `graph.Reach` rule). An edge naming a node with no declared classes counts as reaching every class (fail closed). A device node reaches safety only when its declaration marks it safety or access (Mark's value, #4999 comment 6705669120). A key whose clerk has no node keeps its direct reach, so existing keys price as today until a declaration lands.
3. **Where it prices.** Grants (`State.priced`, `kernel/cosign.go`) price at worth over direct plus graph reach. A held step's term (`Verified.Window`) keeps its own verb's direct reach unless the verb takes control of the node (see the decision below). `key.Worth` stays the key-only function keycheck mirrors (b2c); the graph term is a second argument the kernel passes, so keydiff's surface does not change.

**Decision to confirm (asked on the issue; build the recommendation unless the answer differs):** which verbs enter the graph closure. Recommendation: for a grant, any verb whose direct reach is data or more enters it (a thief with `read` can read reset codes, which is an edge the graph cannot rule out); for a held step, only verbs that take the node over enter it (`change-account`, `reveal-or-create-secret`, `delete-remote`, the identity rows), since Mark's value prices each step by what that step reaches. Consequence to state in the PR: once a mail declaration says the mailbox resets a bank, every new mail key with `read` is a rank-3 grant (P4, the hardware key).

**Offset (D-310):** this row adds an estimated 180 trusted lines. It starts after b2-cut (#5671) merges and checks `trusted_base.py measure` against the ceiling at its base; if b2-cut's room has been used by then, it cuts the shortfall itself from b2-cut's candidate table, outside `broker/kernel/*.go`, in the same PR.

**Scope:** `broker/kernel/state.go` (entry type, fold), a new `broker/kernel/reach.go` (closure), `broker/kernel/cosign.go` (`priced`), `broker/kernel/kernel.go` (the hold, only for the control verbs), `broker/kernel/key/worth.go` (`WorthOf` over a combined reach; no table change), tests beside each, `broker/kernel/ASSUMPTIONS.md`, `broker/kernel/testdata` (a fixture graph), this brief. The writer of the entry (agentosd or the owner graph) is a separate untrusted-side row the builder files if none exists.

**Guard files:** none (no new package).

**Acceptance tests:**
- `kernel/reach_test.go::TestAddingAnEdgeNeverLowersWorth`: a property test over generated graphs (nodes, classes, AND and OR edges); adding an edge or a class never lowers any key's worth. Catches a closure that drops a node on growth.
- `kernel/reach_test.go::TestAnUnknownEdgePricesAsReached`: an edge to a node with no classes makes the key worth `MaxRank`. Catches a fail-open default.
- `kernel/reach_test.go::TestReachMatchesTheGraph`: on generated graphs, the kernel's reached node set equals `graph.Reach`'s for the same data (the test may import `broker/owner/graph`; the kernel may not). Catches a rule drift between the two.
- `kernel/reach_test.go::TestADeviceIsSafetyOnlyWhenMarked`: a device node without the safety or access mark reaches none.
- `kernel/worth_test.go::TestAGrantPricesItsGraphReach`: a `read` mail key is a rank-3 grant once a declaration adds a reset edge to an identity node, and a rank-1 grant before.
- `kernel/state_test.go` (or beside the fold): a malformed or removing `decl.reach` entry is refused, and replay (Rederive) gives the same reach.

**Tier / gate:** tier A (trusted base): L3 and a separate Security accept. Kernel package: runs in the kernel's serial slot. Needs b2-cut (#5671) merged. One session; estimate 120k tokens.
