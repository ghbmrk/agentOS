# Guest bridge (agentos-guest-bridge): assumptions

Rows are added per package that touches this command. A reading a later spec version could change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| GUEST-bridge-tree-dead | The bridge fetches no managed tree: `agentosd` serves no `managed_tree` tool since MIG-4-untrusted-learn, so the tree directory (`-tree`) holds only what the machine was seeded with, and the bridge's idle work is the owner poll alone (no broker tool call). The poll, its mirror and the `-tree-sync` flag are gone (#4491). | ARC-6, ARC-7, CAP-5 | If a later row brings the managed tree back to a live agent, it adds its own fetch and the guest-plane bounds it needs; nothing here is kept for it. |
