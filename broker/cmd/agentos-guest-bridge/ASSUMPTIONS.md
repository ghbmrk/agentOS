# Guest bridge (agentos-guest-bridge): assumptions

Rows are added per package that touches this command. A reading a later spec version could change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| GUEST-bridge-tree-dead | The bridge fetches no managed tree: `agentosd` serves no `managed_tree` tool since MIG-4-untrusted-learn, so the tree directory (`-tree`) holds only what the machine was seeded with, and the bridge's idle work is the owner poll alone (no broker tool call). The poll, its mirror and the `-tree-sync` flag are gone (#4491). | ARC-6, ARC-7, CAP-5 | If a later row brings the managed tree back to a live agent, it adds its own fetch and the guest-plane bounds it needs; nothing here is kept for it. |
| GUEST-bridge-tree-dead-fu | The bridge starts exactly three goroutines: the request server and the signal relay in `main`, which act only when the guest or the system asks, and the idle work, which only `background` starts. The idle work stops when its context ends, between owner messages: a message already handed out is answered and its reply stored first (DEL-1d). `TestEveryGoroutineIsKnown` fails on any other `go` statement or `time.AfterFunc`, `time.NewTicker` or `time.Tick` call anywhere in the command's files, package initializers included, so idle work cannot bypass the idle test (acceptance 3 of #4491). A goroutine started inside an imported package is outside this check. | PLN-5 | A new goroutine is added to that test's list only once the idle test covers it, or it is started through `background`. |
