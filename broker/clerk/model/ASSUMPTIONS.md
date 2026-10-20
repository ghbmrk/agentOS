# Model clerk: assumptions

Built for MIG-4-spend (#2572, D-139 step 4). Covers `broker/clerk/model` and the metering in `broker/kernel` (`model.used`, `Kernel.AdmitSpend`, `Kernel.Meter`, `key.Verified.Spend`). Each row is a reading a reviewer may want to change.

| ID | Assumption | Spec basis | If it changes |
|---|---|---|---|
| MIG-4-spend-a | **A model call is metered usage, not a plan step.** The verb list is closed and a model call is not an effect, so it is charged to the key the plan cites by a `model.used` entry. The plan must be active; the caller names only the plan, and the key and the task (the plan ID) come from it or its latest extension, never from the caller. | VRB-2, HLD-2, LOG-7 | A plan-step model call would add a verb, which the spec forbids. |
| MIG-4-spend-b | **One check, one mechanism.** `Verified.Spend` (live, right clerk, spend caps hold for `amount` more) runs in `AdmitSpend` before a call. `Meter` records what happened and does not re-run it. Rate and use caps count steps, not metered usage, so `caps` skips them for `Spend` (`spendOnly`); no flag rides on `Use`. | KEY-2, LOG-7 | Counting calls would be a `rate` cap read over `Meter` uses. |
| MIG-4-spend-c | **Usage that happened is always recorded**, even past a cap, so the next admission sees it. Only a key that does not verify or whose root was never issued records nothing. | LOG-7 | Refusing the record would hide spend from the caps. |
| MIG-4-spend-d | **Admission uses the worst case** (the prompt's tokens plus `maxOut`); the record uses the provider's figure, else the clerk's own count at four bytes a token. Cost rounds up. | LOG-7 | A real tokenizer replaces `tokens`. |
| MIG-4-spend-e | **Calls are admit, call, meter, one at a time.** The clerk holds a mutex; concurrent admission across clerks is a follow-up issue. | KRN-1 | Parallel calls need a reservation entry before the call. |
| MIG-4-spend-f | **A model key is issued for clerk `model` with the verb `read`.** Roots need a verb; `Spend` ignores verbs. | KEY-2 | A verbless root would be a key-format change. |
| MIG-4-spend-g | **Spend never goes unmetered and is never negative.** `Meter` and `Spend` refuse a negative amount; `Price.cost` uses checked arithmetic and refuses negative tokens or prices and overflow, so no call is admitted or metered below its cost. A provider error, an unusable figure or a failed cost meters the admitted worst case (source `admitted`). If `Meter` fails, the reply is withheld and the clerk makes no further call until the log records what it owes. | LOG-7, CLK-7 | A provider that reports failed-call usage could meter less than the worst case. |
| MIG-4-spend-h | **Not here:** paid API calls and purchases through other clerks, and spare-class draw (HLD-4). They build on `Spend` and `Meter`. | LOG-7, HLD-4 | Each is its own row. |

## MIG-4-spend-b: holds, extensions, pools

Adds `spend.held`, `spend.extended`, `pool.read`, `pool.reset`, `pool.reserve.raised` and `pool.reserve.lowered` to the log, and `Hold`, `Extend`, `ReadPool`, `Reserve`, `AdmitPool` to the kernel.

| ID | Assumption | Spec basis | If it changes |
|---|---|---|---|
| MIG-4-spend-b1 | **A refused spend cap holds the plan**, not only a fully used one. A call whose worst case does not fit means the plan needs more budget; the owner extends it, and a smaller retry is not a way around the hold. | LOG-7 | Holding only at zero left would need a minimum-call rule per route. |
| MIG-4-spend-b2 | **An extension is a derivation of the owner's envelope, not a new caveat kind, and a held key cannot release itself.** `spend.held` records the cited key's root; `Extend` refuses any extension under that root, one with no per-task cap in its chain, or without room left. The envelope's caps sit in a shared chain prefix, so every extension is charged to them and none passes them. | KEY-4, LOG-7 | A per-extension ceiling would be a new cap kind. |
| MIG-4-spend-b3 | **Equal caveats derive the same key**, so two extensions with the same cap are one key and share its cap. Distinct caps give distinct keys. | KEY-4 | Per-grant serials would be a key-format change. |
| MIG-4-spend-b4 | **Owner authentication is outside the kernel**, as for every owner action: the channel authenticates the passkey or text, the kernel records. `Extend` of a held task is itself the grant. | KEY-4, KEY-6 | The kernel would verify an owner signature over the extension. |
| MIG-4-spend-b5 | **A pool is per mille, and the reserve defaults to 0.** `pool.read` records the provider's utilization and reset time. A pool admits while `used + reserve < 1000`. A reading can only narrow: it never reopens a closed pool. Reopening past the reset time (the cooldown; none recorded means never) is the logged widening `pool.reset`. | RES-5, CLK-7 | Percent, or a forecast-based draw, changes `PoolOpen` only. |
| MIG-4-spend-b6 | **Raising a reserve narrows (a text), lowering widens (the passkey).** Two entry types let `Widening` stay typed by entry type, so a restart honours a lowering only when an anchor covers it. | KEY-4, KEY-6, KRN-7 | One entry type needs `Widening` to read the body. |
| MIG-4-spend-b7 | **A held plan is refused by `AdmitSpend` itself** (`held`), so a clerk never makes a call for it and never re-holds. | LOG-7 | A clerk-side check would duplicate the kernel's. |
| MIG-4-spend-b8 | **`Widening` lists `spend.extended`, `pool.reset` and the reserve lowering**: each loosens a limit, so a restart keeps one only when an anchor covers it (KRN-7). | KEY-4, KEY-6, KRN-7 | A narrowing-only extension would not need the anchor. |
| MIG-4-spend-b9 | **One pool per route.** A provider meters one subscription per credential, so a route draws on one pool; a route spanning two is two routes. This is the answer to RES-5's pool list. | RES-5 | A `Pool` list on `Price` and an admit over all of them. |
