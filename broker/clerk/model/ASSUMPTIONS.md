# Model clerk: assumptions

Built for MIG-4-spend (#2572, D-139 step 4). Covers `broker/clerk/model` and the metering in `broker/kernel` (`model.used`, `Kernel.AdmitSpend`, `Kernel.Meter`, `key.Verified.Spend`). Each row is a reading a reviewer may want to change.

| ID | Assumption | Spec basis | If it changes |
|---|---|---|---|
| MIG-4-spend-a | **A model call is metered usage, not a plan step.** The verb list is closed and a model call is not an effect, so it is charged straight to a key by a `model.used` entry, never through a plan. A blind planner calls the model before any plan exists. | VRB-2, HLD-2, LOG-7 | A plan-step model call would add a verb, which the spec forbids. |
| MIG-4-spend-b | **One check, two callers.** `Verified.Spend` (live, right clerk, spend caps hold for `amount` more) runs in the clerk before a call and in the kernel that records it. Rate and use caps are skipped: a call is not a use (`Use.Meter`). | KEY-2, LOG-7 | Counting calls would be a `rate` cap read over `Meter` uses. |
| MIG-4-spend-c | **Usage that happened is always recorded**, even past a cap, so the next admission sees it. Only a key that does not verify or whose root was never issued records nothing. | LOG-7 | Refusing the record would hide spend from the caps. |
| MIG-4-spend-d | **Admission uses the worst case** (the prompt's tokens plus `maxOut`); the record uses the provider's figure, else the clerk's own count at four bytes a token. Cost rounds up. | LOG-7 | A real tokenizer replaces `tokens`. |
| MIG-4-spend-e | **Calls are admit, call, meter, one at a time.** The kernel has no locking, so concurrent model calls would race the admission. The daemon serializes them. | KRN-1 | Parallel calls need a reservation entry before the call. |
| MIG-4-spend-f | **A model key is issued for clerk `model` with the verb `read`.** Roots need a verb; `Spend` ignores verbs. | KEY-2 | A verbless root would be a key-format change. |
| MIG-4-spend-g | **A failed provider call meters nothing.** The reply is withheld if the record cannot be written. | LOG-7, CLK-7 | A provider that bills failures needs its error to carry usage. |
| MIG-4-spend-h | **Not here:** plan-route pools and the owner reserve (RES-5), extensions (CH-10, KEY-4), the held-task state on exhaustion, and paid API calls and purchases through other clerks. They build on `Spend` and `Meter`. | LOG-7, RES-5 | Each is its own row. |
