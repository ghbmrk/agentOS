# Assumptions: inbox slice (#2526, MIG-3)

What the slice rests on. Each line is a choice made to keep the slice small; none changes a requirement.

| ID | Assumption | If wrong |
|---|---|---|
| MIG-3-1 | The slice runs natively under the eval adapter, not in QEMU. The kernel, planner and clerk are pure Go over `MemStore`; no part reads the host. | Re-run the adapter inside the QEMU image once the image carries `cmd/slice`. |
| MIG-3-2 | Keys and the clock are fixed (seeded ed25519 keys, ChaCha8 nonces, 2026-10-19 09:00Z). Two runs give one log, so the eval's replay check is exact. | None: production uses TPM-sealed keys and the real clock (D-141). |
| MIG-3-3 | The owner's first tap issues one standing root key (organize, trash, unsubscribe) to the holder. The planner gets that key narrowed with the hold caveat (600 s base, 24 h novelty); it cannot lift the hold. | A key without the caveat would dispatch irreversible steps at once; `Next` would not hold them. |
| MIG-3-4 | Earlier unsubscribes are replayed as steps already done under a root issued before the oldest one, so their senders are not novel. The real kernel gets this from its own log; the eval supplies only `prior_unsubscribes`. | A sender's first unsubscribe in the real log is novel as soon as it is the first. |
| MIG-3-5 | The planner sees a mail id, its class and, when VRB-2 holds, an opaque sender handle: `sender-` + 32 hex (128 bits) of HMAC-SHA256 of the address under the account's secret (at least 128 bits; `NewAccount` refuses less). The handle is also the kernel `Recipient` that novelty is judged on. It sees no header, body or address. One unsubscribe step goes out per handle. | Two senders sharing a handle needs an HMAC-SHA256 collision on 128 bits. A leaked secret lets its holder compute handles from addresses, not read them back. The eval fixes the secret so a run replays; a real account draws its own and keeps it with the clerk. |
| MIG-3-6 | One plan per action. A refused step rejects its whole plan (KRN-3), so grouping would let one refusal cancel the rest. | None; plans are cheap. |
| MIG-3-7 | The clerk treats trash on an account whose trash is kept fewer than 7 days as `delete-remote` and refuses it, because the trash is not then a restore point. The 7-day floor is SPEC VRB-2's trash rule. The clerk also trashes only mail the reader classes as spam or phishing. | A reader that misclasses a real mail as spam still trashes it, undoably, within retention. |
| MIG-3-8 | The organizational domain is the last two labels. Fixture domains sit under the reserved `.test`, where that is exact. | Real mail needs the Public Suffix List before VRB-2 ships against live accounts. |
| MIG-3-9 | The class of each mail comes from a fake reader. A real reader is a separate row. | The planner's output is a function of class only, so a better reader changes no code here. |
| MIG-3-10 | An alert (a bank or security notice) is never unsubscribed (only `bulk` is) and never trashed (only spam and phishing are), whatever the planner asks: both checks are the clerk's. The synthetic mailbox has no alert mail and the eval set is not edited here, so only the unit tests exercise it. | A real alert the reader misclasses as phishing is trashed, undoably. Follow-up: a sub B alert case in the eval set, and a guard in the real reader. |
| MIG-3-11 | The in-process planner (`Plans`) stands in for PLN-5's `plan` command. It reads only the clerk's listing, as the command would. | The real command replaces `Plans`; the kernel, keys and clerk do not change. |
| MIG-3-12 | The unopened and first-mail ages are 90 days, a constant of the clerk (D-141). A sender with no `last_opened` entry has never been opened, so it is eligible once the first-mail age holds; an entry that is not a date, or a `today` that is not a date, makes the mail ineligible (`bad-date`). | A reader that drops opens it saw would unsubscribe a sender the owner reads. The real reader must report every sender it has seen opened. |
| MIG-3-13 | Eligibility is judged again when the hold ends: `Do` re-runs VRB-2 on the clerk's copy of the mail against the world as it is then. | A mail the owner opens during the hold is not unsubscribed. |
| MIG-3-14 | `Do` acts only on a request `State.Dispatched` finds in the kernel's log: same step, key, attempt, dispatch and hold. `Request.Now` is not recorded there and is not checked. A direct call that is not a dispatch cannot write the kernel's log, so the clerk records its refusal in its own list. | A clerk that took the clock from a forged request could pass a time check; the hold itself is checked against the log, not the clock. |
| MIG-3-15 | The planner key carries a per-day cap of 200 actions (`LimitRate`), which counts all verbs together. | A per-verb trash cap is a later item; today a burst of 200 trashes is allowed, each of spam or phishing, undoable. |
| MIG-3-16 | Labels live under `agentOS/` (VRB-2), so the clerk never writes into the owner's own labels. | A provider with no nested labels needs a flat prefix. |
| MIG-3-17 | A sender with one eligible bulk mail and another mail classed spam, phishing or personal is still unsubscribed; eligibility is per mail found first. | Narrowing per sender is a later item. |
| MIG-3-18 | The eval's `keys_at_end` is read from the planner key and `owner_taps` from the log's widening entries, so a widened key or a second approval fails the eval. | None. |

## Release items (not in this slice)

| ID | Item | Failure path |
|---|---|---|
| MIG-3-R1 | Public Suffix List for `org()`. | A domain under a multi-label public suffix aligns with every site under that suffix. |
| MIG-3-R2 | The real POSTer's egress rules: parse with `net/url`, deny private addresses after resolution, port 443 only, no redirects, reject userinfo, whitespace and control characters. | An unsubscribe URL steers the POST at a host inside the home network. |
| MIG-3-R3 | DKIM `x=` and `t=` tags, and IDN domains. | An expired or replayed signature passes VRB-2. |
| MIG-3-R4 | A wider lookalike check than the confusable pairs in `skeleton`. | A lookalike sender outside the pair list is unsubscribed from. |
