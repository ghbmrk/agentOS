# Assumptions: inbox slice (#2526, MIG-3)

What the slice rests on. Each line is a choice made to keep the slice small; none changes a requirement.

| # | Assumption | If wrong |
|---|---|---|
| 1 | The slice runs natively under the eval adapter, not in QEMU. The kernel, planner and clerk are pure Go over `MemStore`; no part reads the host. | Re-run the adapter inside the QEMU image once the image carries `cmd/slice`. |
| 2 | Keys and the clock are fixed (seeded ed25519 keys, ChaCha8 nonces, 2026-10-19 09:00Z). Two runs give one log, so the eval's replay check is exact. | None: production uses TPM-sealed keys and the real clock (D-141). |
| 3 | The owner's first tap issues one standing root key (organize, trash, unsubscribe) to the holder. The planner gets that key narrowed with the hold caveat (600 s base, 24 h novelty); it cannot lift the hold. | A key without the caveat would dispatch irreversible steps at once; `Next` would not hold them. |
| 4 | Earlier unsubscribes are replayed as steps already done under a root issued before the oldest one, so their senders are not novel. The real kernel gets this from its own log; the eval supplies only `prior_unsubscribes`. | A sender's first unsubscribe in the real log is novel as soon as it is the first. |
| 5 | The planner sees a mail id, its class and, when VRB-2 holds, an opaque sender handle (`sender-` + 8 hex of SHA-256 of the address). It sees no header, body or address. One unsubscribe step goes out per handle. | A handle collision would unsubscribe two senders at once; 32 bits is far above eval and household scale but is not collision resistant at scale. |
| 6 | One plan per action. A refused step rejects its whole plan (KRN-3), so grouping would let one refusal cancel the rest. | None; plans are cheap. |
| 7 | The clerk treats trash on an account whose trash is kept fewer than 7 days as `delete-remote` and refuses it, because the trash is not then a restore point. Spam is organized and left. | The 7-day floor is a default, not Mark's number; tune with `minRetentionDays`. |
| 8 | The organizational domain is the last two labels. Fixture domains sit under the reserved `.test`, where that is exact. | Real mail needs the Public Suffix List before VRB-2 ships against live accounts. |
| 9 | The class of each mail comes from a fake reader. A real reader is a separate row. | The planner's output is a function of class only, so a better reader changes no code here. |
