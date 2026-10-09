# pubsend assumptions

Package OSS-6s-a. The sender behind `pubid.Sender`: one constant frame a day, an idempotent ledger, and the network behind `Transport` (OSS-6s-b).

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| S1 | **One frame a day, always the same size.** pubid hands over one sealed batch every counted day, a zero-item cover batch when nothing is due (pubid P4, P10). pubsend sends it as one frame of `FrameSize` = 16×64 KiB bytes: the batch, then padding. No setting turns the cadence or the padding off (D-062). | OSS-6 | OSS-6p may resize the slots. |
| S2 | **Padding is a keyed stream over a stored random seed (a5, a7).** Each new publication gets a 32-byte seed from crypto/rand, stored in the ledger before anything is sent; the padding is AES-256-CTR keystream under that seed with a zero IV (each seed keys one frame). A retry rebuilds the same frame, so observers never see two versions of one publication. The batch's count and lengths are inside its signature (pubid P11); the frame carries no other length. | OSS-6 | — |
| S3 | **The ledger is keyed by (day, SHA-256 of the unpadded batch) (a4, a6).** A key already confirmed or waiting is a no-op; a different batch for a confirmed day (a clock far back, N1 on #163) is new and is sent. The ledger is replaced atomically (temp file, fsync, rename, directory fsync, as pubid's outbox), loaded strictly, and a damaged one is an error, never taken as empty. A crash after the transport accepted and before the ledger recorded it re-sends the same frame. The last 400 confirmed keys are kept, over a year of days. | OSS-6 | — |
| S4 | **`MaxWaiting` = 7 is provisional (a9).** With the transport unreachable, frames wait, at most 7; past that the oldest is dropped. OSS-6p sets the real bound. | OSS-6 | OSS-6p. |
| S5 | **Silent to the owner except for drops.** A drop is written to the owner-visible log (OSS-1) only, naming the day and no content; transport errors are not reported to the owner (D-062, pubid P10(iii)). `Publish` returns once the batch is durable in the ledger, so pubid's outbox does not also hold it; `Flush` returns the transport error to its caller. | OSS-1, OSS-6 | — |
| S6 | **No network here (a8).** pubsend imports no `net`, `net/*`, `crypto/tls` or `os/exec`, and no broker package but pubid. | OSS-6 | — |

## Conditions for wiring

- **SW1:** the broker calls `Flush` on a timer as well as at release, so a backlog leaves when the transport comes back rather than on the next day's batch. `Publish` and `Flush` share one mutex, so the timer may run beside release. Carried to OSS-6s-b.
- **SW2:** `pubid.Publisher.Clear` does not reach frames waiting in the pubsend ledger (pubid P6(b)); OSS-6s-b adds a `Sender.Clear` and wires it to the same owner action.
