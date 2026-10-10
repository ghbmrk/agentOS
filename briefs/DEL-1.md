# DEL-1: An accepted owner reply survives a crash (DEL-sd a, provisional)

Board section: Owner-benefit review (2026-10-09). Finding from the 2026-10-09 owner-benefit review (point 2), checked against the code at 9b4bf8a.

**Tier:** A (`broker/guest`, `broker/cmd`). Strongest model. About 60k tokens.

**Needs:** DEL-sd opened (the spec diff need not be merged: the choices below are provisional and recorded in `broker/guest/ASSUMPTIONS.md`, as W5-Dc-r1 did with r14). DEL-2 builds after this and shares the outbox.

## Today

The reply leg from the guest to the owner loses work in three places. A lost reply also loses the task, since a message is rerun only when it was never answered.

1. **Acknowledged before persisted.** `guest/owner.go` `ownerReply` calls `m.box.answer(id)`, which removes the message and writes the inbox (it ignores the write error: "the answer goes out even if the store cannot be written"). It then calls `cfg.OwnerReply`, which is `ev.enqueue` (`cmd/agentosd/main.go:1134`), pushing into the in-memory channel `evidence.q`. Then it returns 204. A broker crash or restart between the 204 and `evidence.run` draining the channel loses the reply. The message is already gone from the inbox, so `requeue` will not rerun it either.
2. **The guest drops the answer on any failed POST.** `cmd/agentos-guest-bridge/main.go` `ownerOnce` (l.172-206) returns the error on a network error, a 5xx or a 404. The `owner()` loop sleeps 2s and GETs `/owner/next` again. The computed answer is discarded. The test guests (`vm/gvisor/testdata/guest`, `cleanroom/testdata/guest`) copy the pattern.
3. **A late reply gets 404.** After a requeue, the old answer gets 404 ("no such pending message", `owner.go:288-291`) once a new turn's reply lands first.

G5 (`broker/guest/ASSUMPTIONS.md:14`) promises at-least-once delivery only for owner-to-guest messages. Nothing promises it for the reply. No SPEC row covers reply durability (ARC-4 is about machine state; CH-19 only covers withheld text), hence DEL-sd.

## Requirements (local IDs; DEL-sd a when the spec diff merges)

- **DEL-1a, persist before 204.** `ownerReply` writes a durable outbox record before it answers 204: machine, message ID, text, summary, private flag and receive time. The record goes in a broker-owned 0600 store next to the inbox. A store write failure returns 503 and leaves the message pending; it never returns 204. Removing the message from the inbox and writing the outbox happen in one write, or in the order "outbox, then inbox", so that a crash between the two leaves a pending message plus an outbox entry (a replay), never neither.
- **DEL-1b, outbox drained after restart.** On start, agentosd hands every outbox entry to the evidence worker, in receive order, before new replies. An entry leaves the outbox only when DEL-2 records an outcome (sent, kept, or flagged uncertain). `evidence.q` becomes a wake-up signal, not the store of record.
- **DEL-1c, idempotent reply.** A second POST for a message ID already in the outbox, or one already answered within the outbox's retention, returns 204 and changes nothing. Bodies are compared by hash, and a different body for the same ID is 409 with no change. 404 stays for IDs never handed out or belonging to another machine (G5's "accepted once" becomes "applied once").
- **DEL-1d, the guest retries what it holds.** The bridge keeps its answer and retries the POST with bounded backoff (1s doubling to 30s) on network errors, 5xx and 503. It drops the answer only on 204, 404 or 409. It never re-asks the model for a message it already answered in this incarnation. The test guests follow suit, or say in a comment why they need not.
- **DEL-1e, bounded.** The outbox holds at most 64 entries. When it is full, `ownerReply` returns 503 (the guest retries; nothing is dropped silently), and a status line says replies are waiting. The bound is provisional; record it in ASSUMPTIONS.

## Tests (written first)

- A crash after the 204 and before the evidence worker runs: reopen from the files, and the reply is sent once (pattern: `TestG5OwnerMessagesSurviveABrokerRestart`, `guest/plane_test.go:573`).
- A crash between the outbox write and the inbox write: after the reopen the reply is sent once, and the rerun turn's duplicate POST is a 204 no-op.
- An inbox or outbox write failure gives 503, and the message stays pending.
- A duplicate POST gives 204 with one send; a different body gives 409; another machine's ID still gives 404.
- The bridge (new unit test with an `httptest` broker): a 503, then 204, sends one POST body twice and asks the model once.
- A full outbox gives 503 and the status line, and nothing is lost.

## Scope

`broker/guest/owner.go`, a new `broker/guest/outbox.go` (or the inbox store gaining a section), `broker/guest/*_test.go`, `broker/guest/ASSUMPTIONS.md` (G5 updated, new row for the outbox bound), `broker/cmd/agentos-guest-bridge/`, `broker/vm/gvisor/testdata/guest/main.go`, `broker/cleanroom/testdata/guest/main.go`, `broker/cmd/agentosd/evidence.go` and `main.go` (outbox drained into the worker only; outcome handling is DEL-2).

## Not in scope

How each outcome is reported to the owner: that is DEL-2. A page that lists kept replies: that is CH-20p. The summary field in the bridge: that is CH-20w.
