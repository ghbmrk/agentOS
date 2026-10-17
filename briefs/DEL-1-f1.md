# DEL-1-f1: A deletion reaches replies waiting in the guest outbox

Board row: DEL-1-f1 (#1047), follow-up of DEL-1 from #709's Findings. Risk tier A (deletion reach, CAP-3).

**Problem.** A reply a guest posted is acknowledged (204) once it is in the guest plane's outbox (`store.outbox`, at most `MaxOutbox` = 64, written through to `InboxPath`). It waits there until the evidence worker in agentosd hands it on and calls `ReplyDone`. A deletion through `forgetFan` (agentosd/evidence.go) drops every kept reply and the learning plane's cases, but not these waiting replies: a reply that quotes the deleted record is still sent afterwards, and a reopen of the store brings it back. Failure path: delete while replies are waiting to be sent.

**Reach.** A `PendingReply` names its machine and message, not the task or record it is about, so a deletion cannot pick out the replies that quote its subject. Like the kept replies (security C6 on #148), the forget drops every waiting reply.

**Requirements** (marker `REQ: CAP-3 (DEL-1-f1a, DEL-1-f1b, DEL-1-f1c)`):
- **DEL-1-f1a** `Plane.ForgetReplies` drops every waiting reply from the outbox in one durable write: after a store reopen none is pending. Each dropped reply is recorded in `done` (machine, message ID, hash; no text), so the guest's retry of it is a 204 that queues nothing and is not sent. A failed write is returned, and nothing dropped is held in memory.
- **DEL-1-f1b** `forgetFan.ForgetTasks` reaches the outbox the evidence worker serves from, and reports its failure joined with the others. No change to main.go: the fan reaches it through `keptReplies`.
- **DEL-1-f1c** No reply waiting when the forget runs is handed on afterwards: the worker reads the outbox again before each reply, and a reply already being routed when the forget runs leaves no kept copy behind.

**Scope.** broker/guest/{store.go, owner.go, outbox_test.go, ASSUMPTIONS.md}; broker/cmd/agentosd/{evidence.go, evidence_test.go}; this brief.

**Acceptance tests:**
- DEL-1-f1a: `broker/guest/outbox_test.go::TestDEL1f1ForgetDropsWaitingReplies` and `::TestDEL1f1ForgetWriteFailure`: replies waiting at a forget are gone after a reopen, a retry queues nothing, and a failed write is reported. Catches a forget that only clears memory.
- DEL-1-f1b: `broker/cmd/agentosd/evidence_test.go::TestDEL1f1DeletionReachesTheOutbox`: the forget fan drops the served outbox and reports its failure; an outbox that cannot drop fails the deletion. Catches a fan that skips the outbox.
- DEL-1-f1c: `broker/cmd/agentosd/evidence_test.go::TestDEL1f1ForgetDuringARoute`: a deletion mid-route sends no other waiting reply and leaves no kept copy. Catches a worker iterating a stale snapshot.

**Out of scope.** A reply already handed to the owner channel cannot be recalled. Per-task selection needs a task link on the reply (DEL-sd).
