# W5-Dc-r12: A forget survives a crash between the tombstone and the digest purge (CAP-3)

Release finding on #592 (W5-Dc, merged a818e20): security 6080263349 point 1 and L3 6080272656 point 2. BOARD row W5-Dc-r12. Two release points from #612 (W5-Dc-r7) are folded in: L3 6083352871 and Security 6083353716.

SPEC row: CAP-3 (a deletion propagates: the record and everything derived from it leave recall at once; actions already taken stay done).

**Why one package.** One seam: what ties the tombstone, which defines a forgotten goal, to the digest queue across a restart. About 150 lines with tests in `broker/cmd/agentosd` (`digest.go` `openLocked`, `forget.go`, one line in `main.go`). The two folded-in points are test-only (`digest_test.go`, `digestqueue/queue_test.go`).

**Order.** W5-Dc-r1a (#617, open) edits the pacer in `broker/owner/*` and the forget-agent tests. It does not touch `main.go`, `digest.go` or `forget.go`. Keep this package away from pacer code. Line references are from main at f6851ee; reread them there.

**Today.**
- `ownerForget.Execute` (forget.go:538) first owes the forget (`owed.owe`) and then calls `forgetAll` (forget.go:586). `forgetAll` runs `f.forget`, which writes the tombstone and then forgets the stores, and then `f.digest(goal)`, which is `dg.forget` (main.go:651).
- A failed `owed.owe` is only logged.
- If the process then stops after the tombstone but before `f.digest`, the next boot has:
  - no owed entry, so `finishOwed` (forget.go:1409) does not ask the digest;
  - no digest hold, because `digestBox.forget` never ran;
  - a tombstone, which `replayForgotten` replays only for the learning stores.
- A Ready batch holding the goal's reference is then sent at the next digest step. This is the double fault.
- `digestBox.forget` (digest.go:569) drops a held reference once the queue's `Forget` holds: `if d.forgets[ref] { delete; keepForgets }`. No test kills that branch (L3 6083352871 on #612).
- `validate` (digestqueue/queue.go about 238) refuses a redacted batch that keeps a snapshot or an ack. `TestInvalidPersistedStatesRejected` covers only "redacted ready". The mutant "drop the no-snapshots / no-acks clause" (M4) survives (Security 6083353716 on #612).

**Decision: the digest replays the tombstone when its queue opens.** Record it in agentosd ASSUMPTIONS (DF row).
- `digestConfig.Forgotten func() []string` lists the tombstoned goals. `openLocked`, after `digestqueue.New` and the existing `forgets` purge, calls `q.Forget(g)` for each listed goal that `digestRef` accepts.
- Any refusal fails the open. The box stays down (`d.q == nil`), nothing is sent, and the next step reopens and replays again.
- `ownerForget.wireDigest(dg, lp.forgotten.goals)` sets both `f.digest` and `dg.cfg.Forgotten` in one call, so the two cannot be wired apart.
- Why this option, and not "save the digest hold before the tombstone":
  - The tombstone is what makes a goal forgotten. A replay from it covers every crash after the tombstone, whatever the owed and hold writes did, with no new write.
  - It mirrors `replayForgotten`, which already replays the tombstone for the learning stores.
  - A hold-first design adds a digest-store write on the forget's critical path. It needs a rule for a failed hold save, which reopens the same gap one fault deeper. It also leaves a hold that withholds a batch for ever when the forget is then refused before the tombstone (`errNotTombstoned`).
  - Cost: one in-memory scan per tombstoned goal per open. `Queue.Forget` commits only when a batch matches, and the tombstone is capped at 65536 goals.
  - Replaying through `dg.forget` per goal before the open was also rejected: each refused call saves the box state, which is O(N²) bytes written for N goals.

**Requirements** (local IDs under CAP-3):
- **DF-1, a crash after the tombstone sends nothing.** Setup: a Ready batch holds `owner:a`, the forget's `owed.owe` fails, and the process stops after the tombstone and before `f.digest`. After a restart with the same stores, no digest step sends the batch's line, and no batch holds a snapshot with `owner:a`.
- **DF-2, a refused replay keeps the queue closed.** If the queue's `Forget` refuses a tombstoned goal at open (store refusal), the box is not open and sends nothing. A later step reopens, the replay holds, and the line is never sent.
- **DF-3, the replay is cheap and exact.** A replay that matches no batch writes neither the queue store nor the box's state store. A tombstoned goal that is not a valid reference is skipped and does not fail the open.
- **HF-1, a held forget is dropped once it holds** (L3 6083352871 on #612). After a hold, `digestBox.forget(ref)` with the queue open returns nil, removes ref from `forgets`, and saves: the state store no longer holds ref.
- **VR-1, validate pins the redacted clause** (Security 6083353716 on #612). `New` refuses a persisted redacted Unknown batch and a redacted terminal batch that keeps one snapshot or one ack bit.

**Failing-test-first controls.** Show each test failing at main, cite the message in the PR, then show it passing at the head. Markers: `REQ: CAP-3 (W5-Dc-r12 DF-1)` and so on.

| ID | Test | Why it fails on main |
|---|---|---|
| DF-1 | `TestDigestForgetCrashAfterTombstoneSendsNothing`: a digest rig with a Ready batch holding `owner:a`, a real tombstone and an owed store whose Save fails. `Execute` stops (Goexit) after the tombstone. Restart: new box over the same stores, `wireDigest`, `finishOwed`, open, digest step. | The batch is sent. |
| DF-2 | `TestDigestTombstoneReplayRefusedKeepsTheQueueClosed`: the queue store refuses the save that drops `owner:a` once. The first open fails and the box is down; the next step purges, and nothing is sent. | Without the replay there is nothing to refuse: the batch is sent. |
| DF-3 | `TestDigestTombstoneReplayWritesNothingWithoutAMatch`: an open with an unmatched and an invalid tombstoned goal writes as many saves as one with no tombstone, and opens. | Passes at main behaviour; it pins the no-write property. Show the mutants "no `digestRef` filter" and "replay always saves" failing it. |
| HF-1 | `TestDigestHeldForgetIsDroppedOnceItHolds` | Passes on main. It pins the branch: show the mutants "no delete" and "no keepForgets" failing it. |
| VR-1 | Cases in `TestInvalidPersistedStatesRejected` | Passes on main. Show mutant M4 failing it. |

**Controls that must keep passing.** All `broker/digestqueue` and `broker/cmd/agentosd` tests, in particular `TestDigestForgetBeforeOpenPurgesOnOpen`, `TestDigestRefusedForgetHoldsItsReadyBatchAfterARestart`, `TestDigestHeldForgetKeepsItsReadyBatchUnsent` and `TestOwedForgetPurgesTheDigestAfterARestart`.

**Threat check for the reviewer.**
- No path sends a Ready batch holding a tombstoned reference after a restart: the replay runs inside every open, before `NewSender`, and a refusal leaves the box down.
- The replay cannot wedge the digest for ever: only a store refusal or a broken queue fails it, the same faults that already stop sends. A Sending batch cannot exist at open, because `New` turns it into Unknown.
- No forgotten text or reference reaches a log: the open error is logged as the queue's error, which names no reference.
- Wiring: `Forgotten` is set wherever `f.digest` is.

**Out of scope (findings).**
- In-process window: a digest step running between the tombstone and `f.digest`, with no crash, can still send. It equals a send just before the owner's YES and leaves nothing kept, so raise it as later (LATER.md).
- The learning plane not opening after a restart: no tombstone is read, so there is no replay. Today the owed path has the same gap. Raise it as later.
- Rows W3-forget-*, DIG-1, W5-Dc-r1a and W5-Dc-r1b, and the pacer.

**Scope:**
- `broker/cmd/agentosd/digest.go`: `digestConfig`, `openLocked` and the `forget` comment.
- `broker/cmd/agentosd/forget.go`: `wireDigest` only.
- `broker/cmd/agentosd/main.go`: the CAP-3 wiring line only.
- `broker/cmd/agentosd/digest_test.go` or a new `broker/cmd/agentosd/digestforget_test.go`.
- `broker/digestqueue/queue_test.go`: `TestInvalidPersistedStatesRejected` cases only.
- `broker/cmd/agentosd/ASSUMPTIONS.md`, `broker/digestqueue/ASSUMPTIONS.md` (the agentosd Forget note).
- `briefs/W5-Dc-r12.md`, `BOARD.md` row W5-Dc-r12, `LATER.md` (one line).

**Needs:** W5-Dc (#592) and W5-Dc-r7 (#612), both merged.

**Done:**
- CI green.
- DF-1 to DF-3, HF-1 and VR-1 covered by passing tests with markers.
- Risk tier A (`broker/cmd`).

## Delivery

Builder model: the session's model (risk tier A). One package per session, tests first. Review: L3 with the threat check above, then a separate Security section (OPERATING §3–4); the CAP-3 path is security-critical. Estimate and checkpoint: about 80k tokens, not a ceiling (OPERATING §5).
