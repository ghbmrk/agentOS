# OP-journal-record-guards: intent-state guards on cancel and quality records

Board section: Release rows from the state-machine audit (2026-10-16). Source: work item #1927; `/mnt/project-files/audits/2026-10-16-state-machines.md` §2.1 and R2e. Tier A (broker/journal is the commit path of every effect).

**Why.** `Engine.validate` is the only check a record passes before it is journaled, and `Open` replays every record through it. Two record types were checked only for a known intent: `cancel_requested` could name any attempt in any state, and `quality` had no stated rule. A record the live engine would never write but replay accepts lets live and replay disagree on what was cancelled.

**Requirements:** OP-2 (an attempt cut off by STOP keeps its cancel evidence; unknown outcomes stay unresolved until resolved), OP-7 (permission, execution success and goal quality are recorded separately), and the journal invariant that live commit and replay accept the same records.

**Change.**
- `cancel_requested` is legal only for an attempt that was in flight or outcome-unknown when a `stop` record was applied. The `stop` record's apply marks those attempts (`Engine.stoppedAt`), so replay rebuilds the set. The mark is never cleared, so Stop's cancel stays legal when the attempt settles, or RESUME runs, while the canceller is out of the lock.
- `quality` stays legal from every state, and validate says so. OP-7 keeps quality apart from permission and execution; apply never changes state or attempts for it. Owners and fixtures rate tasks before dispatch, and journals already hold such records, so a state guard would fail their Open with ErrCorrupt (deviation from #1927's ask, recorded in ASSUMPTIONS A20).
- `recheck_failed` from `not_applied` (NotApplied→Denied) is stated as intended in validate: a recheck before a resend can fail (OP-3), and Erase denies a not-done intent this way (CAP-3).

**Tests first.** A table of (state, record) pairs over pending, authorized, denied, denied at recheck, outcome unknown, succeeded and not applied: legal pairs commit and replay to the same status; illegal ones are refused live and, appended raw, make Open fail with ErrCorrupt. Plus: a cancel after the attempt settles or after RESUME still commits and replays; an attempt dispatched after STOP cannot be cancelled until the next STOP.

**Acceptance tests:** OP-2: `TestOP2CancelRecordGuard`, `TestOP2CancelAfterAttemptSettles`, `TestOP2CancelOfAttemptAfterStop`; OP-7: `TestOP7QualityRecordGuard`, `TestOP7QualityWhileInFlight` (all in `broker/journal/record_guard_test.go`); the existing `TestOP2SameEffectModel` stays green.

**Out of scope.** Scrubbing quality notes on erase; a journal version bump.

**Scope:** `broker/journal/engine.go`, `broker/journal/record_guard_test.go` (new), `broker/journal/ASSUMPTIONS.md`, `briefs/OP-journal-record-guards.md`.

**Usage estimate:** 120k tokens.
