# OWNER-retire-surface: STATUS says when an answered approval could not be saved

Board row: #1971 (class:release, tier A). Origin: L3 review of #1970 (SM-approval-journal, head e06a5c6).

**Requirement IDs:** SM-AJ-4 ("the failure is surfaced", from briefs/SM-approval-journal), OP-11.

**Problem.** `retireLocked` keeps a failed save in `c.retireErr` and `Channel.RetireErr()` reports it (broker/owner/approvals.go), but nothing in production reads it. Failure path: the state disk fills, the retire save fails, `openLocked` then refuses new requests on the same store, so the owner stops getting approval requests while STATUS and the daemon log say nothing.

**Scope.**
- `broker/owner/approvals.go`: `Channel.RetireNote()`, STATUS's fixed-word line while `RetireErr` is set (UX-56-1: no raw error, plainLine-safe, at most 100 characters).
- `broker/cmd/agentosd/main.go`: `newOwnerPacer` adds that line to `cfg.Notes`; the pacer's minute tick logs the raw error once per distinct failure.
- Tests: `broker/owner/retire_test.go`, `broker/cmd/agentosd/pacing_test.go`.
- `broker/owner/ASSUMPTIONS.md`, `broker/cmd/agentosd/ASSUMPTIONS.md`, this brief.

**Acceptance tests:**
1. SM-AJ-4: `broker/owner/retire_test.go::TestRetireNoteFollowsRetireErr`: empty while saves work; the fixed line once a retire save fails; empty again after the next save works. The line keeps only characters STATUS keeps and fits its 100.
2. SM-AJ-4, OP-11: `broker/cmd/agentosd/pacing_test.go::TestStatusSaysAnUnsavedAnswer`: through the notes `newOwnerPacer` puts on the daemon config, a real owner channel whose store starts failing after a request is opened, answered with YES, shows the line; the tick logs the cause once, not every minute; once a save works the line clears.

**Not in scope.** The other dropped owner saves and `RetireErr` over-reporting (#1969).

**Usage estimate:** 40k tokens (tier A).
