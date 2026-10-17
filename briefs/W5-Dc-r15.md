# W5-Dc-r15: pacer defaults `approval` to urgent (CH-15 / D-129)

Board row: issue #2250. Class: release. Tier: A (`tools/risk_tier.py` rates `broker/owner/pacer.go` A). Builder: strongest model (tier A). Usage estimate: 50k tokens, checkpoint at 40k.

**Decision (cite, do not restate).** Mark chose "Urgent" on the approvals card at 2026-10-17 20:03:36Z: approval texts bypass quiet hours by default. D-129 in spec PR #2251 (head 3ba546b): urgent texts skip quiet hours and the hourly limit but still count toward it.

**Why.** `Pacing.urgent` returns true for `approval` only if the owner listed it, so with `QUIET 22-7` at 23:00 a blocking approval is held overnight (ASSUMPTIONS O21).

## Requirement
- **CH-15** as written by D-129: `approval` urgent unless the owner switches it off.

Package IDs:
- **W5-Dc-r15-1** A zero `Pacing` (and any old state file) reads `approval` urgent; `security` urgent; `agent` and `update` not.
- **W5-Dc-r15-2** `URGENT APPROVAL OFF` persists across a restart and holds approval; `URGENT APPROVAL ON` clears it; the corrupt-setting fallback lands on the defaults above.

## Acceptance tests
- `broker/owner/pacer_test.go::TestPacingDefaultsFromAnOldState` (per-class default, old state and corrupt state).
- `TestPacingSettingsNeedUnlock` (ON/OFF round trip, saved).
- `TestQuietHoursHoldUpdatesButNotSecurity`, `TestAgentTextIsNeverPackedWithOtherTexts`: tests that expect a held approval set `ApprovalHeld: true`.
- Add: a quiet-hours test that an approval goes at once by default and counts toward the hourly limit.
- `broker/cmd/agentosd` `TestGrantsWiringReadsTheOwner`, `TestCallersUseTheirClass` expect approval held by default; update them.

## Design
Draft on this branch: `Pacing.ApprovalHeld bool json:"approval_held,omitempty"` (zero value = urgent, so old state files load unchanged and OFF has somewhere to be stored); `urgent(ClassApproval)` returns `!ApprovalHeld`; `URGENT APPROVAL ON|OFF` sets it. Alternative the builder may prefer: store an explicit tri-state. Update ASSUMPTIONS O21 and the pacing help text.

## Scope
`broker/owner/pacer.go`, `broker/owner/pacer_test.go`, `broker/owner/ASSUMPTIONS.md`, `broker/cmd/agentosd/pacing_test.go`, this brief.

## Out of scope
Routing deadline or work-holding questions to `ClassApproval` in `broker/cmd/agentosd/main.go`: waits for #2015, separate package. Note it on #2250 (do not close the issue on this PR).

## Notes
- Main's `broker/owner` tests fail to compile at `reaction_test.go:314` (`RequestEach` takes `[]time.Time`); a hotfix PR is in progress. Rebase on it before running tests.
- Packages CH12-ucs2, CH15-chat-window, OWN4-ack (#2254) also edit `pacer.go` and sequence after this one.
- Run broker guard tests and `go test ./...` (known sandbox-only failures: loop7 jail, loops canary, two probecmd canary tests).
