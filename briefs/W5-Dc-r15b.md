# W5-Dc-r15b: owner questions are `approval` class (CH-15 / D-129)

Board row: issue #2250 (second half; the pacer half merged in #2262). Class: release. Tier: A (`broker/owner/`, `broker/cmd/agentosd/`). Builder: strongest model.

**Decision (cite, do not restate).** D-129 (CH-15): `approval` covers "questions with a deadline or that hold or contain work" and is urgent unless the owner sends `URGENT APPROVAL OFF`.

**Why.** Every owner question (CAP-10, `broker/question`) carries a deadline: `owner_question` requires a positive `wait_minutes` (`question/tool.go`), and the book clamps it to [MinWait, MaxWait]. So every question is an `approval` text. agentosd's wiring and `owner.Channel.NotifyNow` still pace questions as `agent`, so with `QUIET 22-7` a question asked at 23:00 is not texted until 07:00 and its default stands late.

## Requirement
- **CH-15** as written by D-129: questions with a deadline are `approval`.

Package IDs:
- **W5-Dc-r15b-1** A question goes at once in quiet hours and past the hourly allowance by default, and still counts toward the hour; `URGENT APPROVAL OFF` holds it (quiet hours, allowance, the gate's approval-first `Reserve`); `URGENT AGENT ON` no longer decides it.

**Acceptance tests:**
- `broker/owner/pacer_test.go::TestNotifyNowSendsAtOnceAndCounts` (default urgent; held with `URGENT APPROVAL OFF`, even with agent urgent).
- `broker/cmd/agentosd/question_quiet_test.go::TestQuestionQuietWiring` (per class setting), `TestQuestionReserveWiring` (urgent skips the gate's reserve; held keeps it).
- `broker/owner/pacer_race_test.go` rigs set `ApprovalHeld` so they keep testing the paced path.

## Design
`NotifyNow` reads `ClassApproval`; agentosd's `questionQuiet`, `questionQuietHours` read `ClassApproval`, and `questionReserve` skips `grants.Gate.Reserve` while approval is urgent (the urgent send counts through `sendCounted`). Update owner ASSUMPTIONS O22, O23 and agentosd ASSUMPTIONS PW2.

## Scope
`broker/owner/pacer.go`, `broker/owner/pacer_test.go`, `broker/owner/pacer_race_test.go`, `broker/owner/ASSUMPTIONS.md`, `broker/cmd/agentosd/questions.go`, `broker/cmd/agentosd/question_quiet_test.go`, `broker/cmd/agentosd/ASSUMPTIONS.md`, this brief.
