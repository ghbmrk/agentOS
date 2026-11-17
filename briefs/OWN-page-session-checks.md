# OWN-page-session-checks: held owner text that fails CH-19 or CH-21 is shown only as a pointer and cannot be run

Board section: Defects and later findings on surviving packages. Work item #5184 (release finding of OWN-page-session, #4941; its PR #5185 merged).

**Problem:** `owner.Channel.LocalHeld` (`broker/owner/waiting.go`) returns every held message in full, and `LocalRunHeld` runs any ID the page marks. CH-14 says held text that fails the CH-19 or CH-21 checks is shown only as a pointer and cannot be run. A held text carrying a planted footer or a texted-code lookalike can therefore be run from the page.

**Requirements:** CH-14 (pointer-only clause), CH-19, CH-21.
1. `LocalHeld` runs, over each held message, the same CH-19 and CH-21 checks the channel applies to agent text (the fold `checkAgent` uses in `broker/owner/pacer.go`), and marks a failing message as pointer-only (its text left out).
2. The page (`broker/localui/inbox.go`) lists a pointer-only message as one line with no checkbox.
3. `LocalRunHeld` refuses a `run` list naming a pointer-only ID (a new error, or `ErrHeldChanged` if the page could not have shown it as runnable), and runs nothing from that tap.

**Scope:** `broker/owner/waiting.go`, `broker/owner/waiting_test.go` (or a new `broker/owner/heldcheck_test.go`), `broker/owner/ASSUMPTIONS.md`; `broker/localui/inbox.go`, `broker/localui/inbox_test.go`; `broker/localapi/localapi.go` only if the held-message wire type needs a pointer flag; this brief. Not `broker/cmd/agentosd` (serial, D-111).

**Acceptance tests:**
- `broker/owner`: `TestLocalHeldShowsACH21FooterAsAPointer` (a held message with a CH-21 footer comes back pointer-only, no text); catches a `LocalHeld` that skips the check.
- `broker/owner`: `TestLocalRunHeldRefusesAPointerOnlyID` (a run naming it is refused and nothing runs); catches a run path that trusts the page.
- `broker/owner`: `TestLocalHeldShowsACH19FailureAsAPointer` (a held texted-code lookalike); catches a check that covers only CH-21.
- `broker/localui`: `TestInboxPointerHasNoCheckbox`; catches a page that still renders the text or a mark control.

**Guard files:** none (no package added or linked).

**Dependencies:** none open. Run before OWN-page-session-hold (#5187), which also edits `broker/owner/waiting.go`.

**Tier / gate:** tier A (`broker/owner`, `broker/localui`: owner-channel input): L3 on the strongest model, lens screen, separate Security accept.

**Usage estimate:** one session, under 100k.
