# PACE-help-questions: URGENT APPROVAL help also names the agent's questions

Board section: Human-native texting. Work item: #2394. Follow-up of D-129 (#2250), O22, O24. **Tier A** (`broker/owner`).

**Why.** Owner questions go out in the approval class (each has a deadline), so `URGENT APPROVAL OFF` also holds them (`broker/cmd/agentosd/questions.go:134`, `:242-244`). The help text mentions only approval requests. Failure path: the owner sends `URGENT APPROVAL OFF` to hold approvals overnight and is not told the agent's questions wait too.

**Requirements:** CH-15 (pacing and the URGENT classes; help names what the setting holds), CH-11 (O24 cites it).

**Change.** `broker/owner/pacer.go`: say "approval requests and questions" in `pacingForms` (`pacer.go:59`), the ON/OFF replies (`:818-826`) and `urgentNames` (`:866`); a short mention in `pacingHelp` (`:65`, already terse). The whole HELP stays within `control.MaxText` (459), pinned by `TestCH15HelpNamesChatUncut` (#2390 F1); update O24's count when it changes.

**Acceptance tests:** (REQ: CH-15, CH-11)
- `broker/owner/settings_test.go::TestUrgentApprovalWordingNamesQuestions` pins the four strings (mutant: revert one).
- `broker/cmd/agentosd/converse_test.go::TestCH15HelpNamesChatUncut` (existing check, kept; both learning variants; mutant: lengthen `pacingHelp` past the budget).

**Out of scope.** Changing which class questions use.

**Scope:** `broker/owner/pacer.go`, `broker/owner/settings_test.go`, `broker/cmd/agentosd/converse_test.go`, `broker/owner/ASSUMPTIONS.md` (O24), this brief.

**Usage estimate:** 30k tokens.
