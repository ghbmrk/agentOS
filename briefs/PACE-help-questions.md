# PACE-help-questions: URGENT APPROVAL help also names the agent's questions

Board section: Human-native texting. Work item: #2394. Follow-up of D-129 (#2250), O22, O24. **Tier A** (`broker/owner`).

**Why.** Owner questions go out in the approval class (each has a deadline), so `URGENT APPROVAL OFF` also holds them (`broker/cmd/agentosd/questions.go:134`, `:242-244`). The help text mentions only approval requests. Failure path: the owner sends `URGENT APPROVAL OFF` to hold approvals overnight and is not told the agent's questions wait too.

**Requirements:** CH-3 (pacing the owner can predict), OWN-18 (the help matches what the setting does).

**Change.** `broker/owner/pacer.go`: say "approval requests and questions" in `pacingForms` (line 46), the ON/OFF replies (753-761) and `urgentNames` (800-813); a short mention in `pacingHelp` (line 49). HELP stays within 459 characters with the longest `HelpExtra` (444 now); update O24 if the count changes.

**Acceptance tests (REQ: CH-3, OWN-18):**
- `broker/owner/settings_test.go::TestUrgentApprovalWordingNamesQuestions` pins the four strings (mutant: revert one).
- `broker/owner/settings_test.go::TestHelpWithLongestExtraFitsBudget` (existing check, kept; mutant: lengthen `pacingHelp` past the budget).

**Out of scope.** Changing which class questions use.

**Scope:** `broker/owner/pacer.go`, `broker/owner/settings_test.go`, `broker/owner/ASSUMPTIONS.md` (O24), this brief.

**Usage estimate:** 30k tokens.
