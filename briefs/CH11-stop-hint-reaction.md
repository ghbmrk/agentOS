# CH11-stop-hint-reaction: keep the STOP near-miss hint on a STOP-led reaction

Board section: Human-native texting (spec #2157, D-127). Work item: #2264. Follow-up of CH11-reaction-forms (#2201, #2202) and CH11-lead-in-note (#2277, PR #2341).

**Why.** A text such as `STOP "<request or coded box text>"` is read as an unlisted reaction, so it never reaches `control.Handler.Handle`, and the owner loses the hourly hint "To pause everything, reply STOP." that a STOP near-miss gets. Failure path: the owner quotes a box text with STOP in front of it to pause the box and is never told how to pause. CH-2 holds either way, because only an exact STOP pauses.

**Requirements:** CH-11; CH-15 (the hint keeps its single hourly quiet window, so spoofed reactions cannot repeat it).

**Change.** `broker/control/handler.go`: a new `Handler.StopHint(lead)` returns the hint when the owner's lead-in is STOP or a STOP near-miss, and it spends the same quiet window that `Handle` uses. `broker/owner/reaction.go`: an unlisted reaction keeps its lead-in, and `reactionLocked` adds the hint ahead of the `readAsReaction` line, both locked and unlocked. Only the lead-in is checked, so a quote that ends in STOP gets no hint. The agent still gets only the "(not shown)" event.

**Acceptance tests:** `broker/owner/reaction_stophint_test.go::TestStopLedReactionKeepsTheStopHint`, `::TestLockedStopLedReactionKeepsTheStopHint`.

**Guard files:** none.

**Out of scope.** `reaction_test.go` and `broker/owner/ASSUMPTIONS.md` are left alone because open PRs touch them (D-111); the tests live in a new file.

**Scope:** `broker/control/handler.go`, `broker/owner/reaction.go`, `broker/owner/reaction_stophint_test.go`, this brief.

**Usage estimate:** 40k tokens.
