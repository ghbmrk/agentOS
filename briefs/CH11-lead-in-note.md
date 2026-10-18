# CH11-lead-in-note: tell the owner when an unlisted form is read as a reaction

Board section: Human-native texting (spec #2157, D-127). Work item: #2277. Follow-up of CH11-reaction-forms (#2201, #2202, PR #2265); Security review of #2265, finding 2.

**Why.** When `Channel.readReaction`'s unlisted-form branch fires (a short lead-in, then a quote of a recent request or coded box text), the owner's lead-in is dropped and the agent gets only the "(not shown)" event. Unless the quoted text expects a reply, the owner gets nothing back. Failure path: the owner sends `Cancel "<box text with a 4+ digit code>"` and believes the agent was told to cancel.

**Requirements:** CH-11 (with CH-3: the line never echoes the quoted text; OWN-18: correction stays cheap).

**Change.** `broker/owner/reaction.go`: a reaction read from an unlisted form is marked, and `reactionLocked` sends the owner one fixed line (`readAsReaction`) saying it was read as a reaction and did not go to the agent, ahead of any pointer, locked or unlocked. Listed forms are unchanged.

**Acceptance tests:** `broker/owner/reaction_leadin_test.go::TestUnlistedReactionTellsTheOwner`, `::TestLockedUnlistedReactionTellsTheOwner`.

**Guard files:** none.

**Out of scope.** #2264 (STOP near-miss hint on this path). `reaction_test.go` and `broker/owner/ASSUMPTIONS.md` are left alone because open PRs touch them (D-111); the tests live in a new file.

**Scope:** `broker/owner/reaction.go`, `broker/owner/reaction_leadin_test.go`, this brief.

**Usage estimate:** 40k tokens.
