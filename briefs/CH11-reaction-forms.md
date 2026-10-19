# CH11-reaction-forms: more reaction forms, no false reaction from an inner quote, no raw coded text

Board section: Human-native texting (spec #2157, D-127). Work items: #2201, #2202. Follow-up of CH11-reactions (#2192, PR #2195).

**Why.** Two release findings from #2195's combined review. (1) `reactionForm` takes the quote greedily, so an owner text such as `Liked "a" and "b"` parses as one reaction to `a" and "b` and is not delivered as chat (#2201). (2) A form outside the fixed list (British `Emphasised "…"`, emoji `Removed a 👍 from "…"`) fails the parse and reaches the agent as chat with the quoted box text raw, including an approval request's ID and any code (#2202; CH-3: request codes never reach the agent).

**Requirements:** CH-11 (with CH-3 for the code that must not reach the agent).

**Change.** `broker/owner/reaction.go`: (a) `parseReaction` refuses a quote that holds a quote mark (straight or curly), so the text is chat; (b) the list gains `emphasised`, `removed an emphasis from`, `removed an exclamation mark from`, and `removed a <emoji> from`; (c) `Channel.readReaction` wraps `parseReaction`: when that fails, a text shaped `<short lead-in> "<quote>"` whose quote matches a recent text to the owner that is an approval request or carries a code is read as a reaction of kind `reacted to` (the "(not shown)" event), so the raw box text never reaches the agent. `channel.go` calls `readReaction` where it routes owner text. Anything else stays chat.

**Acceptance tests:** `broker/owner/reaction_test.go::TestReactionFormatsAreAFixedList` (new pass and fail fixtures), `::TestUnlistedReactionFormsNeverShowACodedText`, `::TestOwnerTextWithInnerQuotesIsChat`.

**Guard files:** none.

**Out of scope.** #2196 (tell the guest its reaction was refused): it lives in `broker/cmd/agentosd/evidence.go` or `broker/guest/plane.go`, outside this scope; it stays queued. Qualification of the forms the owner's phones send (LOOP-10).

**Scope:** `broker/owner/reaction.go`, `broker/owner/reaction_test.go`, `broker/owner/channel.go` (the one call site), `broker/owner/ASSUMPTIONS.md`, this brief.

**Usage estimate:** 60k tokens.
