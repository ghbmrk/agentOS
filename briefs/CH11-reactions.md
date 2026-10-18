# CH11-reactions: recognise owner reactions; refuse agent reactions until qualification

Board section: Human-native texting (spec #2157, D-127). Work item: #2192.

**Why.** A phone sends a tapback to a box texted by SMS as a text, `Liked "Reply YES R7K2 to send"`. Read as ordinary text it carries YES and a request ID, and today it reaches the agent as a raw task message. Texting the box should feel like texting a person: a reaction is acknowledged, never acted on as words.

**Requirements:** CH-11 (with CH-3 and CH-14 for when it reaches the agent).

**Change.** `broker/owner/reaction.go` parses a fixed list of reaction forms before any control word in `Channel.routeLocked`; matches the quote against a bounded window of recent texts to the owner (recorded in `watchedLine`); words a reaction event for the agent (kind plus the matched text, codes redacted, approval requests not shown, or "none matched"); sends a one-line pointer when the marked text expects a reply; holds a reaction while locked, with RUN delivering its event. `control.Handler.Event` delivers the event as task chat goes, past the Settings and Answer hooks (the digest gate keeps `Deliver` inside `Handler.deliver`). `Converse`, `Notify` and `NotifyNow` refuse agent text in a reaction form.

**Acceptance tests:** `broker/owner/reaction_test.go::TestReactionFormatsAreAFixedList`, `::TestReactionToAnApprovalIsNeverAnApproval`, `::TestControlWordsInAReactionAreNotCommands`, `::TestReactionsMatchRecentTexts`, `::TestReactionWhileLockedIsHeldAndRunDeliversTheEvent`, `::TestReactionToARunOfferPointsToRun`, `::TestAgentReactionsAreRefused`; `broker/control/event_test.go::TestEventGoesAsTaskChatDoes` (all new).

**Guard files:** none.

**Out of scope.** Telling the guest synchronously that its reaction text was refused (the outbox path in `cmd/agentosd/evidence.go` only logs it; evidence.go is held by #2177): a follow-up. Qualification of the forms the owner's phones send (LOOP-10).

**Scope:** `broker/owner/reaction.go`, `broker/owner/reaction_test.go` (new), `broker/owner/channel.go`, `broker/owner/autoreply.go`, `broker/owner/converse.go`, `broker/owner/pacer.go`, `broker/owner/ASSUMPTIONS.md`, `broker/control/handler.go`, `broker/control/event_test.go` (new), this brief.

**Usage estimate:** 120k tokens.
