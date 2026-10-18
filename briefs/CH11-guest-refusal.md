# CH11-guest-refusal: tell the guest its agent reaction was refused

Board section: Human-native texting (spec #2157, D-127). Work item: #2196 (release finding from #2195, CH11-reactions).

**Why.** CH-11 says the broker refuses an agent reaction, so the agent replies in text. `owner.Converse` refuses reaction-form agent text with `ErrAgentReaction`, but a guest's reply reaches it only later, from the guest plane's outbox, after `POST /owner/reply` already answered 204. `cmd/agentosd/evidence.go` then only logs the refusal: the guest believes its reaction reached the owner and may never reply in text.

**Requirements:** CH-11 ("until then the broker refuses an agent reaction, so the agent replies in text").

**Change.** The refusal is returned where the guest's other reply errors are: in the answer to `POST /owner/reply`, before the reply is stored or its message counted as answered.
- `broker/owner/agenttext.go` (new) exports `RefuseAgentText`, the same check `Converse`, `Notify` and `NotifyNow` run (`refuseReaction`), so the list of forms stays in one place.
- `broker/guest`: `Plane.CheckReplies(check)` sets a check run on a reply's text and summary before the store; a refusal answers 400 with the check's guest text and leaves the message pending. 400 is the status the guest bridge treats as final ("the same body can never pass"), so it does not retry the same reaction forever.
- `broker/cmd/agentosd/evidence.go`: `serve` sets the check on the plane (`owner.RefuseAgentText`). `main.go` is not touched (held by #2274, #2285).

**Acceptance tests:** `broker/cmd/agentosd/evidence_test.go::TestGuestReactionIsRefusedToTheGuest` (end to end through a real plane: a reaction-form reply answers 400 with the refusal, nothing is queued or texted, and a text reply to the same message then goes out); `broker/guest/refuse_test.go::TestReplyCheckRefusesBeforeTheStore` (new).

**Guard files:** none.

**Out of scope.** The guest bridge (`cmd/agentos-guest-bridge`) logs a 400 and moves on; asking the model again with the refusal is a follow-up. Replies a guest posted before `serve` sets the check still reach `Converse`, which refuses them as today.

**Scope:** `broker/owner/agenttext.go` (new), `broker/guest/plane.go`, `broker/guest/owner.go`, `broker/guest/refuse_test.go` (new), `broker/guest/ASSUMPTIONS.md`, `broker/cmd/agentosd/evidence.go`, `broker/cmd/agentosd/evidence_test.go`, this brief.

**Usage estimate:** 80k tokens.
