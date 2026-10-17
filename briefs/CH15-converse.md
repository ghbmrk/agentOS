# CH15-converse: agent replies to the owner are conversation, not paced

Board section: Owner channel. Source: Mark's "speed of response important" in the human-native texting thread (2026-10-17), Decisions card "Fix + redesign". Defect of W5-Dc-r1: QH-9 re-pointed callers to classes and the agent's replies became `ClassAgent`, held in quiet hours and counted against the hourly allowance.

**Why.** CH-15 says conversation (replies in an open task chat and results the owner asked for) is not paced; pacing and quiet hours apply only to unasked texts. Today an agent reply to an owner text goes through `Notify`, so at 23:00 or with the hour's texts spent the owner's question waits for morning. Texting a person does not behave that way, and it is the largest speed cost on the owner path.

**Requirements:** CH-15, CH-19.

**Change.** `owner.Channel.Converse` sends the agent's reply at once and uncounted, like the channel's own replies to owner texts (`Run` control replies), after the same `agentText` shaping as `Notify` (Hidden pointer for secret-shaped text, AgentPrefix otherwise). `evidence.attach` wires the reply outbox to it. Every outbox reply is bound to one pending owner message (guest `POST /owner/reply`: first answer only, 404 unknown, 409 different hash), so the owner's own texts bound how many go.

**Acceptance tests:** CH-15, CH-19: `broker/owner/converse_test.go::TestConverseIsNeverPaced` (new); CH-15: `broker/cmd/agentosd/converse_test.go::TestAgentReplyIsConversation` (new). Both fail on main's wiring (reply held at 23:00 with the allowance spent).

**Guard files:** none.

**Out of scope.** `broker/cmd/agentosd/pacing_test.go` (#2127 edits it; its `TestCallersUseTheirClass` comment and agent-reply assertion are updated after #2127 merges); pacer.go, channel.go, autoreply.go (#2127); splitting long replies (separate package).

**Scope:** `broker/owner/converse.go` (new), `broker/owner/converse_test.go` (new), `broker/cmd/agentosd/evidence.go`, `broker/cmd/agentosd/converse_test.go` (new), `broker/cmd/agentosd/ASSUMPTIONS.md`, `briefs/CH15-converse.md`.

**Usage estimate:** 80k tokens.
