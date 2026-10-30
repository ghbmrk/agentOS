# CH21-no-prefix: drop the "Agent: " label once the broker-shape check runs on every agent text and fold

Work item: #2189. Board section: Human-native texting (spec #2157, D-127). Tier A (risk_tier.py: broker/owner, broker/control and broker/cmd are A), so the strongest model builds and L3 plus lens review apply. Row 7 of dispatch 2026-10-17-2000 said B; the code paths make it A.

**Goal.** CH-21: agent text carries no prefix once the check is in force; the check withholds the reply-options footer, control-word-with-request-ID shapes, and text opening like a broker request (a request-ID token followed by ":"). Failure path: without the prefix "R7K2: your agent wants to send..." reads as a broker approval; with it kept, every reply starts "Agent: ".

**Requirement IDs:** CH-21, CH-12.

**Unblocked.** #2181 closed; the fold check landed with CH-21e (#3916, merged), and UX3-7 (#993/#3986) keeps held text. #3916's reviews added four items to this row (issue comments 6505445831, 6505522087, 6505574025).

**Change.**
1. `owner.VoiceShaped` (wrapped by `voice.WouldHold`) gains: a line opening with a request-ID-shaped token and ":"; UNLOCK or RESUME with a challenge; one-word vocabulary terms split by punctuation or spaces; "digit" (the adversarial set, HLD-5). The footer and control word with request ID were already there.
2. The CH-19 and CH-21 checks run on each agent text joined to the agent's texts since the owner's last message (CH-12), and on the whole reply before `cmd/agentosd` `sendSplit` splits it.
3. `grants/gate.go`'s five `Inform` texts quote agent-derived request text through a check (`informQuote`).
4. Remove `owner.AgentPrefix`; `agentText` runs the checks itself, so no path sends agent text unchecked. Reaction recognition moves from the prefix to a recorded `agent` flag. Callers that budgeted for the prefix (`corpus/plane.go`, `question.MaxRendered`, agentosd `textRoom`) drop it. A question's text opens "Question Q101: ", not "Q101: ", since the new opening shape would hold it. `voice`'s `pending` keeps `owner` for its remaining third-person literals.

**Acceptance tests** (each fails on main): `broker/voice/shapes_test.go::TestCH21HoldsRequestIDColonOpening`, `TestCH21HoldsFooterAndControlWordShapes`, `TestCH21HoldsTheAdversarialSet`, `TestCH21NewShapesKeepOrdinaryText`; `broker/owner/noprefix_test.go::TestCH21NoPrefixWhenCheckRuns`, `TestCH21AgentTextIsNeverUnchecked`, `TestCH21JoinedTextsAreChecked`, `TestCH21AgentTextKnownByRecordNotWords`; `broker/cmd/agentosd/evidence_test.go::TestCH21RoomHasNoPrefixBudget`, `TestCH21WholeReplyCheckedBeforeSplit`; `broker/grants/informquote_test.go::TestCH21InformQuotesNoAgentShape`; `broker/question/voice_test.go::TestCH21QuestionTextsPassTheCheck`. The old `TestCH21PrefixKeptWhenCheckMissing` has no case to test: the check runs unconditionally in `agentText`.

**Scope:** `broker/voice/`, `broker/owner/` (channel.go, pacer.go, reaction.go, autoreply.go, converse.go, keep.go, voicecheck.go and tests), `broker/grants/gate.go`, `grant.go` and a test, `broker/corpus/plane.go` and test, `broker/question/question.go` and tests, `broker/cmd/agentosd/evidence.go` and tests, ASSUMPTIONS.md of each touched package, this brief. Not main.go or setup.go.

**Dependencies:** after #2250 merges; #2181; after CH12-ucs2, CH15-chat-window and OWN4-ack (evidence.go). D-111 against #2180 (merged), #2181.

**Usage estimate:** medium (about 100k); split corpus/question callers off if over.
