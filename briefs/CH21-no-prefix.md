# CH21-no-prefix: drop the "Agent: " label once the broker-shape check runs on every agent text and fold

Work item: #2189. Board section: Human-native texting (spec #2157, D-127). Tier A (risk_tier.py: broker/owner, broker/control and broker/cmd are A), so the strongest model builds and L3 plus lens review apply. Row 7 of dispatch 2026-10-17-2000 said B; the code paths make it A.

**Goal.** CH-21: agent text carries no prefix once the check is in force; the check withholds the reply-options footer, control-word-with-request-ID shapes, and text opening like a broker request (a request-ID token followed by ":"). Failure path: without the prefix "R7K2: your agent wants to send..." reads as a broker approval; with it kept, every reply starts "Agent: ".

**Requirement IDs:** CH-21, CH-12.

**BLOCKED (do not start):** needs #2181 (CH12-fold-wire: the checks run on both CH-12 folds), which waits on a G1 list change for `broker/voice`. Start only when #2181 is merged and `broker/voice` is writable under `tools/g1_scope.txt` (or the freeze is off).

**Change.**
1. `broker/voice/voice.go` `WouldHold` gains the three shapes: reply-options footer, control word plus request ID, a leading request-ID token followed by ":". Matched against the folded text per #2181.
2. Remove `owner.AgentPrefix` from `agentText` (`broker/owner/pacer.go`) only when that check runs on every agent text and every fold; keep the prefix otherwise.
3. Update callers that budget for the prefix: `broker/owner/channel.go` (`AgentPrefix`), `broker/corpus/plane.go:55`, `broker/question/question.go:56`, `broker/cmd/agentosd/evidence.go:231` and `sendSplit`; `reaction.go:144,147` (prefix-based text recognition) moves to the recorded-ID path.

**Acceptance tests** (new, each fails on main): `broker/voice/voice_test.go::TestCH21HoldsRequestIDColonOpening`, `TestCH21HoldsFooterAndControlWordShapes`; `broker/owner/pacer_test.go::TestCH21NoPrefixWhenCheckRuns`, `TestCH21PrefixKeptWhenCheckMissing`; `broker/cmd/agentosd/evidence_test.go::TestCH21RoomHasNoPrefixBudget`; `broker/owner/reaction_test.go` case that a prefixless agent text is still recognised as the agent's.

**Scope:** `broker/voice/`, `broker/owner/channel.go`, `broker/owner/pacer.go`, `broker/owner/reaction.go` and tests, `broker/corpus/plane.go`, `broker/question/question.go`, `broker/cmd/agentosd/evidence.go` and test, ASSUMPTIONS.md of each touched package, this brief. Not main.go or setup.go.

**Dependencies:** #2181; after CH12-ucs2, CH15-chat-window and OWN4-ack (evidence.go). D-111 against #2180 (merged), #2181.

**Usage estimate:** medium (about 100k); split corpus/question callers off if over.
