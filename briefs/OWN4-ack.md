# OWN4-ack: first-person "On it." after 20 s with no reply, replacing the waking-up hold line

> Note: the default wait is now 5 s (D-134); the 20 s below is the original package.

Work item: #2191. Board section: Human-native texting (spec #2157, D-127). Tier A (risk_tier.py: broker/owner, broker/control and broker/cmd are A), so the strongest model builds and L3 plus lens review apply. Row 7 of dispatch 2026-10-17-2000 said B; the code paths make it A.

**Goal.** OWN-4: when no reply has gone out 20 s (owner-set) after an owner task message reached the box, the broker sends one fixed first-person acknowledgement ("On it."), at most one per owner message, none once a reply has gone out, no agent content, counts as conversation (CH-15). On main (sleeper.go:49,56) the line is "One moment, your agent is waking up." after 15 s, third person, only on a cold wake; a warm agent that takes 40 s gives the owner silence.

**Requirement IDs:** OWN-4, CH-15.

**Change.**
1. One timer per owner task message, armed on delivery (cold or warm), cancelled by any reply for that message; fires the fixed text once, through `Converse` so it is unpaced and uncounted.
2. `broker/cmd/agentosd/sleeper.go`: remove `holdLine` and its once-per-sleep timer; `OwnerMessage` arms the ack timer instead. Update `defaultHoldAfter` to 20 s as the default `AckAfter`.
3. Owner setting for the delay: a pacer setting beside QUIET/TEXTS (`ACK 5-120` seconds, or off is not allowed; OWN-4 says the ack exists), default 20 s.
4. `evidence.go`: report "a reply went out" to cancel the timer; the ack text is not a reply and does not cancel the next message's timer.

**Acceptance tests** (new, each fails on main): `broker/cmd/agentosd/sleeper_test.go::TestOWN4AckWarmAgentAt20s`, `TestOWN4AckOncePerMessage`, `TestOWN4NoAckAfterReply`, `TestOWN4AckReplacesHoldLine` (no "waking up" text anywhere), `TestOWN4AckCarriesNoAgentContent`; `broker/owner/settings_test.go::TestOWN4AckDelaySetting`. Existing sleeper hold tests (PE7 conditions 14, 15) are updated, not deleted: the new cases keep their intent.

**Scope:** `broker/cmd/agentosd/sleeper.go`, `broker/cmd/agentosd/sleeper_test.go`, `broker/cmd/agentosd/evidence.go`, `broker/cmd/agentosd/evidence_test.go`, `broker/owner/converse.go`, `broker/owner/pacer.go`, `broker/owner/settings_test.go`, `broker/owner/ASSUMPTIONS.md`, this brief. Not main.go or setup.go; if `Hold` is wired in main.go or setup.go, stop and hand the one-line wiring change to the coordinator (#2241 and #2015 touch them).

**Dependencies:** after #2250 merges, and after CH15-chat-window (evidence.go, converse.go). G1 is off (D-128); G2 allows these packages.

**Usage estimate:** medium (about 100k).
