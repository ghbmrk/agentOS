# CH15-chat-window: 30-minute owner-set open-chat window for unpaced replies

Work item: #2193. Board section: Human-native texting (spec #2157, D-127). Tier A (risk_tier.py: broker/owner, broker/control and broker/cmd are A), so the strongest model builds and L3 plus lens review apply. Row 7 of dispatch 2026-10-17-2000 said B; the code paths make it A.

**Goal.** CH-15: a task chat is open from an owner message that reaches the agent until 30 minutes (owner-set) after the owner's last such message; agent replies in it skip pacing and quiet hours. Today (59eb45d) `Converse` is bound to a pending owner message (#2159), not a window: a second reply 5 minutes later, a follow-up finding, goes through `Notify` and can be held.

**Requirement IDs:** CH-15.

**Change.**
1. `broker/owner`: chat-window state, opened/extended by each owner message that reaches the agent (`Channel` method called from the owner-message delivery path), expiring at last-owner-message + window.
2. Owner setting for the length: a new pacer setting form beside QUIET/TEXTS in `pacer.go` (`pacingForms`, `settings`), default 30 minutes, bounded (e.g. 5 to 240), persisted like the other pacing settings.
3. `Converse` (or the agent-reply call that precedes it) accepted while the window is open without a pending-message binding; unpaced, uncounted, quiet hours not applied. Outside the window a reply is a push and goes through `Notify` as now. Secret-shaped text still becomes the CH-19 pointer.
4. `broker/cmd/agentosd/evidence.go` routes an agent reply to `Converse` when the window is open.

**Acceptance tests** (new, each fails on main): `broker/owner/converse_test.go::TestCH15WindowOpenRepliesUnpaced` (second reply 5 min later, in quiet hours with the allowance spent, goes at once), `TestCH15WindowEdge` (sent at 29:59, held at 30:01; a new owner message re-opens), `TestCH15WindowSettingBounds`; `broker/cmd/agentosd/converse_test.go::TestCH15AgentReplyInWindowIsConversation`.

**Scope:** `broker/owner/converse.go`, `broker/owner/pacer.go`, `broker/owner/converse_test.go`, `broker/owner/settings_test.go`, `broker/owner/ASSUMPTIONS.md`, `broker/cmd/agentosd/evidence.go`, `broker/cmd/agentosd/converse_test.go`, this brief. Not main.go or setup.go. #2251 (spec text for quiet hours in CH-15) is spec only; read it first.

**Dependencies:** after CH12-ucs2 merges (same files). D-111 against #2184. Confirm G1 scope as in CH12-ucs2.

**Usage estimate:** medium (about 100k).
