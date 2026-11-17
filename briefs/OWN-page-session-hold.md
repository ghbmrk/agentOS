# OWN-page-session-hold: owner-set hold size with MaxInbox to match, and code hygiene for a code mid-message

Board section: Defects and later findings on surviving packages. Work item #5187 (release findings of the #5185 reviews: L3 6747877751, Security 6747866657).

**Problem:** (1) `owner.Config.HoldSegments` (`broker/owner/channel.go`) is a field nothing sets, though CH-14 says the hold bound is owner-set, and `localapi.MaxInbox` (64, `broker/localapi/localapi.go`) caps the page's run lists, so a hold larger than 64 messages would refuse every tap as stale. (2) A code-generator code in the middle of a locked message, not at its end, is held and reaches the model when the owner taps it (CH-18).

**Requirements:** CH-14 (owner-set bound), CH-18.
1. The hold bound has an owner-set value with a stated maximum, and `MaxInbox` is derived from (or checked against) that maximum, so no settable hold exceeds what one tap can carry.
2. A held message carrying a code anywhere in its text has the code stripped before it reaches the agent, or is shown pointer-only on the Inbox page (the CH-14 pointer from OWN-page-session-checks). Recommendation: strip, reusing the channel's existing code matcher, since pointer-only would hide the rest of the owner's own text.

**Scope:** `broker/owner/channel.go`, `broker/owner/waiting.go`, their tests, `broker/owner/ASSUMPTIONS.md`; `broker/localapi/localapi.go` and its test; `broker/localui` only for the setting's control and its test; this brief. The setting's persistence follows the existing owner config path; if that path is in `broker/cmd/agentosd`, wire it there as a separate serial step (D-111) and record it on the PR's Findings line.

**Acceptance tests:**
- `broker/owner`: `TestHoldAboveSixtyFourRunsFromThePage` (a hold set to the maximum, filled, still runs in one tap); catches `MaxInbox` below the settable bound.
- `broker/localapi`: `TestMaxInboxCoversTheLargestHold`; catches the two constants drifting apart.
- `broker/owner`: `TestHeldCodeMidMessageNeverReachesTheAgent` ("pay 123456 now", synthetic digits); catches the end-only strip.

**Guard files:** none.

**Dependencies:** after OWN-page-session-checks (#5184) merges (shared `broker/owner/waiting.go`).

**Tier / gate:** tier A (`broker/owner`, `broker/localapi`): L3 on the strongest model, lens screen, separate Security accept.

**Usage estimate:** one session, under 100k.
