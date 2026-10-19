# CH11-reaction-quote-gaps: close four reaction-quote leaks of request codes

Board section: Human-native texting. Work item: #2392. Follow-up of O45 (PR #2385); Security review comment 6253028757. **Tier A** (`broker/owner`). Run in one session with CAP3-held-forget-scope only if the first leaves room; both edit `reaction.go`, so do not run them in parallel (D-111). Open #2355 also touches `reaction.go`: start after it lands or closes.

**Why / failure path.** The owner taps back on a live request, or the phone cuts the quote short. The text goes to the agent as chat with part or all of the request's code (CH-3, CH-11).

**Requirements:**
- CH11-G1: a short quote (under `minQuote`, `reaction.go:173`) that is a cut of a guarded text is a reaction, live and after a restart (`Liked “YES <id> 56`, `Liked “...YES <id> 56`). A short quote of the agent's own unguarded text stays chat.
- CH11-G2: `normQuote` (`reaction.go:428-436`) trims repeated leading and trailing ellipses until stable, on the saved and incoming side.
- CH11-G3: a quote cut inside a code at both ends matches only through the `both` form of `maskedForms` (`reaction.go:373-385`).
- CH11-G4: guarded texts (live requests, box texts with a code) live apart from the 20-text cap (`recentWindow.add`, `reaction.go:243-249`), bounded by age and open requests; 25 more box texts do not push a live request out.

**Acceptance tests:** in `broker/owner/reaction_followups_test.go` (REQ: CH11-G1..G4)
- `TestShortCutQuoteOfARequestIsAReaction` (G1; live and after restart).
- `TestDoubledEllipsisQuoteIsAReaction` (G2).
- `TestQuoteCutAtBothEndsIsAReactionAfterARestart` (G3; fails with mutant `both := m`).
- `TestLiveRequestSurvivesTwentyFiveMoreBoxTexts` (G4; quote `Liked “…<code> or NO <id>`).

**Mutants:** `both := m`; trim ellipsis once; treat every short quote as chat; apply the 20-cap to guarded texts. Each fails a named test.

**Out of scope.** Task-keyed windows (CAP3-held-forget-scope).

**Scope:** `broker/owner/reaction.go`, `broker/owner/reaction_followups_test.go`, O45 in `broker/owner/ASSUMPTIONS.md` if the window rule changes, this brief.

**Usage estimate:** 70k tokens; checkpoint at 55k.
