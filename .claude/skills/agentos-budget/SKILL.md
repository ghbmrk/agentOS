---
name: agentos-budget
description: agentOS budget and session-cost rules. Load with the builder or reviewer skill, and before spawning sessions, choosing models, or handing off.
---

# Budget (reasons: OPERATING §1, §5)

Moved verbatim from CLAUDE.md (2026-10-17).

- The only hard limit is the subscription (usage credits off). Target: ~100% of the weekly limit used by each reset (Mark, 2026-10-04). ~14% a day is not a ceiling: "14% a day shouldn't be a ceiling. No ceiling as long as not wasteful" (Mark, 2026-10-13 12:40Z). Spend where the next unit of work has clear value, don't idle, and don't spend just because budget remains.
- Near a session-window limit, finish the current step cleanly; start heavy new work after the reset.
- Keep contexts small: brief + touched files. Summarize CI logs instead of pasting them.
- Cold starts cost most: on 5.5 models a cache write costs 40x a cache read. Per merged PR, minimise sessions started, wakes after >1h idle, model switches and compactions (OPERATING §1, §5).
- Pick the model at spawn; never switch models mid-session. A second opinion is a fresh session.
- A session past 150k that will idle over an hour writes a hand-off packet and stops watching. The coordinator routes; investigation goes to a thread.
- `.claude/settings.json` compacts at 200k tokens; don't raise it.
- Size each package so its brief is 20k tokens or less and it finishes under 150k; split it before starting otherwise.
- One package or one review per session. Start a fresh session with a hand-off packet of 20k tokens or less (OPERATING §5) rather than reviving a session over ~150k that sat idle more than an hour.
- Mechanical subagent work (search, log triage, wording sweeps, test scaffolding) passes `model: "haiku"` and stays under 100k tokens, above which Haiku costs 5x; use `"sonnet"` when it needs judgment. Reviews of security-critical paths keep the session's model.
- Sonnet pilot (OPERATING §5, 2026-10-08 to the 2026-10-13 reset): tier B and C builder sessions run on a Sonnet-class model, tier A on the strongest model. Run `tools/risk_tier.py` before opening the PR; on A, stop and hand off.
- Live state lives on GitHub: every review verdict comment ends with the PR's next step and the reviews still owed. A cold session starts from `handoff/CURRENT.md` (rebuild steps and standing decisions; updated only when a standing decision changes), then GitHub (OPERATING §5, §7).
- Read tool output narrowly (grep, tail, `go test -run`), never whole CI logs or large files. Send cross-session messages for decisions, blockers and hand-offs only; progress goes in the status checklist. Per thread, post one acknowledgement, one result and one blocker reply at most.
- Coordinators of chat-based projects follow the chat layout and coordinator cost rules in OPERATING §5 (D-094).
