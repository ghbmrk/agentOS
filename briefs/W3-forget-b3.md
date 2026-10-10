# W3-forget-b3: Promised done text survives a restart

Board section: Integration: wiring merged packages into the box. Part of W3-forget-b (briefs/W3-forget-b.md); SPEC CAP-3.

**Requirement IDs:**
- **CAP-3** (SPEC): deletion requests propagate. The owner is told when the forget is done; briefs/W3-forget.md holds the conditions from UX on #160: the reply goes out only after the save, and a failed save says the task was not forgotten.
- **UX-182-3** (UX lens on #182): a forget still retrying at shutdown texts its done text once the start-up replay (`replayForgotten`) finishes it.
- **#182 SHOULD 4** (L3 on https://github.com/ghbmrk/agentOS/pull/182): the notice owed after a failed save is also delivered after a restart. It rides W3-forget-b1's forget log.
- **Carried:**
  - the local Wi-Fi page lists older tasks (potency R2);
  - no backup-delete pointer in any text until P2-2w (UX).

**Needs:** W3-forget-b1

**Gate:** lenses (UX first); tier set by `tools/risk_tier.py` on the diff, expected B.

**Scope:** `broker/cmd/agentosd/forget.go` and `learn.go` (owed-text state and replay), the local page's task list, their tests and ASSUMPTIONS.md.

**Estimate:** under 100k tokens, Sonnet 5.5 if tier B (strongest model if the diff reaches the forget log's recovery files, tier A).
