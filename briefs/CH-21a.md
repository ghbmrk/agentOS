# CH-21a: First-person voice: lint test and tier-B sweep

Board section: Backlog refill (2026-10-05). Part of CH-21 (briefs/CH-21.md); SPEC CH-21, A14.

The ratchet and the first sweep. A new `broker/voice` test parses every non-test Go file under `broker/` and fails on a string literal with a third-person self-reference ("the box", "this box", "the agent", "Agent:"), except in packages still listed as pending; each later part deletes its packages from that list. Sweep to the first person (unsigned, "I"/"my") the owner-facing literals in `loops`, `maintain`, `question`, `attention`, `follow`, `recalltool` (about 45 strings, tier B). Third-party texts, calls and ADP-12 disclosures keep "<name> (<owner>'s AgentOS assistant)". Strings in `broker/browser`, `broker/desktop` and `broker/adopt` belong to claude2's lane and are skipped (none found on main).

**Needs:** CH-12s

**Gate:** lenses (security first: V1, V2)

**Scope:** `broker/voice/` (new), the six packages above and their tests, their ASSUMPTIONS.md.

**Estimate:** under 150k tokens, Sonnet 5.5 (tier B: new package and B packages only).
