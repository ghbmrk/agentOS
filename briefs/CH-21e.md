# CH-21e: Agent text asking for a code is withheld; welcome-text code line

Board section: Backlog refill (2026-10-05). Part of CH-21 (briefs/CH-21.md); SPEC CH-21, A14.

The broker withholds and journals agent text that asks for a code or reproduces the reply grammar; the welcome-text code line.

**Needs:** CH-21b

**Gate:** lenses (security first: V1, V2)

**Duties** (L3 on #462, point 1; V7 in `broker/voice/ASSUMPTIONS.md`): `TestPendingListIsNotStale` only catches a stale entry, so this package does each of these and tests it:
- Remove `owner` from the `pending` map in `broker/voice/voice_test.go`.
- Remove `owner.AgentPrefix` (`broker/owner/channel.go`) together with the withhold check; the prefix is the only structural broker/agent marker until then.
- Drop the "AgentOS: " signature from the recovery texts (`broker/recovery/owner.go`; LATER CH-21c f2).
