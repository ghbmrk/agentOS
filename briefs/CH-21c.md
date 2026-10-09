# CH-21c: First-person voice: owner-page and recovery texts

Board section: Backlog refill (2026-10-05). Part of CH-21 (briefs/CH-21.md); SPEC CH-21, A14.

Sweep of the tier-A packages `localui`, `recovery`, `grants`, `change`, `owner`, `modem`, `clock`, `apply`, `update`, `workers`, `guest`, `mail` (about 85 strings); remove them from the lint test's pending list. May be split further by package when its brief is written.

**Known strings (release, UX and L3 on #381):** "The box isn't answering right now." (`localui/paused.go`) and the `pausedBy` fallback "the box" ("Paused by the box.", `grants/resume.go`).

**Needs:** CH-21a

**Gate:** lenses (security first)
