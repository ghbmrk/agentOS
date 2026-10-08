# SR2-3s: Step snapshots that fail are not silent

Board section: Backlog refill (2026-10-05).

Step snapshots that fail are not silent (REV-1; security R1 on #174): `guest/plane.go` only logs a failed step snapshot, so a layer too deep or over its cap loses its rollback points unseen. The agent's next tool result says the step snapshot failed and why (fixed text, no host path), and STATUS carries one line while a machine's steps keep failing

**Needs:** SR2-3i

**Gate:** security check

**State on the board before the 2026-10-08 index split:** in review (#179, stacked on #174)
