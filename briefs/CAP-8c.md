# CAP-8c: Worker follow-ups (#150): layer cap, delete-only commands

Board section: Backlog refill (2026-10-05).

Worker follow-ups from the #150 lenses: over its layer cap, let a worker run delete-only commands so an agent can shrink it in place, with snapshots and forks still refused (potency R1, UX option b; needs a security ruling on what counts as delete-only); refuse `worker_create`, `worker_fork` and `worker_rollback` while STOP holds (security R1, optional)

**Needs:** CAP-8b merged

**Gate:** lenses

**State on the board before the 2026-10-08 index split:** building (Next build item D)
