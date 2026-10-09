# UPD-a: Update apply, broker side

Board section: Backlog refill (2026-10-05).

Update apply, broker side (UPD-1, UPD-6): a journaled `meta.update.apply` intent with a rollback point that hands a verified release to the image's A/B activator (P2-1, behind an interface, faked in tests); applied only outside a call, accepted work and the owner's excluded quiet hours; a fallback never rewinds revocations, spent budgets, deletions or known external effects (state that lives outside the image)

**Needs:** P3-5, W5b; P2-1 for real activation

**Gate:** lenses (security: update path)

**State on the board before the 2026-10-08 index split:** merged (#133)
