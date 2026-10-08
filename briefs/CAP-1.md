# CAP-1: Speculative parallelism

Board section: Backlog refill (2026-10-05).

Speculative parallelism (CAP-1; A15 cloud part): fork N workers with N from measured free memory through admission, keep the winner and discard the rest, frontier spend reserved per fork; a VM test drives 8 workers within RES-2

**Needs:** CAP-8

**Gate:** lenses

**State on the board before the 2026-10-08 index split:** building (Next build item D)
