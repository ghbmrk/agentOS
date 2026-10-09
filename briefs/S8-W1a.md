# S8-W1a: Inventory credential-bearing tool surfaces before worker qualification

Board section: Phase 0: harness and risk spikes.

**Source draft:** [#262](https://github.com/ghbmrk/agentOS/pull/262) (Codex): `docs/security/provider-worker-feasibility.md`, `provider-worker-isolation.md`, `provider-worker-surfaces.csv`.

Before S8-W1 fixes the image for worker-held custody, list every surface through which a provider worker's tools can reach a credential, with the isolation each needs. S8-W1 consumes this inventory; it does not by itself qualify any route.

**Requirements:** CRED-5, A14 (inventory only; claims no coverage).

**Scope:** the three `docs/security/` files above. Recheck every row against current main (the draft is far behind) and cite source anchors at a fixed commit.

**Acceptance:** each CSV row names the surface, the credential reachable, the current control and the gap; the isolation doc maps each gap to an S8-W1 step or a LATER line. doclint clean.

**Needs:** S8

## Delivery

Builder model: Sonnet (risk tier C; PILOT-S). Write or keep the failing test first, then the smallest change; one package per session. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening the PR; if it prints a higher tier than C, stop and hand off. Estimate/checkpoint: 15k tokens, not a ceiling (OPERATING §5). Start from current main, not the draft's base: reuse the draft's diff where it still applies and credit the PR in the body; leave the draft open (Mark, 2026-10-09).
