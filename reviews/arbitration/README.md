# Arbitrator loop

Reconciles the three lenses so their proposals compound instead of trading off:

| Lens | Asks | Home |
|---|---|---|
| Security | Can this be abused, leaked, or escalated? | `reviews/security/` |
| Potency | Does the spec limit capability without need? | `reviews/potency/` |
| UX | Is onboarding and everyday use low-effort for the owner? | `reviews/ux/` |

**When:** inside each batched lens screen, for the PRs in that bundle (docs/OPERATING.md §4, step 4). It stays quiet when nothing conflicts. Until 2026-10-07 it ran weekly after the lens loops; those runs are listed below.

## Method

1. **Collect.** The lens verdicts the screen just wrote for the bundle, plus any open spec-wide lens proposal.
2. **Cross-check.** Score each proposal on the other two lenses: improves, neutral, or costs. A proposal that is neutral or better on all three passes through untouched.
3. **Redesign, don't split.** For each cost, look for a design that removes it rather than a midpoint. The usual levers:
   - move the check from the owner to the broker (a deterministic predicate over verified data costs the owner nothing; precedent: ADP-9 pre-allowances gave silence, safety and power at once);
   - make the effect reversible (REV-3) so it no longer needs a gate;
   - scope by verified data, not by time or by blanket prompts;
   - make the safe path the shortest path.
4. **Escalate only real forks.** When no design dominates and the choice changes Mark's goal or an output he will notice, ask one question answerable in one word, with a recommendation. Everything else is decided here with the reasoning written down.

## Hard constraints (no trade may weaken)

- **Credentials never reach the model** (Invariant C, CRED-1..7, ARC-1).
- **Irreversible effects are always gated** (REV-2): by a code, a broker-checked pre-allowance (ADP-9), or STOP-able journaled intent; never by agent judgment.

Everything else, including defaults, tiers, and timeouts, is tradable when the trade makes all three lenses better off.

## Output

Per PR with a conflict, `YYYY-MM-DD-pr<N>.md`: the conflict, its resolution and why it dominates, and any fork escalated. A spec-wide run writes `YYYY-MM-DD-arbitration.md`: a cross-lens matrix, each conflict with its resolution and why it dominates, forks escalated, and steering notes for each lens. Spec changes go in an L1 spec-diff PR that Mark merges.

## Spec-wide runs

| Run | main at | Inputs | Arbitration |
|---|---|---|---|
| 0 | e841b78 | loop set up | — |
| 1 | e841b78 | PRs #8, #9, #11, #12 | [2026-10-04](2026-10-04-arbitration.md) |

## Records

Per-PR resolutions are the files `YYYY-MM-DD-pr<N>.md` in this directory, in filename order, with no run number. Each opens with a `Record:` line giving PR, package and head SHA; `tools/doclint.py` checks it on files dated 2026-10-09 or later. Nothing is appended to this README (DOC-4).
