# Arbitrator loop

Reconciles the three lens loops so their proposals compound instead of trading off:

| Lens | Asks | Home |
|---|---|---|
| Security | Can this be abused, leaked, or escalated? | `reviews/security/` |
| Potency | Does the spec limit capability without need? | `reviews/potency/` |
| UX | Is onboarding and everyday use low-effort for the owner? | `reviews/ux/` |

**Cadence:** weekly, Mondays after the lens loops (they run ~08:52 Eastern; this runs 10:41 Eastern). Each run reads what the lenses proposed or merged since the last arbitrated commit. It stays quiet when nothing conflicts.

## Per-PR gate (Mark, 2026-10-04)

Every AgentOS feature or addition goes through the three lenses and the arbitrator before it merges, not only the weekly run:
1. The PR reviewer sends the PR to the security, potency, and UX loops.
2. Each lens reviews on demand, in proportion to the PR's size: a small PR gets a one-line sign-off. Each replies to the reviewer with a sign-off or blocking findings.
3. Once all three have answered, the arbitrator reconciles any conflicts using the method below, then tells the reviewer the PR is clear, or sends Mark the real tradeoff.

This gate and the potency/UX/security tradeoff format apply only to OS work: the spec, design, and code. Other communication with Mark stays plain.

## Method

1. **Collect.** Every open lens proposal (PR or review file), plus merged spec changes since the last run.
2. **Cross-check.** Score each proposal on the other two lenses: improves, neutral, or costs. A proposal that is neutral or better on all three passes through untouched.
3. **Redesign, don't split.** For each cost, look for a design that removes it rather than a midpoint. The usual levers:
   - move the check from the owner to the broker (a deterministic predicate over verified data costs the owner nothing; precedent: ADP-9 pre-allowances gave silence, safety and power at once);
   - make the effect reversible (REV-3) so it no longer needs a gate;
   - scope by verified data, not by time or by blanket prompts;
   - make the safe path the shortest path.
4. **Decide whenever no lens gets meaningfully worse** (Mark, 2026-10-04). Only a real tradeoff, where some lens loses, goes to Mark: one plain line, a recommendation, and the potency, UX, and security effects, sent to the project coordinator, which asks him in the project chat. Never ask him in a thread. Work continues on the recommendation while he decides.

## Hard constraints (no trade may weaken)

- **Credentials never reach the model** (Invariant C, CRED-1..7, ARC-1).
- **Irreversible effects are always gated** (REV-2): by a code, a broker-checked pre-allowance (ADP-9), or STOP-able journaled intent; never by agent judgment.

Everything else, including defaults, tiers, and timeouts, is tradable when the trade makes all three lenses better off.

## Output per run

`YYYY-MM-DD-arbitration.md`: a cross-lens matrix, each conflict with its resolution and why it dominates, forks escalated, and steering notes for each lens. Spec changes go in an L1 spec-diff PR that Mark merges.

## Last arbitrated

| Run | main at | Inputs | Arbitration |
|---|---|---|---|
| 0 | e841b78 | loop set up | — |
| 1 | e841b78 | PRs #8, #9, #11, #12 | [2026-10-04](2026-10-04-arbitration.md) |

## Per-PR log

| PR | Lens verdicts | Conflict | Resolution | Outcome |
|---|---|---|---|---|
| #15 (spec v0.12) | Security: block (HW-5a signer). Potency: sign-off. UX: block (OP-8 extension). | OP-8 extension: UX wants it now; potency wants it later, with a daily ceiling | Extend one task by code-generator code, within the overall cap and an owner-set daily ceiling, neither raisable by that reply | Clear once the blockers land |
