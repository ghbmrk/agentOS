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
| #18 (P1-1 journal) | UX: sign-off. Security: 2 blockers. Potency: 1 blocker. L3: 2 blockers. | None; all additive | Note: an OP-2 refused duplicate is shown to the owner as held behind the unresolved intent | Clear once the fixes land |
| #19 (P1-2 broker skeleton) | UX: 1 blocker. Security: 2 blockers. Potency: 1 doc blocker. L3: 2 blockers. | None (the STOP hint still delivers the message to the agent) | The STOP hint is rate-limited as a reply to unauthenticated messages (security finding 18, CH-15) | Clear once the fixes land |
| #21 (P1-3 vault, credentialed egress) | UX: sign-off. Potency: sign-off (OP-8 before P1-7). Security: 2 blockers. L3: 4 blockers. | Relay denies provider-side tools (security) vs losing provider search and fetch (potency) | Label-aware deny: provider tools allowed only for REV-5 `public`; private or unknown is denied. Self-heals when labels reach the proxy | Clear once the fixes land |
| #22 (P1-5 owner channel) | UX: 1 blocker. Potency: 2 blockers. Security: 3 blockers. L3: 5 blockers. | O4 lock after wrong codes: security (pause) vs UX (throttle) vs potency/L3 (spoofer keeps it armed; spoofed STOP deadlock) | Challenge-gated attempts: after lockout, only replies carrying a fresh texted challenge count or consume a slot; spoofers can neither trip nor hold the lock; fixed 24h bound for challenge-bearing guesses | Clear once the fixes land. Correction: the narrowed commitment filter was not equivalent to Mark's D2 version, so his full set is restored (any date or time; the six phrases in any person). Calendar-verified dates sent to Mark as a separate tradeoff |
| #23 (P1-4 agent-machine lifecycle) | UX: sign-off. Potency: sign-off. Security: 2 blockers. L3: 3 blockers. | None (the upper-layer quota could cap potency) | Quota sized from measured free space after RES-4 reserves, as admission; at the quota, the next step gets a clear error and nothing is truncated; a merge delete-vs-edit is an explicit conflict | Clear once the fixes land |
| #24 (P1-7 OpenClaw guest) | UX: 2 blockers. Potency: 1 blocker. Security: 1 blocker plus conditions. L3: 4 blockers. | None (flood caps judged negligible for potency) | Labels fail closed (unknown means private); snapshots coalesce under rate limits instead of refusing calls; output reservation sized to max_tokens and reconciled at once; guests never submit meta.* | Clear once the fixes land |
| #25 (P2-7 model router) | UX: sign-off. Security: sign-off (R2). Potency: 1 blocker (caching). L3: 4 fixes. | Metering max(reported, bytes/4) (security) would charge cached prompts at full price (potency) | Provider usage read on the broker's own connection is authoritative when present (cache-aware); the broker counts content when usage is missing or the stream is cut off; output reserved up front. OP-8 one-line amendment via #15. R8: pre-ticked "use for private tasks" at onboarding is an auto-decide (P2-2) | Clear once the fixes land |
| #28 (ADP-11 calendar acceptance, spec) | Potency: sign-off. UX: 1 blocker (hold lifecycle). Security: 2 wording fixes. | "Every recipient is a contact" (security) would prompt on group threads where the counterpart cc'd someone (potency) | Recipients must be a subset of the latest inbound message's participants, from a DMARC-authenticated contact sender; no added addresses. One hold rule: removed on matching invite or UNDO, expires otherwise, listed in the digest | Clear once the fixes land |
| #27 (grants and approval policy) | Potency: sign-off. UX: 1 blocker (GR9 coalescing). Security: 1 blocker (recipients shown in full). L3: 3 blockers. | GR10 restart: deny pending intents (PR, #22 ruling) vs re-issue after boot (UX) | Re-issue with fresh per-intent codes (old codes die), original expiry kept, OP-3 recheck at re-issue and execution, full lines with the original ask time, coalesced; supersedes the #22 deny-on-restart | Clear once the fixes land |
| #28 (ADP-2 organize verb, spec; Mark: "Yes - reversible", 2026-10-05 00:02) | Potency: sign-off. UX: 1 blocker (UNDO restores only unchanged items). Security: 2 blockers (target allowlist; sender-anchored alert guard). | The sender-anchored guard (security) would prompt on most retail/SaaS mail (potency, UX) | The guard applies only to hiding ops (archive, move out of the inbox, mark read): a hit prompts. Labelling still runs, and the message stays in the inbox, unread and listed in the digest | Clear once the refinement lands |
| #29 (P2-4a vault passphrase unlock) | Potency: sign-off. Security: 2 blockers (serialized, rate-limited Argon2; durable counter). L3: confirms the first (2.1 GB stacking). UX: 2 blockers. | Keeping the key pending after a wrong code (UX) vs CRED-8 "discard if the code fails" | Pending until expiry or cap exhaustion: neutral for security with a durable 3-per-24h cap; one-line CRED-8 amendment via the next spec PR. Nonce-bound /confirm is blocking now: unnonced attempts neither count nor consume the window | Clear once the fixes land |
| #30 (P2-4c vault verify) | Security and UX: blockers. L3: B1–B4. | B1: the vault rate limit refused genuine codes while O4 challenge mode never tripped | Counted bucket 20/10 min (above WrongToChallenge 10, so O4 trips first); separate silent bucket 10/10 min that never refuses counted checks; flood alert required (at most 1 per 24 h, plus digest); the verify last step persisted with #29's durable counter | Clear once the fixes land |
| #32 (P2-2 Owner Card and local UI) | L3: 3 blockers. Security: 2 blockers. UX: 1 blocker. Potency: CAP-9 (pre-ticked per #25 R8). | Per-sign-in and per-wrong-attempt texts (security) vs owner noise (UX); 10 vs 24 per 24 h | Setup bound to the pairing device (blocking; re-pair from that device or by a setup-secret restart). Sign-in texts coalesced to at most 1 per hour. 24 per 24 h kept (negligible odds difference). Wrong-attempt alert on the first attempt per 24 h and at the bound, plus the digest | Clear once the fixes land |
