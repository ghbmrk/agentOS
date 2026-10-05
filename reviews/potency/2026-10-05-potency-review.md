# Potency review 2 (spec v0.12 @ f797b7d)

**Scope:** what changed on `main` since run 1 (e841b78): 853 commits, SPEC.md v0.11 → v0.12 (+154/−53), spike S5 (interim) and S1/S2 kit results, DECISIONS.md, and the per-PR potency verdicts given since (#67 to #134, the W3 step 3 and PE7 designs). Open PRs #41, #132, #133 and #134 were read; none touches SPEC.md, so the new IDs below don't collide.
**Yardstick:** owner-minutes per accepted task (§1).
**Labels:** [Fact] verifiable · [Measured] from a spike or CI · [Inference] reasoned, untested · [Risk] needs a spike · **[Decision]** Mark's call.
**For the arbitrator:** every finding carries a potency / security / UX line. "Conflict" marks the ones where the lenses pull apart.

Findings marked **→ spec** have a SPEC.md edit in this PR (listed in the last section), committed after Mark's yes in the potency thread.

---

## Summary

| # | Cap found this week | Potency gain | Security cost | UX cost | Proposal |
|---|---|---|---|---|---|
| 1 | Capabilities switch off with only a log line: learning when memory is short (#114), the model builder with no image or grant (#126, #134), a box too small for the agent (#118), a security fix held by PINNED or ASK (#130), a provider refusing the line's sign-in (#116) | The owner can fix what they can see; nothing stays dead for months | None | One STATUS line and a digest line while it lasts | **No silent loss of capability** → spec OP-9 |
| 2 | RES-2's pool was a fixed 3.9 GB; the N95 really has about 3.5 GB [S1 kit arithmetic], and larger hosts got no more than the floor (#118, #124) | No OOM against inference on the floor; more parallel evaluation and builders on larger hosts | None (fail-closed on small hosts; HW-4 holds) | None | **Pool derived from the host, scaled by a CPU-bounded rule** → spec RES-2 |
| 3 | A box that is never free never applies a security fix, and PINNED/ASK hold one after a single notice (#130, #133) | Fixes land on busy boxes | **Gain** | One paced ask, only in that case | **Held security fixes surface** → spec UPD-9 |
| 4 | Implicit acceptance (PK2) yields no values, so recurring routines the owner never praises never compile (#119) | Turns the bulk of routine work into compilable evidence | None (explicit owner yes, same value path) | One paced question per recurring routine | **"Keep it as a skill?"** → spec CAP-5 |
| 5 | Forgetting a task would drop every skill whose evidence included it (#123, security C1 on #120) | A routine seen 20 times survives one forgotten instance | None (the forgotten data is gone either way) | Owner sees what a deletion changes | **Rebuild before remove** → spec CAP-3 |
| 6 | On boxes where the agent and one replay don't fit, learning never runs (#114) | About one candidate a night instead of none | **Conflict:** restoring a full-memory checkpoint becomes the agent's normal resume path (REV-1) | First message after a sleep waits for a restore | Evaluate while the agent sleeps (PE7) → later, after the security and arbitrator rulings |
| 7 | RES-2 allows one credentialed browser in 0.5 GB; S5 measured 165 MB PSS for the headless-shell executor on a fixture [Measured, S5] | Two or three logged-in accounts at once at the floor | None if each stays its own sandbox | None | Re-size after S5's live run → later |

Net effect [Inference]: 1–5 raise potency with no security cost (3 raises security too); 6 is the one conflict and stays with the arbitrator; 7 waits for measurement.

---

## Findings

### 1. Capabilities switch off silently (new OP-9)
[Fact] This week's reviews found the same pattern five times. A capability turns off because of the host, configuration, or a held decision, and the only trace is a log line: replay evaluation disabled when memory is short (#114), the model builder inert without an image (#134) or without `-builder-from` grants (W3-builder-tune), the agent refused at every launch on a too-small box (#118), a security fix held after one notice (#130), and a provider whose challenge the line can't answer (#116 PS1). Each was fixed locally with a STATUS line, after a lens caught it. The spec's "silence is never a decision" principle exists only in the review loops, not in the spec, so the next package will repeat it.
- **Proposal (OP-9):** anything off or unable to run gets one owner-worded STATUS line with the fix, repeated in the digest while it lasts. Owner choices are named once and listed, never alerted on.
- **Potency gain:** fixable conditions get fixed; the box doesn't pay for loops that can't adopt anything.
- **Security cost:** none.
- **UX cost:** one line per condition. Owner choices are not nagged about.

### 2. The agent-machine pool ignores the real host (RES-2)
[Measured, S1 kit arithmetic] An 8 GB N95 reports about 7680 MiB, leaving 3496 MiB after the floor budget, not the 3.9 GB RES-2 states. A fixed 4500 MB capacity let admission promise memory the box doesn't have, against inference and the browser (#118, now derived in code by PE6). In the other direction, HW-4 allows larger hosts to add throughput, but a fixed cap kept a 32 GB box at the N95's pool (#124).
- **Proposal (RES-2):** the pool is derived at start from reported memory less the other budgets; a host too small for the agent runs with the agent off and says so (OP-9); larger hosts grow the pool only by a rule also bounded by CPU cores (the #124 verdict proposes `max(4500, headroom + floor(cores/2) × OpenClawMB)`, capped by memory), checked by A2 so foreground latency is unchanged.
- **Potency gain:** no OOM losses at the floor; on an 8-core, 32 GB host about 4 concurrent machines instead of 2.
- **Security cost:** none; admission, preemption and headroom are unchanged (HW-4).
- **UX cost:** none.

### 3. Security fixes can be held indefinitely (new UPD-9)
[Fact] UPD-6 forbids applying during a call or accepted work, with no deadline (#133). PINNED and `SECURITY UPDATES ASK` give one notice (#130). A busy or inattentive box can stay unpatched with no further word.
- **Proposal (UPD-9):** after 24 h staged and unapplied for want of a free moment, one paced ask with the restart time and a "now or tonight" choice; fixes held by settings appear in every digest until installed or declined; ordinary releases never ask, and get a digest line after 7 days.
- **Potency gain:** fixes land.
- **Security cost:** none; **gain**.
- **UX cost:** one paced ask, only when a fix is stuck; a digest line while one is held.

### 4. Implicit acceptance can't compile (CAP-5)
[Fact] Under the W3-values ruling (#119), implicitly accepted runs keep only keyed hashes, so a routine compiles only once one of its runs ended in an explicit GOOD. PK2 exists because explicit GOODs are rare, so most recurring routines would never compile. #121 now uses hashed runs to keep literals, but a first explicit run is still needed.
- **Proposal (CAP-5):** a routine that recurs with only implicit acceptance MAY be put to the owner once, paced, as "Keep it as a skill?"; a yes counts as an owner outcome for CHG-1.
- **Potency gain:** the bulk of routine work becomes compilable.
- **Security cost:** none; it is an explicit owner yes on the existing value path.
- **UX cost:** one question per recurring routine, paced by CH-15.

### 5. Forgetting one task drops whole skills (CAP-3)
[Fact] The forget primitive (#123) and security C1 on #120 require skills whose evidence included a forgotten task to be removed or rebuilt. Removal alone throws away a routine seen many times because one instance was forgotten.
- **Proposal (CAP-3):** rebuild from the remaining evidence and requalify (§11); remove only if it no longer qualifies; tell the owner before the deletion which learned skills it changes.
- **Potency gain:** learned routines survive ordinary deletions.
- **Security cost:** none; the deleted record and everything built only from it are still gone.
- **UX cost:** one line in the deletion confirmation.

### 6. Small boxes never learn (→ later)
[Measured] On boxes where the agent and one replay machine don't fit together, PE2 (#114) turns learning off. PE7 (design: `/mnt/project-files/w3/pe7-design.md`) evaluates while the agent sleeps in a quiet window: checkpoint and stop the agent, run one unit, restore on any owner message. Potency ruled support, with kept pairs carried for 36 h and invalidated when the base changes.
- **Potency gain:** about one candidate a night, up from none.
- **Security cost:** **Conflict.** Restoring a full-memory checkpoint becomes the agent's normal resume path; today REV-1 rollback is owner-driven. Security's ruling is pending.
- **UX cost:** the first message after a sleep waits for a restore ("Waking up, one moment." past 5 s); S1 should measure it.
- **Status:** no spec change until security and the arbitrator rule.

### 7. Credentialed browsers may be over-budgeted (→ later)
[Measured, S5 fixture] The headless-shell executor used 165 MB PSS on the fixture page against RES-2's 0.5 GB for one credentialed browser. Real sites are unmeasured, since S5's live run is blocked on network access.
- **Potency gain if it holds on real sites:** two or three logged-in accounts served at once at the floor.
- **Security cost:** none if each account keeps its own sandbox.
- **Status:** re-size RES-2's browser line after the live run.

---

## Considered, not proposed
- **Letting loop or builder work block updates less by reclassifying it:** not needed. RES-1 already puts loops in `experiments`, and UPD-6 blocks only on accepted work. The #133 implementation should use the classes as written.
- **Raising the 4500 MB cap with memory alone:** rejected. Memory-only scaling starves foreground CPU on few-core hosts; finding 2 bounds it by cores.

---

## SPEC.md edits (L1 spec-diff, approved by Mark)

1. **New OP-9**, after OP-8:
   > **OP-9** **No silent loss of capability.** When a capability is off or cannot run because of the host (memory, hardware), configuration (a missing image or grant), or a held decision (a security fix not yet installed, a provider refusing the line's sign-in), STATUS MUST name it in one owner-worded line with what would fix it, and the digest MUST repeat it while it lasts. A log line alone is not enough. Owner choices (LOOPS OFF, PINNED) are named once when made and then listed in the digest, never repeated as alerts.

2. **RES-2**, append after "agent-machine pool about 3.9 GB.":
   > The pool is derived at start from the host's reported memory less the other components' budgets, never assumed: on an 8 GB N95 that is about 3.5 GB [S1 kit arithmetic]. A host too small for the agent machine runs with the agent off and says so (OP-9). On larger hosts the pool MAY grow past the floor's only by a rule that also bounds it by CPU cores, so that adding machines never slows foreground work (A2); such a rule adds throughput only (HW-4).

3. **CAP-3**, append to the row:
   > Adopted skills and procedures whose evidence included the deleted record are rebuilt from the remaining evidence and requalified (§11), and removed only if they no longer qualify. The owner is told, before confirming a deletion, which learned skills it would change.

4. **CAP-5**, append to the row:
   > A routine that recurs with only implicit acceptance MAY be put to the owner once as a paced question ("Keep it as a skill?", CH-15); a yes is an owner outcome for CHG-1.

5. **New UPD-9**, after UPD-8:
   > **UPD-9** **A security fix is never held in silence.** A security fix that has not been applied within 24 h of being staged, because the box was never free (UPD-6), is put to the owner once, paced (CH-15), with how long the restart takes and a choice of now or the next quiet window. A security fix held by the owner's settings (pinned, or security updates set to ask) is listed in every digest until it is installed or the owner declines it (OP-9). Ordinary releases never ask; after 7 days without a free moment they get a digest line.

6. **A2**, append before the trace column: "On a larger host, the pool rule raises machine count while foreground latency stays at the floor's." **A11**, append: "With learning unable to run (memory too small, no builder, no model grant), STATUS names the cause (OP-9)." and add OP-9 to its trace column.
