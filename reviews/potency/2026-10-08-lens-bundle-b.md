# Potency lens screen: bundle 2026-10-08b (#320, #321, #322, #324, #329)

**Stage:** OPERATING §4 stage 4, batched lens screen, Potency section. #320, #322, #324 and #329 are tier A; #321 is tier B. Each PR has an L3 accept on the head named below, and no head had moved when this screen ran. Security is a separate session; UX (with #321's Security paragraph) is in [`../ux/2026-10-08-lens-bundle-b.md`](../ux/2026-10-08-lens-bundle-b.md).
**Question (README):** does the change cap capability without buying matching security or UX, and what is the cheapest structural lift?
**Labels:** [Fact] checked in the diff or spec · [Inference] reasoned, untested.

## Verdicts

| PR | Head | Verdict | Findings |
|---|---|---|---|
| #320 P2-2w c1 | 35febcd | **accept** | none (UX release into c2 is neutral here) |
| #321 W3-forget-b2 | 24f3d9d | **accept** | none |
| #322 P2-2w d | 11fa1f2 | **accept** | none of its own; UX blocker 1 restores capability |
| #324 SR2-3g | cee016a | **accept** | none |
| #329 P2-2a f1 | 3a79399 | **accept** | none |

---

## #320 P2-2w c1 (35febcd): accept
- **Gain:** [Fact] the owner can enroll the code generator at setup with one code (ONB-3), from a scanned link or a typed seed (ONB-6). Before this, the generator had no setup path.
- **Cap:** [Fact] after sealing, a new generator needs the recovery key (REC-3). That is the spec's rule, and it costs nothing the owner relies on day to day.
- [Inference] The UX release (one seed per page session) removes failed confirmations and pauses. It adds no step.

## #321 W3-forget-b2 (24f3d9d): accept
- **Gain:** [Fact] FORGET now reaches an in-flight build that read the goal, which finishes C23 without waiting for the build to end.
- **No unfair cost to Loop 1:** [Fact] the scheduler counts a requeued build as preempted. Its `spent` is still charged, but it adds no EWMA value or cost sample and no dry count. [Inference] So an owner's forget never counts against Loop 1's measured return, and it can't push the loop toward sleep (LOOP-3). That is the right attribution: the owner stopped the work, and the loop didn't fail to produce value.

## #322 P2-2w d (11fa1f2): accept
- [Fact] Refusing at once when the page isn't served saves the owner a code approval on a request that can't be confirmed. `gcfg.LocalUI = cfg.PageSocket != nil` is the right predicate: it means "the page is served", not "the page is configured".
- [Fact] UX blocker 1 (move the page check below the address check) gives back a capability the PR removed: when the page is off, "Email replies to <someone else>" reaches the agent again. Neutral to positive for potency.

## #324 SR2-3g (cee016a): accept
- **Cost:** [Fact] the agent no longer sees raw internal error text; it sees "<tool> failed (ref …)". [Inference] That could make the agent fail where it could have recovered, but every message that names a step the agent can take was converted to `Safe` text, so the agent keeps what it can act on. What it loses is internal detail (paths, machine labels) that it couldn't act on anyway.
- Considered, not proposed: a wider `Safe` allowlist. It would buy nothing the agent can use, and it would widen SR2-3's leak surface.

## #329 P2-2a f1 (3a79399): accept
- [Fact] A page approval of an item that changed after the page showed it doesn't run (Security P1). The cost is one repeated request, only when the item really changed. That is the minimum price of binding a code to what the owner saw.
- [Inference] The UX blocker (name a step that works for the item's origin) removes a dead end and adds no prompt.

---

## Cross-lens (arbitration, reviews/arbitration/README.md method)

| Proposal | Security | Potency | UX | Result |
|---|---|---|---|---|
| #322 UX B1: check the page only after the address check | neutral (a non-owned address still never becomes a destination; CH-20 unchanged) | improves (owner tasks reach the agent again) | improves | passes |
| #322 UX B2: `evidenceNoPage` names what still works and drops "isn't running" | neutral | neutral | improves | passes |
| #329 UX blocker: the step depends on the origin (agent / EMAIL REPLIES ON / Wi-Fi page), or a neutral "make the request again" | neutral (the text only; the sum check and confirm are unchanged) | neutral | improves | passes |
| #320 UX release (c2): one seed per page session, or say to rescan; show the pause time | neutral (the seed is still handed out only before sealing, and wrong codes stay counted) | neutral | improves | passes; folds into the P2-2w c2 row |

No proposal costs any lens, and no hard constraint (Invariant C, REV-2) is touched, so nothing goes to Mark.
