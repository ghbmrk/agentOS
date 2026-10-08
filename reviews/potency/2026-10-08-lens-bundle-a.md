# Potency lens screen: bundle 2026-10-08a (#300, #319, #323, #327)

**Stage:** OPERATING §4 stage 4, batched lens screen, Potency section. All four PRs are tier A and have an L3 accept on the head named below. Security is a separate session; UX is in [`../ux/2026-10-08-lens-bundle-a.md`](../ux/2026-10-08-lens-bundle-a.md).
**Question (README):** does the change cap capability without buying matching security or UX, and what is the cheapest structural lift?
**Labels:** [Fact] checked in the diff or spec · [Inference] reasoned, untested.

## Verdicts

| PR | Head | Verdict | Findings |
|---|---|---|---|
| #300 CRED-4b part 1 | e000ecc | **accept** | none new (false positives already under K11/K12) |
| #319 OSS-6e | abe4598 | **accept** | none |
| #323 OSS-10w | 72a8693 | **accept** | agree with later OSS-10w-r |
| #327 W3-forget-b2b | fc62903 | **accept** | none |

---

## #300 CRED-4b part 1 (e000ecc): accept
- **Gain:** [Fact] this is the first broker-side path to a credentialed browser (CRED-4). The protocol's verbs are all kept: navigate, click, type, select, snapshot, screenshot, download. A refusal returns a typed `Error` plus a `Detail` the agent can act on, and a withheld screenshot names its reason (CRED-10), and the agent can still read the redacted `snapshot`, so it can continue instead of failing the task. (Only a screenshot withheld after its bytes were scanned carries `URL` and `Title`. Neither withhold that follows a page snapshot does. That is harmless, because a plain `snapshot` returns both.)
- **Cost:** [Fact] the label rule fails closed on some ordinary text (`hotKey 2024-…`, `USBKey …`, prose "secret 2024-…"). A false positive withholds that screenshot or redacts a value. That costs availability only, never authority. The PR already routes these to part 2's shared positive/negative corpus (K11, K12).
- [Inference] When part 2 builds that corpus, it should record the false-positive rate on a realistic page set as well as the misses, so the tradeoff stays measurable. This is guidance for K11, not a new row.
- Considered, not proposed: loosening the detector to cut false positives now. That would weaken CRED-10's floor, and the costs above are fail-closed.

## #319 OSS-6e (abe4598): accept
- [Fact] This is a tightening only. On the same boot, a restart no longer reopens the 20h floor. The cost is that publication can wait out the rest of the floor after a restart. OSS-6 already delays publications by design, so this caps nothing the owner relies on.
- [Fact] A corrupt stored value ahead of the clock counts no day and does not freeze the outbox (G4), so a bad file cannot stop contributions. A malformed count refuses the outbox under the existing MUST 2 rule, which is unchanged here.

## #323 OSS-10w (72a8693): accept
- **Gain:** [Fact] OSS-10 ("installations may follow any fork") gets a working executor. The switch-back to the project is now possible: before this PR the gate refused an empty name. WF1 compares key material, so a forged root cannot pose as the project without costing the owner anything.
- **Cap:** [Fact] after a project root-key rotation, WF1 fails closed, because no chain walk is done. The owner can still follow the project by a named follow, and a new image ships the new root. I agree with **later** (OSS-10w-r): no release has rotated root keys yet.
- [Fact] `MaxHeld` = 4 described roots is enough for a page session. It is a bound on memory, not on which forks can be followed.

## #327 W3-forget-b2b (fc62903): accept
- **Gain:** [Fact] when the agent has not worked since the task, item 1's YES also resets the idle agent with no second question. That is one approval for the whole forget, the ask-first rule applied with the fewest owner-minutes (§1 north star). When the agent has worked, approving only item 1 keeps the work (CAP-3: "if the owner says no, it keeps its work"). Approved take-backs are carried across restarts by recall's `Retry`, not dropped.
- **No cap added:** item 2 reuses `recalltool.Reach` (reset, provenance, Retry). It adds no new gate or prompt.
- [Inference] UX blocker 1 (show "N actions so far stay done" on item 2) uses a count `Reach` already computes. It adds no call and no owner step, so it is neutral for potency.

---

## Cross-lens (arbitration, reviews/arbitration/README.md method)

| Proposal | Security | Potency | UX | Result |
|---|---|---|---|---|
| #327 UX B1: item 2 states the restore point and the action count; the notice and done text say actions stay done | neutral (a count, no content; the gate and code tier are unchanged) | neutral | improves | passes; it is the spec's own wording (CAP-3, DECISIONS 2026-10-05) |
| #327 UX B2: drop "Send FORGET to ask again" where item 1 has run | neutral | neutral | improves | passes |
| #327 UX B2 release: carry the no-agent, not-saved and not-open take-backs as owed | neutral (same owed record, same once-only rule as `ErrCarried`) | improves (no work left on a forgotten task) | improves | passes; release row beside the OP-4 reconcile row |
| #323 UX release: WF1 at describe time in OSS-10w2 | neutral (the executor keeps WF1; the page check only moves it earlier) | neutral | improves (no code spent on a doomed request) | passes |

No proposal costs any lens and no hard constraint is touched, so nothing goes to Mark.

## Delta note 2026-10-08 (re-check)
Potency accept for #327 at 14ee01c: queueing an approved item 2 until recall opens and fixing its count at ask time add capability and cap none; REV-2 and Invariant C untouched; nothing goes to Mark.
