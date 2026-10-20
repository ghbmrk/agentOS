# agentOS — Build Plan

SPEC.md says what to build; this file says in what order, by whom, and how the work is checked. It replaces the phase plan of SPEC v0.12 whole: the old phases, routing table and budget calibration are in git history before MIG-1, not here.
Labels: **[Fact]**, **[Inference]**, **[Rec]**, **[Mark]** = needs Mark's hands, money, or decision.

---

## 1. Planning premises

1. **Machines check what can be computed.** Compile, test, fuzz, lint, canary scans, simulation and replay run in CI, never as a model's opinion. Models produce code and judge what cannot be computed.
2. **The spec is the objective function.** Every requirement ID becomes an executable test or a recorded manual check (TRACE.md). Done means traced tests pass.
3. **The trusted base stays small and is built first.** The kernel, the key library and the clerks (SPEC KRN-2) are where a defect costs the most, so they are built before anything that depends on them, serially, by one strong builder, inside the simulator from the first commit (SPEC EVL-1).
4. **No debt, no relics.** Nothing is built on a path that will change or be thrown away. Old code is not adapted to the new design: each port replaces a directory and deletes what it replaces in the same PR, and the old core is deleted, not kept as a fallback (Mark, 2026-10-20 02:01Z and 02:40Z).
5. **No overlap.** Each directory has one owner at a time (docs/LANES.md), so Mark's two subscriptions never build the same thing twice or race on one file.
6. **Loops need stop rules more than they need intelligence.** Every loop has a progress test and an escalation target (§2, docs/OPERATING.md §5).
7. **Independent verification.** The session that built something never approves it; a fresh session reviews against requirement IDs (docs/OPERATING.md §4).

---

## 2. The nested loops

```
L0  Mark ─────────── direction, gate sign-off, hardware, money, irreversible calls
 └ L1  Program loop ─ picks packages, writes briefs, judges gates, revises this plan
    └ L2  Package loop ─ builds one package to green
       └ L3  Verify loop ─ CI, simulation, replay, fresh-context review; can reject
 L4  Meta loop ─────── tunes L1–L3 from measured metrics (METRICS.md)
```

- **L0 — Mark.** Sets priorities, approves gates on evidence, does the physical steps (hardware, SIMs, power) and the irreversible or external calls (accounts, money, publishing). Mark is asked one-word questions with a recommendation, through the coordinator (CLAUDE.md).
- **L1 — Program loop.** Picks the next package in the order of §3, writes its brief (requirement IDs, scope, acceptance tests, estimate), dispatches it, integrates the result and keeps BOARD.md, LANES.md and this plan current. Spec changes go through an L1 spec-diff PR.
- **L2 — Package loop.** In a fresh context with the brief: failing tests for each cited ID first, the smallest change that passes them, the repo's checks locally, then a PR with its trace table. **Stop rules:** at the estimate, continue if tests are moving and note it, otherwise escalate; the same failing test after two fixes, or a growing diff with a flat pass count, stops and escalates; three escalations on one package and L1 splits, redesigns or drops it; a file outside the brief's scope fails the PR.
- **L3 — Verify loop.** Mechanical checks first (CI, the kernel simulator and the replay gate, fuzzers, canary scans, the trace and scope checks), then a fresh-context review of the diff against its IDs, without the builder's reasoning. Verdicts are accept, fix-list or reject (docs/OPERATING.md §4). L3 can block; only L1 overrides, with a recorded reason.
- **L4 — Meta loop.** Reads METRICS.md (first-pass accept, review rounds and causes, usage, defects after merge, flake rate) and proposes changes to instructions, routing, sizing and tooling, each judged on past packages before it is adopted. It cannot change gate criteria or L3's blocking rules.

---

## 3. Migration to SPEC v1.0

Six steps, strictly in order where a step depends on the one before. Each step ends on a check, not on a date.

| Step | What | Who | Ends when |
|---|---|---|---|
| **0** | **Freeze.** Builds on old-core paths stop; DECISIONS.md, handoff/CURRENT.md and the migration case list (docs/migration/cases.md) record the hold, what in-flight work is kept or closed, and the cases the new design must pass. | sub A: the step-0 freeze thread | its PR merges |
| **1** | **Spec and plan.** SPEC v1.0 (every v0.12 ID restated or dropped with a reason, Appendix A); this plan; the BOARD intro, LANES, OPERATING and the README descriptions rewritten; the trace tool counts old-core markers and fails a PR that grows the old core. | sub A: MIG-1 | its PR merges |
| **2** | **Kernel.** `broker/kernel` (the pure transition function, the log, the plan checker), the key library, `broker/clerk` (the clerk runtime and its fake clerks) and the deterministic simulator, built serially by one tier-A builder with the simulator from the first commit. It starts from the survey and simulator work on `pkg/sim-sim-bwcvu2` at 6cf8b16. `broker/sim` is old core (D-139), so the simulator replaces it in place: the PR that adds the new simulator deletes broker/sim's journal-coupled code and takes `broker/sim` off tools/old_core.txt, a port like any other. Its first PR amends tools/g1_scope_g2.txt to allow `broker/kernel` and `broker/clerk` (`broker/sim` is already allowed). | sub A: one tier-A builder, serial | A20 passes; the kernel's and clerks' interfaces are frozen |
| **3** | **First slice.** "Sort my inbox and unsubscribe from and delete the spam" (SPEC EVL-2): the mail clerk, the quarantined reader, the planner's command interface ([Rec: pending Mark] one `plan` command, SPEC PLN-5), the key proposed from use, the hold window and the replay gate, in QEMU with a synthetic mailbox, fake endpoints and injection mails. | sub A: one builder, then parallel builders within the slice, all on sub A | A21 passes |
| **4** | **Ports, by directory.** Each remaining requirement is built on the frozen interfaces. Each port owns whole directories (docs/LANES.md) and deletes, in the same PR, the old code it replaces. | sub A: the trusted side (kernel, clerks, modem, enforcer); sub B: the untrusted side (planner, reader, guests, owner channel and UI); the Codex lane: the adapters and evals (docs/LANES.md) | every v1.0 ID has its owner; old-core markers reach zero |
| **5** | **Delete the old core.** Remove every old-core package and test that step 4 left without callers; broker/core/core.txt then lists only the kernel and the clerks; the conv-* triage notes in docs/ and the old BOARD sections go with them. | either sub, one PR | `python3 tools/trace.py` reports 0 old-core markers and core.txt names only kernel and clerk paths |
| PUB-1 | Publication (SPEC §15), built only after step 5. | either sub | its gate tests pass |

**Rules that hold across the steps.**
- **Who works where until step 4 (D-139).** Sub A runs steps 0 to 3. Sub B runs only the hardware track (image, modem and Wi-Fi hardware work) and the eval set: the slice's acceptance cases as runnable tests against the kernel's public interface, under `evals/slice-inbox/`, which no kernel PR touches. From step 4 the directory owners in docs/LANES.md decide; after step 5, D-099 applies in full again.
- **One owner per directory.** From step 4, docs/LANES.md lists which subscription owns which directories; a change another owner's directory needs goes to that owner as an issue. Before step 4, sub A's step-2 and step-3 builders own `broker/kernel`, `broker/clerk` and `broker/sim`, sub B owns `evals/slice-inbox/`, and no one else writes there.
- **Interfaces freeze at the end of step 2.** A change to them after that is a kernel PR at tier A with a delta of A20.
- **A port deletes what it replaces.** No adapter layer between the old core and the new one, no feature flag between them, no copy kept for reference.
- **The old-core ratchet.** A test marker that cites a retired ID (SPEC Appendix A) is an old-core marker. `tools/trace.py` counts them in TRACE.md. On every PR, CI runs `tools/trace.py --ratchet` against the base and fails if the old core grew: more old-core markers, more lines under a directory tools/old_core.txt lists (the D-139 packages), or more imports of one from outside them (their wiring). A port takes its directory off that list in the PR that deletes the directory's old files, and the ratchet fails the PR if any of them remain. The marker count is zero at the end of step 5.
- **Gates.** G1 to G7 are SPEC §18's. The G2 freeze (tools/g1_scope_g2.txt) stays on; step 2's first PR widens it only by the two new directories. A20 and A21 run on every change to the kernel or clerks after they first pass.

---

## 4. Routing and tiers

- **Tiers.** Tier A is the trusted base: `broker/kernel`, `broker/clerk`, the enforcer, the sealed store, the signed image, and the gate files (CLAUDE.md). Tier B is everything else, and its changes also pass the replay gate once step 3 has one (SPEC HLD-2). `tools/risk_tier.py` is the authority on which paths are which (docs/OPERATING.md §3).
- **Models.** Tier-A building and review use the strongest model; tier-B building uses the mid tier; mechanical subagent work uses the cheapest that suffices. Speed rules and session sizing are docs/OPERATING.md §5 and the agentos-budget skill.
- **Budget.** There is no budget ceiling (D-109); the subscription is the only hard limit, and checkpoints replace caps.

---

## 5. Artifacts the harness maintains

README.md's document table lists every file the harness maintains, its kind, and who changes it.

---

## 6. Failure modes of the plan itself, and guards

| Failure | Guard |
|---|---|
| Old and new designs both live on (a Frankenstein system) | A port deletes what it replaces (§3); the old-core marker ratchet; step 5 deletes the rest |
| Two subscriptions build the same thing or race on a file | One owner per directory (docs/LANES.md); no build starts while an open PR touches its scope (OPERATING §5) |
| Kernel interfaces churn under the ports | Serial kernel build; interfaces freeze at the end of step 2; changes after that are tier A with A20 |
| The trusted base grows unseen | Its size is measured on every PR (SPEC KRN-2); tier-A review for growth |
| Loops burn usage without progress | Progress-based stops (§2), not fixed caps |
| Builder and reviewer share blind spots | Fresh context, no builder reasoning shown, mechanical checks first, a separate Security review on gate files |
| Tests drift from the spec | TRACE.md generated by CI; uncovered IDs block their gate |
| Hardware assumptions fail late | The first slice needs no hardware; G1 runs on the M6 Ultra when it arrives |
| Mark becomes the bottleneck | One-word questions with a recommendation; everything reversible proceeds without waiting |
