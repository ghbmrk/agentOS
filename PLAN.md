# AgentOS — Build Plan

Builds the spec in `SPEC.md` (v0.12 at P0 exit; v0.11 started at `/mnt/project-files/spec/agentos-core-spec-v0.11.md`) with Claude models under a **finite usage budget**, using nested iterative loops.
Labels: **[Fact]**, **[Inference]**, **[Rec]**, **[Mark]** = needs Mark's hands, money, or decision.

---

## 1. Planning premises (first principles)

1. **Tokens are the scarce resource; CPU is not.** Anything a machine can check deterministically (compile, test, fuzz, lint, canary scans) MUST be checked by CI, not by a model. Models are used to *produce* and to *judge what can't be computed*.
2. **The spec is the objective function.** Every requirement ID becomes an executable test or a recorded manual check. "Done" = traced tests pass, never a model saying it's done.
3. **Retire risk before writing volume.** The spec's riskiest unknowns are physical: screenless boot, modem voice, 8 GB headroom, consumer-AI routes. They're cheap in tokens and expensive if discovered late. Spikes come first.
4. **Write as little as possible.** Reuse mature components wherever they meet a requirement; the broker is the only large original component. Every line written is a line to review, test, and maintain within budget.
5. **Loops need stop rules more than they need intelligence.** An unbounded loop converts budget into nothing. Every loop has a budget cap, a progress test, and an escalation target.
6. **Independent verification.** The model that built something never approves it. A fresh context, ideally a different model tier, reviews against requirement IDs.
7. **Dogfood the architecture.** The build harness *is* an early version of AgentOS loop 1 (§11A): journal, candidates, held-out tests, adoption. What's learned building it transfers directly.

---

## 2. The nested loops

```
L0  Mark ─────────── direction, gate sign-off, hardware, money, irreversible calls   (weekly / per gate)
 └ L1  Program loop ─ plans, allocates budget, judges gates, revises plan            (per milestone, Opus-class)
    └ L2  Package loop ─ builds one work package to green                           (continuous, Sonnet-class)
       └ L3  Verify loop ─ adversarial review + CI + fuzz/canary, can reject           (per PR, mixed)
 L4  Meta loop ─────── tunes L1–L3: prompts, routing, caps, from measured metrics     (weekly, Opus-class, small)
```

### L0 — Mark
- Sets priorities and approves each **gate** (spec §15) on evidence.
- Does **physical** steps: buying hardware, plugging into PCs, inserting SIMs, power-cycling.
- Makes irreversible or external calls: license, publishing, purchases, accounts.
- Interface: one weekly digest, plus gate packets (evidence + a one-word decision). Target: under 1 hour per week except during physical test sessions.

### L1 — Program loop
- **Inputs:** spec, `PLAN.md`, `BOARD.md` (work packages and states), `LEDGER.md` (budget spent vs allocated), CI results, L3 verdicts, the traceability matrix.
- **Each cycle:**
  1. Pick the next packages by *risk retired per budget*, respecting dependencies.
  2. Write each package brief: requirement IDs, interfaces, acceptance tests, token cap, out-of-scope list.
  3. Dispatch to L2.
  4. Integrate results and update the board, ledger, and plan.
  5. When a gate's tests pass, assemble the gate packet for Mark.
- **Owns spec revisions:** spike findings turn into proposed spec diffs (v0.12, …), which Mark approves.
- **Review trigger:** if a phase runs past ~120% of its forecast, L1 re-plans, re-forecasting the remaining work, and tells Mark in the digest. Continuing is fine when the value case holds; the point is to notice, not to stop.

### L2 — Package loop (the builder)
Per package, in a fresh context with only the brief and the relevant code:
1. **Tests first:** write failing tests for each requirement ID in the brief.
2. Implement the smallest change that passes them.
3. Run CI locally (lint, typecheck, unit, relevant integration).
4. Iterate on failures.
5. Open a PR with a trace table (requirement ID → test → result).

**Stop rules:**
- **Checkpoint, not cap:** L1 sets a per-package *estimate*. At the estimate, the builder checks progress: if tests are moving toward green, it continues and notes the extension; if not, it escalates. At ~2× the estimate, L1 must look.
- **No-progress detector:** the same failing test after 2 fix attempts, or a growing diff with a flat pass count. Stop, write a diagnosis, and escalate to L1.
- **3-strike rule:** three escalations on one package and L1 must split, redesign, or drop it.
- **Scope guard:** touching files outside the brief's declared scope fails the PR automatically.

### L3 — Verify loop
- **Mechanical (free):** CI suite, fuzzers on broker sockets and the action protocol, canary scans (spec A5), dependency audit (A9), and a coverage check that every requirement ID in the brief has a passing test.
- **Model review (paid):** a fresh-context reviewer gets the diff, the requirement IDs, and the threat model, but *not* the builder's reasoning.
  - Security-critical paths (broker, vault, executors, clean room, update signing) get the strongest tier.
  - Other paths get the mid tier.
  - Verdict is *accept*, *fix-list*, or *reject*, with citations to requirement IDs.
- **Rule:** L3 can block; only L1 can override, and only with a recorded reason.

### L4 — Meta loop
- **Weekly, small budget.** Reads metrics:
  - tokens per merged requirement;
  - first-pass L3 acceptance rate;
  - escalation rate;
  - defects found after merge;
  - CI flake rate;
  - spend vs plan by phase and by model tier.
- **Proposes:** changes to builder/reviewer instructions, model routing, caps, package sizing, and harness tooling. Each change is evaluated like a candidate in the spec's §11: compare on a frozen set of past packages (replay) before adopting.
- **Cannot** change gate criteria or L3 blocking rules. Those are Mark's.

---

## 3. Phases (mapped to spec gates)

### P0 — Foundations and risk spikes (≈10% of budget)
**Harness:**
- repository, CI, `CLAUDE.md` (builder rules);
- traceability tooling (requirement ID ↔ test);
- the ledger;
- the PR template with a trace table;
- the decision log.

**Spikes** (time-boxed, each ends in a yes/no plus measurements and a proposed spec diff):

| # | Question | Who | Kill/pivot rule |
|---|---|---|---|
| S1 | Does a USB4 SSD boot screenless (≤1 keypress) on ≥3 unmodified PCs from different vendors? | **[Mark]** hands; builder prepares the image | <2 of 3 → bring the integrated key forward or accept a documented one-keypress setup |
| S2 | Does a USB LTE modem do SMS **and** voice under Linux reliably? | **[Mark]** buys 2 modems + SIM; builder tests | No voice → MVP is text-only; voice moves to a later gate |
| S3 | Agent machines at 8 GB: microVM vs container+sandbox; snapshot/fork/rollback times; how many concurrent | Builder, in a VM then on the N95 | If microVMs don't fit, use a lighter sandbox at the floor and microVMs above it |
| S4 | Does OpenClaw run unmodified as a guest using only broker tools? | Builder | Insufficient interface → record the exact seam; minimal patch is allowed (ARC-3) |
| S5 | Credentialed browser: can the narrow action protocol drive 5 real sites without arbitrary JavaScript? | Builder | Too weak → widen verbs carefully, each verb reviewed by L3 |
| S6 | Consumer AI CLIs in no-tools relay mode: do any work? | Builder + **[Mark]** accounts | None → API-key route only for MVP |
| S7 | Host foundation: compare 2–3 immutable-image options on A/B updates, Secure Boot shim, USB boot, build time | Builder | Pick by measured properties |

**Exit:** spec v0.12 incorporating spike results, plus a re-estimated budget. **[Mark]** approves.

### P1 — Core in a VM (Gate G2: A4, A5, A9) (≈25%)
Work packages, in dependency order:
1. Journal and intent engine (OP-1–7) as a library, with property-based tests.
2. Broker skeleton: sockets, admission classes, STOP/STATUS without inference (ARC-2, CH-2).
3. Vault plus egress credential injection (CRED-1, CRED-5 API-key path).
4. Agent-machine lifecycle: create, snapshot, fork, rollback, destroy (REV-1, REV-4, ARC-4).
5. Owner channel against a **modem simulator**: SMS in/out, approval codes, tiers (CH-1–4).
6. Canary harness (A5) and dependency audit harness (A9) as permanent CI jobs.
7. First guest: OpenClaw wired through broker tools (S4 result).

**Language:** [Rec] Go for the broker. Faster compile–test loops mean fewer wasted tokens on build errors, it's simple to read in review, and it has a strong standard library. Rust is the alternative if L3 finds memory-safety issues cost more than iteration speed. The decision boundary is broker size: if the broker stays small, Go wins on iteration cost.

### P2 — Real hardware (Gate G3: A2, A3, A6, A8) (≈30%)
1. Image build and boot from the drive (S1, S7 results).
2. Owner Card generation, local access point, local web UI (CH-7–9, ONB-1).
3. Real modem integration, SMS plus voice where S2 allows (CH-5).
4. Trusted-host TPM unlock and unknown-host flow (CRED-8/9).
5. Resource admission, preemption, memory budgets, accelerator discovery (RES-1–4).
6. Credentialed browser executor and action protocol (CRED-4, CRED-6, CRED-7).
7. Provider adapters: two frontier providers (A3).
8. Recovery and portability (REC-1–3, A8).

**[Mark]** runs the physical test sessions (A1, A8), guided by a printed checklist the builder produces.

### P3 — Compounding (Gate G4: A7, A10, A11) (≈20%)
- Change pipeline with held-out suites (CHG-1–5).
- Loops 1–3 (LOOP-0–11).
- Recall index, event bus, compiled skills, attention optimizer (CAP-3–6).
- Leverage benchmark vs unmodified OpenClaw (A10). **[Mark]** supplies a real recurring workload.

**Dogfood point:** once P3's pipeline works, the L2/L3/L4 harness migrates onto an AgentOS box. From then on, AgentOS helps build AgentOS. [Inference] This should cut later-phase cost; whether it actually does is measured in L4, not assumed.

### P4 — Open source (Gate G5: A12) (≈5%)
- Hint schema, clean-room builder, leakage audit (OSS-1–7).
- Attestations, release signing, channels and cadence (OSS-8–13, UPD-3–7).
- **[Mark]** chooses the license, publishes the repository, and holds the offline signing key.

### Reserve (≈10%)
Held back and spent only by L1 with a recorded reason. Unspent reserve rolls into P3 (more leverage work).

---

## 4. Model-tier routing (initial; L4 rebalances)

| Work | Tier | Why |
|---|---|---|
| L1 planning, gate judgment, spec diffs, hard design choices | Top tier (Opus-class) | Low volume, high consequence |
| L3 review of security-critical code | Top tier | Missed defects here are the most expensive |
| L2 building | Mid tier (Sonnet-class) | Bulk of volume; good cost/quality |
| L3 review of ordinary code | Mid tier | Fresh context matters more than tier |
| Log triage, CI failure summaries, doc formatting, test-name generation | Small tier (Haiku-class) | Cheap and repetitive |
| L4 meta analysis | Top tier, small budget | Leverage over all other spend |

**Initial spend target:** ~25–35% top tier, ~55–65% mid tier, ~5–10% small tier. This is a starting guess, not a measured value. Exact model IDs and prices to be confirmed when the harness is set up; nothing here relies on remembered pricing.

**Budget hygiene:**
- Prompt caching for the spec and stable code context.
- Small, focused contexts per package (brief + touched files only).
- Summaries of prior attempts instead of full transcripts.
- Never let a model read raw CI logs when a small-tier summary will do.

---

## 4A. Budget reality: the $200 Claude plan (calibrated 2026-10-04)

**Observed** (Mark's usage screen, Sunday 10:58 local):

| Measure | Used | Resets |
|---|---|---|
| Current session window | 44% | in 51 min |
| Weekly, all models | 14% | Sunday 06:00 |
| Weekly, Fable only | 11% | Sunday 06:00 |

Usage credits are off.

**What it implies:**
- [Inference] The weekly reset was about 5 hours before the screenshot. Most of the 14% likely came from today's design work in this project.
- At that rate, unpaced loops would exhaust a week's allowance in roughly 1.5–2 days. **The weekly limit, not the session window, is the binding constraint.** Pacing is mandatory.
- Phase shares in §3 become shares of **total weeks × weekly allowance**. The plan is budgeted in "weekly allowance units" (WAU): 1 WAU = one week's limit.

**Rules (flexible by design):**
Rigid caps breed waste: work abandoned at 95% done, padding to "use the budget", or allowance that resets unused. So the only **hard** limit is the subscription itself (B-4). Everything else is a **target with a checkpoint**: on reaching it, the loop decides on evidence whether continuing is worth it, and records why.

- **B-1 Weekly envelope (adaptive):** the default target is ~70% of the week for the build, ~30% left for Mark. The weekly allowance resets, so **unspent allowance at week's end is pure waste.**
  - The protected share for Mark shrinks as the week goes on: from ~30% early in the week to ~10% in the final day, adjusted to his actual recent usage.
  - Late in the week the build may use what Mark predictably won't.
  - If Mark's own usage spikes, the build backs off first.
- **B-2 Pacing (guideline, not a gate):** ~10% per day is the planning average. Front-loading is fine when work is unblocked and productive; idling to stay "on pace" is not.
- **B-3 Session windows:** near ~85% of a session window, finish the current step cleanly rather than stopping mid-step; heavy new work waits for the reset.
- **B-4 Hard cap (the only one):** usage credits stay **off**, so spend can never exceed the subscription.
- **B-5 Separate pools:** treat "Fable only" as its own pool; route work to it where that model fits, once measured.
- **B-6 Measurement:** session-log estimates, recalibrated from Mark's weekly usage screenshot.
- **B-7 Value over budget:** the allocation question is always "what's the expected value of the next unit of spend?", never "is there budget left?". Phase shares (§3) and package caps are **forecasts used to notice surprises**, not entitlements or ceilings. Overrunning a forecast triggers a look, not a stop. Underrunning is good news, not a reason to spend.

**Rough schedule in WAU** [Inference; L1 re-estimates after P0 using measured cost per merged requirement]:

| Phase | Share | Approx. weeks at a 70% envelope |
|---|---|---|
| P0 harness + spikes | 10% | 1–2 |
| P1 core in a VM | 25% | 3–5 |
| P2 real hardware | 30% | 4–6, partly gated by Mark's physical sessions |
| P3 compounding | 20% | 3–4 |
| P4 open source | 5% | 1 |
| Reserve | 10% | 1–2 |

This totals roughly **3–5 months** of calendar time at this plan level. That figure is a sizing guess, not a commitment. Mark's physical test sessions and spike outcomes will move it more than token efficiency will.

## 4B. Re-estimate at P0 exit (2026-10-04)

**Measured (B-6), Mark's usage screen, Sunday 2026-10-04 19:50 local:** weekly all models 23% (resets Sun 06:00); Fable only 11% (unchanged since 10:58); current session window 22% (resets in 1 h 59 min); usage credits off.

| Reading | Weekly, all models | Weekly, Fable only | Between readings |
|---|---|---|---|
| 10:58 | 14% | 11% | spec design (mostly Mark's own thread) |
| 19:50 | 23% | 11% | +9 points: three spikes' review fixes, three lens reviews, arbitration, the spec PRs, PR reviews, this package, and P1-1, P1-2, P1-5 building in parallel |

**Pace: tokens are the binding constraint.** The week reset at 06:00 Sunday, so 23% is one day's spend, against the ~10%/day planning pace. Sustained, that is about 160% of the week. **Pacing rule from 2026-10-04 (coordinator, told to Mark):** about 8% per day, at most three build threads at once, and no new packages start until the open PRs merge. Front-loading (B-2) stays allowed only within that rule.

**What changed since §4A.**
- **Scope grew.** SPEC.md went from 101 requirement IDs and 12 acceptance tests (v0.11 as imported, 25f9b2b) to 144 IDs and 15 tests (v0.12), and from 40 KB to 88 KB. Review 1 added 38 IDs (adapters ADP-1–12, owner channel CH-10–20, onboarding ONB-3–8, data labels, worker machines, routing, TUF); the spikes added 5 (HW-5a, UPD-1a, ARC-6, ARC-7, OP-8). Requirements also got denser, so ID count understates the growth.
- **P0 cost, measured:** at most **0.23 WAU** in total, and that also covers the design session and the first P1 packages. That is inside P0's 10% share (≈ 0.9–1.4 WAU of the §4A total). The 9 points between the two readings come from two of Mark's screens; how they split across threads is inferred. S1, S2, S5, S6 remain.
- **Standing overhead.** Four weekly review loops plus PR review now run every week. Their per-run cost isn't split out of the 9 points; ≈ 3–10% of a week is the plausible range [Inference]. Under the 8%/day rule that matters, so loops run on change only (recommendation 2).
- **No calibration yet for build cost.** P0 merged spikes and spec text, not requirement-covering code, so tokens per merged requirement (the number L1 needs) is first measured in P1.

**Revised forecast** (weeks at the effective envelope; ranges scale each phase by the new IDs that land in it):

| Phase | New IDs landing there | Scale | §4A weeks | Revised weeks |
|---|---|---|---|---|
| P0 (incl. S1, S2, S5, S6) | — | — | 1–2 | 1–2 (on forecast; S1/S2 wait on hardware) |
| P1 core in a VM | ARC-5–7, REV-5, OP-8, CAP-8/9, CH-10–19 against the simulator | ×1.5 | 3–5 | 4.5–7.5 |
| P2 real hardware | ADP-1–3, 5–7, 9–12, ONB-3–8, CRED-10, REC-4, CH-20, HW-5a, UPD-1a | ×1.5 | 4–6 | 6–9 |
| P3 compounding | CHG-6, CAP-10, ADP-4/8 | ×1.15 | 3–4 | 3.5–4.5 |
| P4 open source | UPD-8 | ×1.1 | 1 | 1 |
| Reserve | 10% | — | 1–2 | 1.5–2.5 |
| **Total** | | | 13–20 (3–5 months) | **17.5–26.5 at 70% (4–6 months)** |

**Reading the forecast after the measurement.** The weeks column assumes the 70% envelope is actually spent at a sustainable rate. Day one used tokens far faster than that, so the forecast is not optimistic about tokens: tokens set the pace, and the 8%/day rule (≈ 56% a week) stretches it by about 70/56 ≈ 1.25×, to roughly 22–33 weeks (5–8 months), until P1's measured cost per merged requirement replaces these factors (recommendation 3).

**Recommendations.**
1. **Start P1 now** on the merged S3/S4/S7 results; S5 (cloud) runs beside P1, and S1, S2, S6 stay open as P0 tails that gate only P2. Nothing in P1 depends on them (§3).
2. **Run review loops on change only:** a lens loop runs when SPEC.md or security-critical code changed since its last run, else it records "no change" and stops. Under the 8%/day rule this saving matters, and no review of new material is skipped.
3. **Recalibrate after the first three P1 packages** from tokens per merged requirement, and replace the scale factors above with that measurement.
4. **Hold P1's first package to the smallest end-to-end slice** (journal + broker STOP/STATUS, OP-1–6, ARC-2, CH-2) so the first measurement comes early.

## 5. Artifacts the harness maintains (in the repo)

| File | Purpose | Updated by |
|---|---|---|
| `SPEC.md` | Current spec (v0.12+) | L1 (Mark approves) |
| `PLAN.md` | Phases, packages, dependencies | L1 |
| `BOARD.md` | Package states: queued, building, in review, merged, escalated | L1/L2 |
| `LEDGER.md` | Budget allocated, spent, and remaining per phase and tier | L1, automated from usage logs |
| `TRACE.md` | Requirement ID → tests → status (generated) | CI |
| `DECISIONS.md` | Every decision with date and evidence | L1 / Mark |
| `METRICS.md` | L4 inputs and history | CI + L4 |
| `CLAUDE.md` | Builder and reviewer rules | L4 proposes, L1 adopts |

---

## 6. Failure modes of the plan itself, and guards

| Failure | Guard |
|---|---|
| Loops burn budget without progress | **Progress-based** stops (no-progress detector, 3-strike rule) instead of fixed caps; checkpoints at forecasts; L1 review past ~120% of a phase forecast |
| Builder and reviewer collude (same blind spots) | Fresh context, no builder reasoning shown, different tier for security code, mechanical checks first |
| Tests drift from the spec | Traceability matrix generated by CI; uncovered requirement IDs block the gate |
| Spec churn | Spec changes only via L1 diffs approved by Mark; packages pin a spec version |
| Hardware assumption fails late | Physical spikes in P0, before any volume |
| Over-building | "Write as little as possible"; L1 must show why reuse fails before approving new components |
| Rigid caps cause waste (abandoned near-done work, unspent weekly allowance) | Only the subscription is a hard limit; adaptive weekly envelope; checkpoints instead of ceilings (B-1–B-7) |
| Mark becomes the bottleneck | Batched gate packets; everything reversible proceeds without waiting |

---

## 7. What's needed from Mark to start

1. **Repository:** `agentOS` under Mark's GitHub account. Mark creates it (this session can't create repositories), then it's attached to the project.
2. **Budget:** ✓ the $200 Claude plan, weekly-paced (§4A).
3. **P0 hardware** (prices unchecked):
   - the N95 floor box;
   - 2–3 used PCs from different vendors;
   - 2 USB4 dual-mode NVMe enclosures plus SSDs;
   - 2 USB LTE modems with voice support, of different chipsets;
   - 1–2 prepaid SIMs.
4. **Approve P0.** With a repository connected, the harness and spikes S3–S7 can start immediately in the cloud. S1 and S2 wait for the hardware.

---

## 8. First concrete steps once approved

1. Scaffold the repository: CI, `CLAUDE.md`, trace generator, ledger, PR template; import the spec as `SPEC.md` with requirement IDs parsed.
2. Run S7, S3, S4 in parallel in the cloud (no hardware needed).
3. Produce S1/S2 test images and a printed physical-test checklist for Mark.
4. First L4 review after the first week of packages; adjust routing and caps.
