# Operating model

How AgentOS is built for the most progress per weekly limit at the same quality. CLAUDE.md holds the rules, one line each; this file holds the procedures and the reasons behind them. Decided by Mark on 2026-10-07 (DECISIONS.md, COST-1).

**Where facts live.** Each fact has one home, chosen by its kind; other files point to it and never restate it. README.md has the full document map and a reading order per role.

| Kind | Home |
|---|---|
| What to build | SPEC.md (requirement IDs are normative) |
| How it is phased | PLAN.md |
| Rules | CLAUDE.md |
| Procedures and reasons | this file |
| Live state | BOARD.md (index), LATER.md (release vs later), docs/LANES.md (team lanes) |
| One package's work | `briefs/<ID>.md`, linked from its BOARD row |
| Records | DECISIONS.md, `reviews/`, each package's `ASSUMPTIONS.md` |
| Generated | TRACE.md, METRICS.md |

Any agent, from any subscription or vendor, works from these files. Nothing a builder or reviewer needs lives anywhere else.

**Terms.** L0–L4 are the nested loops of PLAN.md §2: L0 Mark, L1 program (coordinator), L2 builder, L3 reviewer, L4 meta. Tiers are §3; lanes are §7.

## 1. What limits progress

The only hard limit is the weekly subscription allowance. Baseline, measured over the week of 2026-10-04 (COST-1, PR #294); current figures are in METRICS.md. List-equivalent spend split into:

| Part | Share |
|---|---|
| Cache reads (rereading context on every call) | 54% |
| Cache writes (new or woken context) | 29% |
| Output | 17% |

By role, builders were 51.5%, one long-lived reviewer session 26.6%, lens sessions 13% and coordinators 6%. The first-pass L3 accept rate was 12% (METRICS.md), so most packages were built more than once.

**Price weights.** On Opus 5.5 and Sonnet 5.5 a cache write with the one-hour lifetime costs 2x base input and a cache read 0.05x, so a written token costs 40x a read one (Haiku 5.5 reads at 0.1x, so 20x there); source: the prompt-caching pricing docs. A cold start (a new session, a wake after more than an hour idle, a model switch, a compaction) writes the whole context and so costs about as much as 40 warm calls over it.

Cost per merged package = (calls × context per call × read price + writes + output) ÷ first-pass rate.

Levers in order of effect:

1. **Cut rework.** Raise the first-pass rate and build only what the first release needs (§2, §4). L3 cause codes (§4) say which part of the pipeline the rework comes from.
2. **Fewer cold starts, then smaller context.** Count cold starts per merged PR and cut them: pick the model at spawn, don't wake idle sessions, hand off before a long idle (§5). Then small briefs, a short BOARD index and compaction at 200k keep each call's context small.
3. **Fewer calls per package.** One package per session; batch reviews (§4).
4. **Route by model price.** Use the cheapest model that keeps quality, and check with tests rather than with a more expensive model (§5).
5. **Fill capped time with free CI.** Fuzzing, race soak and mutation run on Actions while the allowance resets.

The budget rules themselves are CLAUDE.md §Budget; PLAN.md §4A–4B hold the calibration history behind them.

## 2. Finding triage: blocker, release, later

Every finding (L3, lens, CI soak, an agent's own observation) gets one class at the moment it is raised. Whoever raises it assigns the class; the reviewer can correct it.

| Class | Meaning | Where it goes |
|---|---|---|
| **blocker** | Breaks a requirement the PR cites, or an invariant. | Fixed in the same PR before merge. |
| **release** | Needed to pass an acceptance test in SPEC §15 (A1–A15) or an invariant, but not in this PR's scope. The finding names that test or invariant and one failure path: what goes wrong without it. | A new BOARD.md row, named in the PR's Findings line. |
| **later** | Anything else: polish, hardening beyond the spec, nice-to-have wording. | One line in LATER.md. No package is started for it before the first release ships. |

The PR's Findings line also names every LATER.md row the PR removes, including a row outside its brief's scope that it strikes; the reviewer checks the line against the diff.

Security findings on tier-A broker paths are never `later` unless they are purely wording. On assurance tooling (`tools/depaudit*`, `tools/canary*`, `assurance/`), a finding is `release` only if it can make the tool report a pass on a real violation (a false pass); the tool's messages, diagnostics and remedy text are `later`. When unsure between blocker and release, pick blocker. When unsure between release and later, class it `later` with the tag `recheck` and say so (D-086).

- **Follow-up depth.** A finding raised on a follow-up of a follow-up (a row whose source is itself a review finding on a follow-up row) is `later` unless it is a blocker on the cited IDs, a false pass, or an exploit path.
- **One review, one package.** The release findings from one PR's reviews go into one follow-up brief, with one BOARD row per finding grouped under it, not one package each.
- **Pre-release sweep.** Before the first release ships, one session re-reads every `recheck` line and every tier-A `later` line in LATER.md and promotes any that now block an acceptance test.

LATER.md also holds the critical-path audit of BOARD.md: each open row is marked release or later. The coordinator does not start `later` rows. A row moves to release only with the acceptance test it now blocks.

## 3. Risk tiers

Review depth follows risk, decided mechanically from the paths a change touches. `python3 tools/risk_tier.py --git origin/main HEAD` prints the tier; CI writes it to the PR's step summary. A change takes the highest tier of any path it touches.

| Tier | Paths (tools/risk_tier.py is authoritative) | Review (stages in §4) |
|---|---|---|
| **A** | broker packages holding credentials, isolation, effects, owner auth, update and supply chain (vault, tpmseal, egress, grants, verb, journal, reversible, sockets, guest, vm, workers, cgroup, owner, control, card, modem*, localapi/localsrv/localui, cleanroom, hint, pubid, attest, update, apply, change, replay, sipsign, smsapi, sendrules, clock, recovery, hostdisk, hostchange, vendor, mail, plus the wiring in daemon and cmd), `broker/go.mod`, `broker/go.sum`, `assurance/`, `tools/canary*`, `tools/depaudit*`, `tools/risk_tier*`; `image/` except its top-level `*.md`; `.github/` (workflows build the image, gate merges and push to main); `.claude/` (agent permissions); the guest's build inputs (`guest/*/build-rootfs.sh`, `package.json`, `package-lock.json`, `launch.json`, `guest/openclaw/openclaw.json5`); any `*.service`, `*.socket` or `*.timer`, and any `*.conf` under a `systemd` directory, outside `spikes/` | CI, L3 on the strongest model with a threat check, lens screen with a separate Security section, Security re-sign on later deltas |
| **B** | other `broker/` packages, the rest of `guest/`, SPEC.md (which also needs Mark through an L1 spec-diff PR), and any path no rule names, so a new top-level directory gets a lens pass until it is classed | CI, L3, one combined lens pass |
| **C** | only the explicit list: top-level `*.md` other than SPEC.md (BOARD, LATER, DECISIONS, LEDGER, METRICS, TRACE among them), `docs/`, `briefs/`, `reviews/`, `decisions/`, `spikes/`, `tests/`, `tools/` outside the tier-A prefixes, `image/*.md` | CI, L3; no lens screen |

A new broker package that holds credentials or gates effects is added to `TIER_A_BROKER` in the same PR that creates it. A renamed tier-A package fails `tests/test_risk_tier.py` until the list is updated.

**Security re-sign (mechanical).** After Security has signed a tier-A PR, any later delta for which `python3 tools/risk_tier.py --git <signed commit> HEAD` prints tier A needs a re-sign. The Security session may sign a test-only or comment-only delta in one line. This over-triggers on harmless deltas and never misses one; on tier A that is the right trade (DECISIONS D-054).

**Every PR gets an L3 review.** Tier C skips only the lens screen, never the review (DECISIONS D-055).

## 4. Review pipeline

Checks run cheapest first; each stage sees only what passed the one before. A PR merges once every stage its tier needs has passed.

| Stage | Tiers | Who and model | Reads | Writes | Passes when |
|---|---|---|---|---|---|
| 1. CI | all | GitHub Actions | the PR | checks; tier in the step summary | green |
| 2. Mechanical checks | where useful | Haiku subagent, under 100k tokens | diff, markers, logs | notes in the PR | nothing flagged |
| 3. L3 review | all | fresh session per PR (or per small batch of tier-C PRs); strongest model for tier A | diff, cited IDs, the brief | verdict in the PR (format below) | accept |
| 4. Lens screen | A, B | fresh session per bundle | §4 checklist below | `reviews/<lens>/` | no blocker open |
| 4a. Security section | A | separate fresh session, strongest model | the same | `reviews/security/` | signed |
| 5. Merge | all | primary coordinator only (§7) | — | — | stages above passed |

Never a standing reviewer session: the one long-lived reviewer cost 27% of the first week.

**L3 verdict format.** First line `Verdict: accept|fix-list|reject`. Every verdict except accept adds a line `Cause: spec-gap|brief-gap|defect|scope` naming the main cause of the rework:

- `spec-gap`: SPEC.md is ambiguous or silent on what the PR had to decide.
- `brief-gap`: the brief left out something the package needed.
- `defect`: the code breaks a cited requirement or an invariant.
- `scope`: the review asks for something outside the cited IDs; such points are `release` or `later` (§2), not blockers, and the verdict should normally have been accept.

Each fix-list point cites a requirement ID or a concrete defect and carries its class (§2). METRICS counts causes per week, so L4 can tell whether to fix the spec, the briefs, the builders or the reviewers.

**Lens screen checklist.** The coordinator starts one fresh session per bundle: the tier A and B PRs that passed L3 when the screen starts, at least daily while any PR waits, from every team.

1. Read the bundle's diffs, the IDs they cite, the active DECISIONS rows and each lens README (`reviews/security/`, `reviews/potency/`, `reviews/ux/`). Not whole files, not transcripts. The run index for a lens is one command: `grep -H -e '^Record:' -e '^Verdict' reviews/<lens>/*.md`.
2. For each PR, apply each lens's question and method. Tier B gets one combined pass; tier A gets UX and Potency here and Security in its own session (stage 4a). A tier-A diff confined to assurance tooling (`tools/depaudit*`, `tools/canary*`, `assurance/`, `tools/risk_tier*` and their tests) gets no UX pass: its messages are `later` under §2 (D-086).
3. Write one verdict per lens per PR to `reviews/<lens>/YYYY-MM-DD-pr<N>.md` (for a tier-B combined pass, `reviews/combined/YYYY-MM-DD-pr<N>.md`), in the L3 format above, and link it from the PR. Under the title put one line, `Record: PR #N · package <ID> · head <SHA>`, where `PR`, `package` and `head` are literal, e.g. `Record: PR #400 · package DOC-4 · head a74ee45` (a bundle lists several; `PR none` if there is no PR); `tools/doclint.py` requires it from 2026-10-09. The record files, in filename order, are the run index: no lens README keeps a run table, so no PR edits one.
4. Settle tensions between lenses in the same session under `reviews/arbitration/README.md`; write any resolution to `reviews/arbitration/YYYY-MM-DD-pr<N>.md`. Only a real fork goes to Mark: one question answerable in one word, with a recommendation.
5. Skip any finding kind a lens README lists under "Checks that replaced findings": CI already catches it.

**Recurring findings become checks.** When the same kind of finding appears on a second PR, the next package that touches the area adds a lint rule, test or CI check that catches it, and the lens README lists it under "Checks that replaced findings". Reviewers then stop looking for it by hand.

Lens memory lives in DECISIONS.md and the lens READMEs, not in a session. There are no standing lens, reviewer or builder sessions.

## 5. Sessions, sizing and models

The rules are in CLAUDE.md §Budget; the reasons and procedures are here.

- **Why one package or one review per session:** every call rereads the whole context (§1), so a session that carries a finished package into the next one pays for it on every later call. A brief of 20k tokens or less, done under 150k, keeps the reread small; a package that cannot fit is split before it starts.
- **Why fresh sessions instead of revived ones:** a session idle more than an hour has dropped out of cache, and waking it rewrites its whole context to cache (the 29% of §1).
- **Why cold starts count most:** at the §1 price weights one cold start costs about as much as 40 warm calls over the same context. The weekly cost routine counts them per merged PR: sessions started, wakes after more than an hour idle, model switches, compactions.
- **Pick the model at spawn.** A model switch mid-session rewrites the whole context to the new model's cache (inferred from session counters; the caching docs don't state it). A second opinion from another model is a fresh review session from the diff, which L3 needs anyway.
- **Before a long idle.** A session past 150k that will wait more than an hour on CI or review writes a hand-off packet and stops watching; the coordinator starts a fresh session when the PR next needs work. Below 150k, waking it is usually no dearer than a fresh start, whose fixed prefix (system prompt, tools, CLAUDE.md) plus packet is rewritten anyway (inferred).
- **Coordinator.** It routes, and merges (§4 stage 5) in its own turn, batching merge-ready PRs; investigation goes to a thread, so its context stays flat. A separate merge session would add a cold start. Its replacement is up to the harness, so there is no recycle rule.
- **Chat posts.** Per thread: one acknowledgement, one result, one blocker reply; progress goes in the status checklist. Each post is another call at full context, and a thread reply probably also wakes the coordinator (inferred).
- **Hand-off packet** when a session must continue elsewhere (20k tokens or less): the task and its BOARD ID; the failing check and its output, trimmed; the files that matter, with paths; what was tried and why it failed; the next step. Never a transcript.
- **Models.** Tier-A authoring and tier-A reviews use the strongest model. Mechanical subagent work uses Haiku under 100k tokens (it costs 5x above). Judgement subagent work uses Sonnet. Where PLAN.md §4's initial routing table differs, this line wins.
- **Pilots** of a cheaper route run as a BOARD row with the measures that judge them, and the result goes to DECISIONS.md.
- **Sonnet pilot (from 2026-10-08, through the 2026-10-13 reset):** every tier B and C builder session runs on Sonnet 5.5: the coordinator starts it with that model, choosing the tier from the brief's declared scope; tier A stays on the strongest model. Before opening its PR the builder runs `tools/risk_tier.py`; if it prints A, the builder stops and writes a hand-off packet, and the coordinator continues the work in a strongest-model session. Each PR's Budget section names its builder model. Judge on PRs merged from 2026-10-08 to the 2026-10-13 reset against those merged the week before 2026-10-08: first-pass L3 accept, L3 rounds per merged PR and `Defect:` lines within 7 days of merge, counted by hand from the `Builder model:` lines (METRICS.md does not split by model); usage per merged PR from METRICS.md, the 2026-10-11 week against the 2026-10-04 week, noting the latter carries three pilot days, which narrows any gap. Keep Sonnet for B/C if none is worse; otherwise revert. The result is recorded in DECISIONS.md.

- **Idle limit:** a PR or `building` row with no activity for 48 hours is finished, handed off with a packet, or returned to `queued` with its PR closed (branch kept). No draft is exempt: drafts held under CODEX-1 follow the same rule (D-096, replacing D-086 item 7's exemption).
- **PR cap:** at most about 10 open PRs per lane (docs/LANES.md), drafts included. Over the cap, the lane finishes, hands off or returns to `queued` its oldest idle PR before opening another; the coordinator does the closing, branches kept (D-096). METRICS.md follows once WIP-1 lands.
- **Scope freeze (D-096):** until G2 passes, no new rows or follow-ups for the open-source bridge, the second line, fuzz in the loop or learning sources beyond one; LATER rows FRZ-oss, FRZ-line2, FRZ-fuzz and FRZ-learn list them. A new row names the G1 or G2 test it serves or is `later`.
- **Questions for Mark** go to docs/MARK-QUEUE.md, one line each, answerable in one word, with a recommendation. Mark answers the queue in one sitting; an answered line moves to DECISIONS.md.

**Coordinator chat layout** (token rules for any team's coordinator; Mark, 2026-10-09 and 2026-10-10). A chat-based project runs on these rules; a second subscription's team (§7) follows them in its own project.

- **Chat only manages threads.** The project chat creates and manages threads; everything else goes in a thread. Keep thread cards few: batch related mechanical work into one thread where one-review-per-session allows, hang every card under a single anchor post, and resolve each thread as soon as it finishes so it collapses to one line.
- **Four standing threads**, each replaced by a numbered successor after about 30 replies or 100k tokens of context:
  - *Decisions*: every multiple-choice question for the owner, as a decision card.
  - *Questions*: the owner asks, Claude answers there.
  - *PR updates*: merges, review verdicts and conflicts.
  - *Alerts*: blockers, failures and anything else needing the owner's attention.

  Work threads report results in their own thread and route decisions and alerts through the coordinator. The owner pins the current version of each standing thread; Claude has no pin tool, so every successor's root post ends with "Pin this one and unpin the previous one."
- **Merges.** Mark, 2026-10-09: "if all reviews accept I don't need to approve to merge just do it." Merge with no question when every required review accepts the current head, CI is green and it merges cleanly; this includes SPEC PRs and D-048 exceptions. A merge goes to Decisions only when reviewers disagree or a required review is missing. If the permission check refuses, cite the owner's typed approval of this rule; if it still refuses, stop and post in Alerts what was refused with a direct GitHub link so the owner can merge it, and never try another route.
- **Asks to the owner.** Mark, 2026-10-09: "Typing the text doesn't help, don't do that" and "Ideally give me a card to press." Every ask is a card to press, never a phrase to type. Where a card tap cannot satisfy a permission check, say so and give the one action that clears it: a GitHub link, a named permission prompt, or the physical step.
- **Blocked threads.** Mark, 2026-10-10: "When threads are marked blocked check to see if actually blocked." Before telling the owner anything is blocked, check the PR's live state on GitHub (it may be merged, closed or superseded) and whether the block is only an approval that the merge rule above already covers. Raise only what truly needs the owner's hands. Thread surveys and status labels go stale, so verify each against GitHub; a close announced in a comment may not have taken effect, so confirm the PR's state after closing it.
- **Blocked threads get a card or no block.** Mark, 2026-10-10: "Currently there are blocked threads. They should either be cards in here for me to unblock or they shouldn't be blocked" and "Every time there are blocked threads ask this question." Whenever any thread shows as blocked, the coordinator checks it at once against GitHub's live state and the owner's existing approvals. A stale block is resolved, a block the owner's existing approvals cover is told to proceed, and a block that truly needs the owner becomes a decision card. No thread is left blocked without a card. A relayed card tap does not satisfy the permission check for closing PRs, so such a card carries direct GitHub links for the owner to act on.
- **Coordinator cost rules.** Count cold starts (new sessions, wakes after more than an hour idle, model switches, compactions) per merged PR and minimise them. Pick the model at spawn and never switch mid-thread; a second opinion is a fresh thread. The coordinator routes and merges in its own turn, batched; investigation goes to a thread. Per thread: one ack, one result, one blocker reply, with progress in the status checklist. Wait by subscription, not polling. Never wake an idle thread for new work; start a fresh one (D-094).

**Package records.**

- **Brief** (`briefs/<ID>.md`): what the builder reads. Goal, requirement IDs, declared file scope, dependencies, the usage estimate, and anything the coordinator learned that the builder needs, including the "Recurring kinds" each lens README lists for the touched area, as acceptance criteria. 20k tokens or less. The BOARD row links it and stays one line.
- **Assumptions** (`<package>/ASSUMPTIONS.md`): what the package's code rests on, one table row each: `# | Assumption | Spec basis | If it changes`. The builder writes it; reviewers check the code against it. When an assumption is settled, it becomes a SPEC.md change or a DECISIONS row and its line is struck through with the pointer. Keep it under about 3k words; past that, the package is probably two.

## 6. Weekly measures

METRICS.md (generated daily by `.github/workflows/metrics.yml`, once CONV-0 lands) carries first-pass L3 accept, L3 rounds and causes per merged PR, usage per merged PR, defects after merge and CI flakes, and the convergence measures of D-086: open PRs and `building` rows by age, follow-up rows created per merged PR by source review, and rows promoted from later to release. Usage comes from the manual readings in LEDGER.md, the only hand-kept input; Mark adds a reading when he chooses. Session-level spend (cache-write share, cold starts per merged PR, spend by role) is measured by the weekly cost routine outside the repository; any figure from it that drives a decision is copied into LEDGER.md with its date before anyone relies on it. Targets: first-pass accept rising toward 50%; L3 rounds per merged PR falling toward 1.5; cold starts per merged PR falling; follow-up rows per merged PR under 0.5; nothing idle past the §5 limit. Guard: if promotions from later to release or `Defect:` lines run above their baseline two weeks in a row, D-086's narrower release class is reverted. The earlier target of a cache-write share under 20% assumed reads at 0.1x; at 0.05x a session must reread its context about 160 times before writes fall to a fifth of input cost, so it was dropped (D-092).

## 7. Working in parallel: a second subscription or another coding agent

Extra capacity (a second subscription, a teammate's agent, or another vendor's coding agent) multiplies progress only if the teams never build the same thing and never disagree about what is true. The design:

**One source of truth: the repository.** Chat history and any team's private memory are not sources of truth; a decision that matters is written to DECISIONS.md before anyone relies on it.

**Disjoint lanes.** Each team owns whole subsystems behind stable interfaces, listed in docs/LANES.md. A team changes files only inside its lane. A change that must cross a lane boundary is an interface change: it goes as a PR to the owning team, or as an issue labelled `lane:<name>` if it needs their design.

**Claims on BOARD.md.** A team claims a row by a PR or commit to main that sets the row's state to `building` and its owner to the team name, before any work. A row with an owner belongs to that team until its state changes. Two claims on one row: the earlier merged one wins and the other stops.

**One merge authority.** Only the primary coordinator merges to main, after the stages its tier needs (§3, §4). Other teams open PRs; they do not merge, and they never push to another team's branch. Branch stems carry the team: `pkg/<team>-<id>-<slug>`.

**Each team reviews its own PRs; the primary team gates.** A team runs the L3 review (§4 stage 3) on its own PRs, on its own subscription, and marks a PR ready only after an accept, linking the verdict in the PR. The primary team then runs the lens screen on tier A and B PRs before merging; a tier C PR merges on the team's L3 accept and green CI (§4 stages 4–5).

**GitHub is the bus.** PRs and issues carry everything between teams: claims, interface requests, blockers, review verdicts. No team needs access to another team's chat, sessions or memory.

**Hand-off to a new team** is one onboarding PR from the primary team that adds the team's lane and an onboarding section to docs/LANES.md: the BOARD rows in its lane with their state, and the interfaces it may call. The new team's first session reads only that PR plus README.md's reading order for its role.

**Credentials stay with their owner.** No team shares a subscription login, token or key with another, in the repo or anywhere else. Each team runs on its own account.

**Terms.** Anthropic subscriptions may be used only through Claude Code and claude.ai; a second Claude subscription for the same person needs its terms checked before purchase. OpenAI's Codex CLI on a ChatGPT plan is OpenAI's own tool and fine on its own account. AGENTS.md is the entry point Codex reads.

**Chat coordination.** Each team's coordinator follows the coordinator chat layout in §5 (standing threads, merge rule, asks as cards, verified blockers).

Lanes, and each team's onboarding record, are in docs/LANES.md.
