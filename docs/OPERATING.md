# Operating model

How AgentOS is built for the most progress per weekly limit at the same quality. CLAUDE.md holds the short rules; this file holds the reasons and the procedures. Any agent, from any subscription or vendor, works from this file, CLAUDE.md, SPEC.md, PLAN.md, BOARD.md, LATER.md and DECISIONS.md. Nothing it needs lives anywhere else. Decided by Mark on 2026-10-07 (DECISIONS.md, COST-1).

## 1. What limits progress

The only hard limit is the weekly subscription allowance. Measured over the week of 2026-10-04 (COST-1, PR #294), list-equivalent spend split into:

| Part | Share |
|---|---|
| Cache reads (rereading context on every call) | 54% |
| Cache writes (new or woken context) | 29% |
| Output | 17% |

By role, builders were 51.5%, one long-lived reviewer session 26.6%, lens sessions 13% and coordinators 6%. The first-pass L3 accept rate was 12% (METRICS.md), so most packages were built more than once.

Cost per merged package = (calls × context per call × read price + writes + output) ÷ first-pass rate.

Levers in order of effect:

1. **Cut rework.** Raise the first-pass rate and build only what the first release needs (§2, §4).
2. **Shrink context per call.** Small briefs, compaction at 200k, fresh sessions instead of revived ones (§5).
3. **Fewer calls per package.** One package per session; batch reviews (§4).
4. **Route by model price.** Use the cheapest model that keeps quality, and check with tests rather than with a more expensive model (§5).
5. **Fill capped time with free CI.** Fuzzing, race soak and mutation run on Actions while the allowance resets.

## 2. Finding triage: blocker, release, later

Every finding (L3, lens, CI soak, an agent's own observation) gets one class at the moment it is raised. Whoever raises it assigns the class; the reviewer can correct it.

| Class | Meaning | Where it goes |
|---|---|---|
| **blocker** | Breaks a requirement the PR cites, or an invariant. | Fixed in the same PR before merge. |
| **release** | Needed to pass an acceptance test in SPEC §15 (A1–A15) or an invariant, but not in this PR's scope. | A new BOARD.md row, named in the PR's Findings line. |
| **later** | Anything else: polish, hardening beyond the spec, nice-to-have wording. | One line in LATER.md. No package is started for it before the first release ships. |

Security findings on tier-A paths are never `later` unless they are purely wording. When unsure between two classes, pick the stricter one and say so.

LATER.md also holds the critical-path audit of BOARD.md: each open row is marked release or later. The coordinator does not start `later` rows. A row moves to release only with the acceptance test it now blocks.

## 3. Risk tiers

Review depth follows risk, decided mechanically from the paths a change touches. `python3 tools/risk_tier.py --git origin/main HEAD` prints the tier; CI writes it to the PR's step summary. A change takes the highest tier of any path it touches.

| Tier | Paths (tools/risk_tier.py is authoritative) | Review |
|---|---|---|
| **A** | broker packages holding credentials, isolation, effects, owner auth, update and supply chain (vault, tpmseal, egress, grants, verb, journal, reversible, sockets, guest, vm, workers, cgroup, owner, control, card, modem*, localapi/localsrv/localui, cleanroom, hint, pubid, attest, update, apply, change, replay, sipsign, smsapi, sendrules, clock, recovery, hostdisk, hostchange, vendor), `broker/go.mod`, `broker/go.sum`, `assurance/`, `tools/canary*`, `tools/depaudit*` | Fresh L3 on the session's strongest model with an explicit threat check, then the batched lens screen with a separate Security section. A later delta that changes security-relevant semantics needs a Security re-sign. |
| **B** | other `broker/` packages, `guest/`, SPEC.md (which also needs Mark through an L1 spec-diff PR) | Fresh L3, then one combined UX/Security/Potency pass in the batched screen. |
| **C** | docs, tooling, CI, spikes, tests outside tier-A packages, BOARD/LATER/DECISIONS | Fresh L3 and CI only. |

A new broker package that holds credentials or gates effects is added to `TIER_A_BROKER` in the same PR that creates it. A renamed tier-A package fails `tests/test_risk_tier.py` until the list is updated.

## 4. Verification waterfall

Checks run cheapest first, and each stage only sees what passed the one before:

1. **CI**: unit tests, trace check, fuzz, race, the tier summary.
2. **Mechanical checks** by a Haiku subagent under 100k tokens where useful: wording rules, marker coverage, log triage.
3. **Fresh L3 review**: a new session per PR (or a small batch of tier-C PRs), from the diff plus the cited requirement IDs. Never a standing reviewer session; the one long-lived reviewer cost 27% of the first week.
4. **Batched lens screen** for tier A and B PRs that passed L3: the coordinator starts one fresh session per bundle of ready PRs (a bundle is whatever is ready when the screen starts; at least daily while any PR waits). The session reads the diffs, the cited IDs, DECISIONS.md and `reviews/<lens>/README.md`, and writes one verdict per lens per PR to `reviews/<lens>/`. Tier A PRs get their Security section in a separate fresh session on the strongest model. Lens tensions are settled in the same screen under `reviews/arbitration/README.md`; only a real tradeoff goes to Mark.
5. **Merge** once the stages the tier needs have passed.

Lens memory lives in DECISIONS.md and the lens READMEs, not in a session. There are no standing lens, reviewer or builder sessions.

**Recurring findings become checks.** When the same kind of finding appears on a second PR, the next package that touches the area adds a lint rule, test or CI check that catches it, and the lens README notes the rule. Reviewers then stop looking for it by hand.

## 5. Sessions, sizing and models

- **One package or one review per session.** A package brief is 20k tokens or less and is sized to finish under 150k tokens of context. A package that cannot is split before it starts.
- **Hand-off packet** when a session must continue elsewhere (≤20k tokens): the task and its BOARD ID; the failing check and its output, trimmed; the files that matter, with paths; what was tried and why it failed; the next step. Never a transcript.
- Compaction is at 200k (`.claude/settings.json`); don't raise it.
- **Models.** Tier-A authoring and tier-A reviews use the strongest model. Mechanical subagent work uses Haiku under 100k tokens (it costs 5x above). Judgement subagent work uses Sonnet.
- **Sonnet pilot (from the 2026-10-11 reset, one week):** tier B and C builder packages run on Sonnet 5.5; tier A stays on the strongest model. Compare against the week before on first-pass L3 accept, L3 rounds per merged PR, `Defect:` lines within 7 days of merge, and usage per merged PR. Keep Sonnet for B/C if none is worse; otherwise revert. The result is recorded in DECISIONS.md.

## 6. Weekly measures

METRICS.md (generated weekly by `.github/workflows/metrics.yml`) carries first-pass L3 accept, L3 rounds per merged PR, usage per merged PR, defects after merge and CI flakes. Session-level spend (cache-write share, spend by role) is measured from session usage by the weekly cost routine and written to `/mnt/project-files/cost/weekly.md`. Targets: first-pass accept rising toward 50%; L3 rounds per merged PR falling toward 1.5; cache-write share under 20%.

## 7. Working in parallel: a second subscription or another coding agent

Extra capacity (a second subscription, a teammate's agent, or another vendor's coding agent) multiplies progress only if the teams never build the same thing and never disagree about what is true. The design:

**One source of truth: the repository.** Everything an agent needs is in this repo: this file, CLAUDE.md (AGENTS.md points other vendors' agents to it), SPEC.md, PLAN.md, BOARD.md, LATER.md, DECISIONS.md and `reviews/*/README.md`. Chat history and any team's private memory are not sources of truth; a decision that matters is written to DECISIONS.md before anyone relies on it.

**Disjoint lanes.** Each team owns whole subsystems behind stable interfaces, listed in the Lanes table below. A team changes files only inside its lane. A change that must cross a lane boundary is an interface change: it goes as a PR to the owning team, or as an issue labelled `lane:<name>` if it needs their design.

**Claims on BOARD.md.** A team claims a row by a PR or commit to main that sets the row's state to `building` and its owner to the team name, before any work. A row with an owner belongs to that team until its state changes. Two claims on one row: the earlier merged one wins and the other stops.

**One merge authority.** Only the primary coordinator merges to main, after the stages its tier needs (§3, §4). Other teams open PRs; they do not merge, and they never push to another team's branch. Branch stems carry the team: `pkg/<team>-<id>-<slug>`.

**Each team reviews its own PRs; the primary team gates.** A team runs the fresh L3 review (§4 stage 3) on its own PRs, on its own subscription, and marks a PR ready only after an accept, linking the verdict in the PR. The primary team then runs the batched lens screen on tier A and B PRs and spot-checks tier C before merging. Bundles from all teams go through that screen at least daily, so PRs don't drift from main.

**GitHub is the bus.** PRs and issues carry everything between teams: claims, interface requests, blockers, review verdicts. No team needs access to another team's chat, sessions or memory.

**Hand-off to a new team** is one onboarding PR from the primary team that: adds the team's row to the Lanes table; lists the BOARD rows in its lane with their state; and links the interfaces it may call. The new team's first session reads only that PR plus the files listed above.

**Credentials stay with their owner.** No team shares a subscription login, token or key with another, in the repo or anywhere else. Each team runs on its own account.

**Terms.** Anthropic subscriptions may be used only through Claude Code and claude.ai; a second Claude subscription for the same person needs its terms checked before purchase. OpenAI's Codex CLI on a ChatGPT plan is OpenAI's own tool and fine on its own account. AGENTS.md is the entry point Codex reads.

### Lanes

| Lane | Team | Paths |
|---|---|---|
| everything | primary (Claude, Mark's subscription) | all |

Rows are added by the onboarding PR for each new team; the primary team's lane shrinks to match.
