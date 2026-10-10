# AgentOS

A computer for delegated work. Frontier AI you already pay for does the reasoning; a drive you plug into any PC does the executing, remembering, and improving, under your sole control. You direct it by text or phone call.

**Status:** pre-alpha, not yet usable by an owner. What is being built now, and what is done, is on [BOARD.md](BOARD.md).

## Documents

Each fact has one home; other files point to it rather than restate it ([docs/OPERATING.md](docs/OPERATING.md), "Where facts live"). `tools/doclint.py` checks that this table lists every top-level document.

| File | Kind | What it is | Changed by |
|---|---|---|---|
| [SPEC.md](SPEC.md) | what to build | The system specification. Requirement IDs like `CRED-1` are normative. | L1 spec-diff PR, Mark approves |
| [PLAN.md](PLAN.md) | how it is phased | Phases, the nested build loops (L0–L4), budget calibration history. | L1 |
| [CLAUDE.md](CLAUDE.md) | rules | The working contract for builder and reviewer agents, one line per rule. | L4 proposes, L1 adopts |
| [AGENTS.md](AGENTS.md) | rules | Entry point for agents other than Claude Code; points to CLAUDE.md. | L1 |
| [docs/OPERATING.md](docs/OPERATING.md) | procedures | The reasons and procedures behind the rules: triage, risk tiers, review pipeline, sessions, parallel teams. | L1, Mark decides |
| [BOARD.md](BOARD.md) | state | Index of work packages: one line each with state and owner, linking its brief. | L1, L2 |
| `briefs/<ID>.md` | state | One package's brief: goal, IDs, scope, dependencies, estimate. | L1 |
| [LATER.md](LATER.md) | state | Which open rows the first release needs, and the backlog that waits. | L1 |
| [docs/LANES.md](docs/LANES.md) | state | Which team owns which paths; onboarding records. | primary team |
| [docs/MARK-QUEUE.md](docs/MARK-QUEUE.md) | state | Questions and actions only Mark can take, one line each, with a recommendation. | L1 adds, Mark answers |
| [docs/conv-3-triage.md](docs/conv-3-triage.md) | state | Class of every open PR (merge-ready, finish, parts bin, superseded, stale) and the close list (Q3, D-090). | CONV-3, then L1 |
| [DECISIONS.md](DECISIONS.md) | record | Decisions as `D-NNN` rows with date, status and source; long reasoning in `decisions/D-NNN.md`. | L1, Mark |
| `reviews/<lens>/` | record | Lens methods (README) and lens verdicts per PR. | lens screen |
| `<package>/ASSUMPTIONS.md` | record | What each package's code rests on. | its builder |
| [LEDGER.md](LEDGER.md) | input | Manual usage readings from Mark's usage screen; METRICS reads them. | L1 |
| [METRICS.md](METRICS.md) | generated | Weekly L4 inputs: first-pass accept, review rounds and causes, usage, defects. | `metrics` workflow |
| [TRACE.md](TRACE.md) | generated | Which tests cover which requirement IDs. Never edited by hand. | `trace` workflow |
| [docs/owners-guide.md](docs/owners-guide.md) | product | The guide for the box's owner. | builders, with the features it describes |

## Reading order by role

Read in this order and stop when you have what you need. Token counts are approximate.

| Role | Read | About |
|---|---|---|
| Builder (L2) | CLAUDE.md; your `briefs/<ID>.md`; the SPEC.md sections for the IDs it cites; the touched package's `ASSUMPTIONS.md` | 3k + brief + cited sections |
| Reviewer (L3) | CLAUDE.md; OPERATING §2–4; the diff; the cited SPEC.md IDs; the brief | 5k + diff |
| Lens screen | OPERATING §4 checklist; active DECISIONS rows; the lens READMEs; the bundle's diffs | 10k + diffs |
| Coordinator (L1) | CLAUDE.md; OPERATING; BOARD.md; LATER.md; recent DECISIONS rows | 15k |
| Another team | AGENTS.md; CLAUDE.md; docs/LANES.md (your lane); OPERATING §7; then the builder row above | 6k + builder |

No license has been chosen yet; all rights reserved until one is (spec OSS-12).
