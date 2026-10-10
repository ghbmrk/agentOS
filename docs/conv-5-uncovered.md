# The 24 uncovered requirement IDs (CONV-5)

What blocks each ID that TRACE.md lists as uncovered (135 of 159 covered at the CONV-1 head), so the first-release date can be read from this list. Brief: [CONV-5](../briefs/CONV-5.md). The classes are the builder's reading of SPEC.md; a fresh L3 checks five of them (CONV-5 acceptance). Tiers are expected, from the paths each row will touch; `python3 tools/risk_tier.py` is authoritative when the row's brief is written.

Classes: **buildable now** (cloud-buildable; dependencies are in Needs), **stand-in** (testable against `tools/hostcheck_standin.sh`, the S1 test kit or a VM or S5 fixture before real hardware), **environment-blocked**, **hardware-blocked**, **spec-blocked**.

## Classification

| ID | Class | Blocker or route | Row |
|---|---|---|---|
| HW-3 | buildable now | Owner's guide and card name UEFI x86-64 as the supported host; the image-config half (no legacy-boot target) folds into IMG-1. Real boot proof is S1's. | HW-3t |
| HW-4 | hardware-blocked | The N95 floor box (GEEKOM Air12 Lite); the 4-core, 8 GB measurements need it. | MARK-QUEUE A7 |
| HW-6 | hardware-blocked | Screenless USB boot and per-model boot-key recipes need S1's three PCs, USB4 SSD and hands. `broker/hostchange` cites HW-6 but nothing tests it. | MARK-QUEUE A2 |
| HW-7 | buildable now | Negative requirement: Macs are not boot targets. A docs test, same row as HW-3. | HW-3t |
| CRED-2 | spec-blocked | The stated trusted base is rewritten by D-082 (guarantee claims); a test now would target text CONV-4 changes. | CONV-4 (D-082) |
| CRED-11 | stand-in | Broker verbs `copy`, `paste`, `hand-off` against the S5 fixture executors. Needs CRED-4b part 2. | CRED-11a |
| ONB-2 | stand-in | Host disk never written: hostcheck stand-in disk plus HOST-1e's harness. Part 2 waits on P2-1's image. | HOST-1a, HOST-1e (existing) |
| ONB-9 | buildable now | One plan line per usage pool from stub-CLI pool state; needs RES-5a and the Wi-Fi page. | ONB-9a |
| CAP-2 | stand-in | Reach: uncredentialed browsing from an agent machine to a local fixture site through egress, plus S5's credentialed fixture and a granted local-device fixture. Umbrella ID, no new component. | CAP-2t |
| CAP-7 | environment-blocked | Two frontier participants on one task needs two providers' accounts (A3). It is guest behavior, so CONV-2 should ask whether it is a release test. | MARK-QUEUE A4 |
| CAP-11 | environment-blocked | S8's cloud part is merged; the live route needs Claude and ChatGPT plan logins (A4) and a supervised session for S8-W1 (D-064). | S8-live, S8-W1 (existing) |
| CAP-12 | buildable now | The `resources` broker tool over stub routes and pools. Needs RES-5a and CAP-9. | CAP-12a |
| CAP-13 | buildable now | The six local passes as broker tools over a stub local-model endpoint; measured figures on the N95 wait on A7 and are not part of this row. | CAP-13a |
| ADP-5 | stand-in | Kiosk and file-dialog confinement in a VM fixture; needs CRED-4b. Lane claude2 (D-050). | ADP-5 (existing) |
| ADP-6 | buildable now | Adapters change only through §11; the same row as ADP-8. Lane claude2. | ADP-8 (existing) |
| ADP-8 | buildable now | Mismatch check against a demo environment with synthetic data. Row says unblocked. | ADP-8 (existing) |
| ADP-13 | environment-blocked | The box's own mailbox is an account at a free mail provider; the live run needs one test account. The fixture part waits on CRED-4b, P2-6m and CH-21. | MARK-QUEUE A6; ADP-13 (existing) |
| ADP-14 | stand-in | Web recipes against an S5 fixture site and a demo environment. Needs CRED-4b and ADP-8. | ADP-14a |
| ADP-15 | stand-in | Composited desktop over fixture executors. Needs CRED-11a and ADP-5. | ADP-15a |
| ADP-16 | stand-in | Suite executor with fixture apps of one account. Needs ADP-5. | ADP-16a |
| OSS-12 | environment-blocked | Waits on Mark's licence choice (D-041, date `Pending`). No class fits a decision; the blocker is named instead. Upstream-notice preservation is checkable now and rides the first row that ships a LICENSE. | MARK-QUEUE Q4 |
| RES-5 | buildable now | Pool tracker and reserve admission against S8 stub CLIs. | RES-5a |
| UPD-7 | buildable now | Soak plus attestations, no project-run rollout. Likely already exercised by M6's tests in `broker/maintain`; first step is to add the `REQ: UPD-7` marker, then fill any gap. | UPD-7t |
| UPD-9 | buildable now | Held security fix put to the owner. Wiring (`maintain.Loop3`) and the D3 and O2 registrations are W5b's. | W5b (existing) |

Counts: buildable now 10, stand-in 7, environment-blocked 4, hardware-blocked 2, spec-blocked 1 (24).

## Queued rows

Each row's acceptance test and failure path, for its brief. A row does not start before its Needs are merged.

| Row | IDs | Acceptance test | Failure path | Tier | Needs |
|---|---|---|---|---|---|
| HW-3t | HW-3, HW-7 | `tests/test_supported_hosts.py`: owners-guide and card text name UEFI x86-64 as supported and Windows-on-ARM, pre-UEFI PCs and Macs as unsupported. | A host outside the list is refused with the plain-words reason, not booted half-way. | C | none |
| RES-5a | RES-5 | Stub CLI reports per-pool use and reset; admission is refused when a run would take any pool it draws on past the owner's reserve, with reserve 0% by default. | Unreadable pool state: broker-held mode refuses the plan route and falls back to the API route; worker-held mode is advisory (CAP-11) and the run and wall-clock caps still bound it. | B | S8 (merged) |
| ONB-9a | ONB-9 | Wi-Fi page and STATUS text render one line per pool with use and reset time; at-reserve line names the reset and whether work waits. | Pool state absent: the line says "usage unknown", never a stale figure. | B | RES-5a, P2-2w |
| CAP-12a | CAP-12 | `resources` returns kind, qualified task classes, pool headroom, marginal cost and concurrency per granted route, with no credential or account detail in the output (canary check). | A route with no measurement reports "unmeasured", not a guess. | B | RES-5a, CAP-9 |
| CAP-13a | CAP-13 | Each of reduce, retrieve, extract, triage, check and draft is callable; a pass outside the set is refused; `check` rejects a result that fails its schema. | Local model unavailable: the pass returns `unavailable` and the main route proceeds unaided. | B | ARC-6 (merged) |
| CAP-2t | CAP-2 | Fixture run: agent machine browses a local site through egress uncredentialed; S5 fixture browses credentialed; a granted local-device fixture is reached and an ungranted one is not. | A destination outside egress or grants is refused and journaled. | B | CRED-4b part 2 |
| CRED-11a | CRED-11 | `copy` never reads a password field, `paste` never fills one, `hand-off` moves a file between workspace directories only; no verb path shares clipboard, display or file system. | A refused verb returns a typed error and journals; data labels follow the item. | A | CRED-4b part 2 (lane claude2) |
| ADP-14a | ADP-14 | Recipe maps each submit to a verb on a fixture site; an unknown site stops at the first state-changing request and raises one approval in fixed wording. | A background request overlapping a submit's shape is rejected at adoption. | A | CRED-4b part 2, ADP-8 (lane claude2) |
| ADP-15a | ADP-15 | One composited screenshot over two fixture executors; each action reaches exactly one executor; per-window withholding applied. | A window id outside the agent's set is refused; cross-account data moves only through CRED-11. | A | CRED-11a, ADP-5 (lane claude2) |
| ADP-16a | ADP-16 | Suite of fixture apps of one account shares an executor; an app of another account is refused; turning it on is a new-grant intent. | An app without a saved-login condition is excluded, not started. | A | ADP-5 (lane claude2) |
| UPD-7t | UPD-7 | Stable proposes a release only after soak and at least `MinPasses` early-channel attestations; no code path reads a project-run rollout setting. | Too few attestations: the release stays unproposed and the digest says why. | C | none (broker/maintain M6) |

## Findings

- `later`: CONV-5-1's class list has no "decision-blocked" class; OSS-12 is recorded as environment-blocked with the decision named.
- `later`: CAP-7 is guest behavior; CONV-2 should judge it against the release test.
- `release`: the rows above (queued, not built here).
