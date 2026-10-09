# OP9-status: STATUS names every capability that is off or can't run (OP-9)

Board section: Phase 3: compounding. Written 2026-10-09 against SPEC OP-9 and A11 as on main, and agentosd as on main. Replaces the placeholder at the end of [P3-4b.md](P3-4b.md#op9-status-now-briefed-separately).

## Goal

> **OP-9** When a capability is off or cannot run because of the host (memory, hardware), configuration (a missing image or grant), or a held decision (a security fix not yet installed, a provider refusing the line's sign-in), STATUS MUST name it in one owner-worded line with what would fix it, and the digest MUST repeat it while it lasts. A log line alone is not enough. Owner choices (LOOPS OFF, PINNED) are named once when made and then listed in the digest, never repeated as alerts.

A11 also asks: "With learning unable to run (memory too small, no builder, no model grant), STATUS names the cause (OP-9)." TRACE.md shows OP-9 uncovered.

## What exists on main (inventory, 2026-10-09)

STATUS is one sink, `control.Handler.status()` (`broker/control/handler.go`). It writes the journal counts, then `Machines()` (agentosd's agent line, `daemon.Config.AgentStatus`), then the first line of each `Notes[i]()`, each clipped to 100 characters (`plainLine`). There is no registry: notes are appended where each feature is wired (`cmd/agentosd/main.go`, `learn.go`, `build.go`, `diskquota.go`, `questions.go`, `follow.go`, `evidence.go`, `secondline.go`; the clock note comes first, `fit_test.go`).

**There is no digest sender.** No production code calls `change.Pipeline.Digest`, `Scheduler.Digest`, `Guard.Digest`, `Loop3.Digest`, `secondLine.Digest`, `evidence.digestLines`, `question.Book.TakeDigest`, `events.Attention.TakeDigest` or `owner.Channel.TakeDigestNotes`. `question/ASSUMPTIONS.md` says so too. `change.Pipeline.Notice(key, line)` queues a line once per key. `main.go` queues `pe7:sleep-mode` (`sleepDigest`, `sleepwire.go`) through it once. Only `stepNotes.digest` (SR2-3s, `main.go`) uses it to repeat a line, daily for 7 days and then weekly. It exists only while the learning plane is open (`lp != nil`).

Each row below is one capability that can be off. "Line" is what STATUS says today. Rows marked **silent** have no STATUS line, which breaks OP-9 today.

| # | Capability | Cause class | Trigger (main) | Line today | Fix named? |
|---|---|---|---|---|---|
| H1 | Agent, host too small (RES-2) | host | `mem.AgentOff`, `memPlan` (main.go) | "Agent: off, this box has X GB of memory and running the agent needs about Y GB." | no |
| H2 | Agent, no delegated cgroup | host | `openMachines` fails, `agentNoLimits` (cgroot.go) | "Agent: off, the box can't yet keep the agent within its limits; it needs an update." | vague |
| H3 | Agent machines, no disk quota (or `-disk-quota=off`) | host | diskquota.go | "Agent machines are off: this box's disk can't limit what each one writes." and two variants | no (the log names `prjquota`; STATUS does not) |
| H4 | Learning, no room to test changes (PE2, PE7 sleep mode) | host | `noRoom`, `replayFits` (main.go, learn.go) | `noRoomNote` "Learning: paused, the box's memory is too small to test changes." / `sleepModeNote` | no |
| C1 | Agent machine not set up: `-runsc` empty, `vm.Open` fails, the guest plane fails, agent image missing or unregistered, bad launch.json | config | main.go (`agentSpec`, the `md.err` paths) | `agentNotSet` "Agent: not set up; the box needs an update or a restart." for some paths. Others only log ("agent machines disabled", "no agent machine kept running") | generic |
| C2 | Model route: `-egress` unset or the vault's model socket unreachable. The agent gets no model, and Loop 1 runs without model evaluation (`ModelWired`) | config | main.go (`modelWired`) | **silent** | — |
| C3 | Learning plane failed to open | config | main.go (`openLearning`), learn.go | `learningOffNote` "Spare-time work: not running." The HELP and settings replies say a restart may fix it; STATUS does not | no |
| C4 | Loop 1 builder: no image, or open failed | config | build.go | `builderOffNote` and `builderUnsetNote` | the off line only |
| C5 | Loop 2 checks not run (hash, advisory, drift, expiry) | config | `loop2NotRun` (loop2.go), `Guard.Status` | "Loop 2: partial (not run: …, needs the updater; …)." | names a component, not an owner action |
| C6 | Loop 2 finding with no fixer | config | `waitNoFixer` (loops/report.go) | "… waits for a fix: I cannot build one yet." | no (LATER P3-4b-1 l6) |
| C7 | Recall off: `-recall` or `-owner-verify` empty (`recallExec.Off()`) | config | main.go | **silent**: `LateExecutor.Status` returns "" when off, and nothing is logged | — |
| C8 | Recall failed to open | config | main.go (`exec.Failed()`) | "Memory did not open; agents cannot fork or merge" | no |
| C9 | Owner questions plane failed (no clock note either) | config | main.go ("owner questions disabled") | **silent**: log only | — |
| C10 | Worker tools: `-worker-image` empty or unregistered | config | main.go | **silent**: log only, and nothing at all when empty | — |
| C11 | Update checks: `maintain.Loop3` is not constructed in agentosd (W5b queued), so no update or security check runs | config | learn.go (`Sources` = Loop 1 + Guard) | **silent** | — |
| C12 | Routing changes held: no routing target (`heldRouting`) | config | learn.go | **silent** in STATUS. A digest notice exists per refused rule (W3-route) | — |
| C13 | Evidence email failing or refused | config | evidence.go | "Emailing replies: failing since …" | yes |
| D1 | Second line: provider refuses the sign-in or can't be reached | held decision | secondline.go | "Second line: confirm your provider on the box's Wi-Fi page. …" and the texts lines | yes |
| D2 | Rollback snapshots failing (SR2-3s) | config | `stepNotes` (main.go) | yes, and repeated in the digest | yes |
| D3 | Security fix held by PINNED or ASK (UPD-9) | held decision | `maintain.Loop3.pendingLine` | **unreachable**: Loop3 is not wired (C11) | text exists in maintain |
| D4 | Plan route withdrawn; a task class with no qualified route (CAP-9, CRED-5) | held decision | `route.RouteWithdrawn`, `no_route` (broker/route, vault process) | **not wired** into agentosd | — |
| O1 | LOOPS OFF, or one loop paused (owner choice) | owner choice | `Scheduler.Settings` | none. `Scheduler.Shares()` (LOOP-3 "unmeasured") has no production caller. `Scheduler.Digest` has "Spare-time work is off. Reply LOOPS ON to restart it." but is never sent | digest text has it |
| O2 | PINNED or security updates set to ASK (owner choice) | owner choice | maintain | unreachable (C11) | — |

**Not capabilities under OP-9** (recorded as assumptions, no line): accelerators off or not found (RES-3: inference runs on the CPU, nothing is lost, `accel.Pool.Summary` log), no PSI (an admission input only; the memory budget still bounds admission), `-modem-bridge` off and `-localui-uid -1` (simulator and test builds; a texted STATUS can't arrive without the bridge, and the shipped image always sets both).

## Split

| Row | What | Needs | Tier | Class | Estimate |
|---|---|---|---|---|---|
| OP9-status-a | One capability-line registry for STATUS and the digest; every **silent** row above (C1 paths, C2, C7, C9, C10, C11, C12) gets its line; the A11 learning-cause test | P3-2, P3-4 (merged) | A (`broker/cmd/agentosd`) | release (A11, OP-9) | ~110k |
| OP9-status-b | Fix clauses for every existing line that lacks one (H1–H4, C3, C4, C5, C6, C8); loop 2 wording (LATER P3-4b-1 l6, l8); owner choices and the loop-shares line (O1, LOOP-3); D3 and O2 wired when W5b's Loop3 lands | OP9-status-a, P3-4b-1b, P3-4b-5 (all touch `loop2.go`, `learn.go` or `loops/report.go`; P3-4b-5 changes when C6 occurs) | A (`broker/cmd/agentosd`; `broker/loops` is B) | release (OP-9, LOOP-3) | ~90k |
| DIG-1 | Daily digest sender (CH-15): one daily text that takes every `Digest()` source, the registry's lines included. Not part of this brief: a new BOARD row, brief to write | W5 owner channel, OP9-status-a (creates `digestSources`) | A | release (CH-15, OP-9) | — |

D4 belongs to CRED-5f ("plan route withdrawn with no API key granted must still route or tell the owner"). When it lands in the vault process, its owner line enters through the registry. CRED-5f's brief should say so; this brief doesn't change it.

Build order: -a; then -b once P3-4b-5 has merged; DIG-1 after -a. -a touches `learn.go` for registration only and doesn't wait for P3-4b-5. Whichever of -a and P3-4b-5 merges second merges main first and keeps both sets of tests green. -b waits for P3-4b-5 because P3-4b-5 wires a fixer into `learn.go` and `loop2.go`. After that, C6 ("no fixer") holds only while no builder is set up, so -b words C6 for that case. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening each PR. Both are A by path (`cmd`), so each runs on the strongest model. The Sonnet pilot's hand-off rule doesn't apply here.

## Definitions (shared by -a and -b)

**Capability line.** One owner-worded sentence, at most 100 characters (STATUS clips there). It has the form `<capability>: <state>; <fix>.`, for example "Worker tools: not set up on this box; an update will add them." It holds no flag names, paths, socket names or error text. Those stay in the log. The log line stays as it is, next to the STATUS line.

**Fix clause.** It names the owner's step when there is one ("check the server name on the box's Wi-Fi page", "restart the box", "reply LOOPS ON"). When no owner step can fix it (a build gap, or hardware the owner can't change in place), it says so plainly and names what will fix it: "nothing to do; a later box version adds it", or "needs a box with 8 GB of memory or more". See open question Q1.

**Cause line, not capability line.** One cause that turns off several capabilities gives one line that names them all. For example, `-runsc` empty turns off the agent machine and worker tools: "Agent and worker tools: not set up on this box; …". STATUS stays short and still names each capability (Q2).

**Registry.** A single list in agentosd (a new `cmd/agentosd/capoff.go` or similar). Each entry has a stable key, a cause class (host, config, held decision, owner choice) and a `func() string` that returns the line while the condition lasts and "" once it clears. Each entry is computed live from current state, never latched, so the line goes away as soon as the condition clears. The registry is appended to `cfg.Notes` once, after the clock note, **whether or not the learning plane opened**. It does not use `change.Pipeline.Notice`, because Notice needs `lp`. Existing notes move into it as -a and -b touch them. They are not rewritten for their own sake.

**Digest repetition.** The registry has `Digest() []string`: the current lines of every non-owner-choice entry, plus the owner-choice listing (O1, O2), recomputed on each call. "Repeats while it lasts" then means each digest takes `Digest()` and gets the line while the condition holds and not after. No sender exists (DIG-1), so the acceptance tests call `Digest()` directly. A test also keeps `Digest()` in the one list of digest sources that DIG-1 will read: a `digestSources` slice in agentosd, created here, which also holds `Scheduler.Digest` and `secondLine.Digest`.

**Owner choice.** An owner choice is never a STATUS alert line or a pushed text beyond its confirmation reply, which already exists (`loops.Confirm`). It does appear in `Digest()` while it is set, and in STATUS's loop-shares line as "off (you turned it off)". OP-9 forbids repeating it as an alert. STATUS is pulled, not pushed, so listing it there is allowed (assumption 4).

## OP9-status-a: registry and the silent cases

**IDs:** OP-9, A11 (OP-9 clause). RES-2 is not claimed here: H1 moves into the registry unchanged, and -b carries its test.

**Scope:** `broker/cmd/agentosd/` only: the new registry file and its test, the wiring edits in `main.go`, `learn.go`, `questions.go`, `build.go` (for registration only), `agent.go`, and `ASSUMPTIONS.md` (a new "Capability lines (OP9-status)" section). No change to `broker/control`, `broker/daemon` or `broker/loops`. If one looks necessary, stop and escalate (scope). Run `go test -race ./cmd/agentosd/`.

**Intended change:**
1. The registry, the `digestSources` list and the wiring, as defined above. The agent line (`AgentStatus`) stays where it is, in `Machines`. C1's paths that only log today get a line through the registry while the agent line reads `agentNotSet`. They don't add a second agent line.
2. C1: every path that leaves the agent machine off gives a line. Paths whose cause the owner can act on are worded separately, so a restart is not suggested where it can't help. Today `agentNotSet` says "an update or a restart" for all of them.
3. C2: model route unset or unreachable. Probe the socket at start and on each STATUS, with a short timeout and cached at most 1 minute. The line names the agent and learning: "Model: not reachable, so the agent can't think and learning can't test changes; restart the box." If the vault process reports no granted route at all ("no model grant", A11), say "no AI plan or key is connected; connect one on the box's Wi-Fi page". If agentosd can't tell those two apart from what it sees today, record that in ASSUMPTIONS and raise it as a release finding against CRED-5f. Don't add a vault call here.
4. C7: recall off. The line says what the owner loses ("Memory across tasks: off on this box; …"). It replaces assumption 3 of the existing agentosd ASSUMPTIONS ("Recall off … has no STATUS line"). Update that row and strike through the old reading.
5. C9: questions plane failed. The line says agents' questions can't reach the owner and the time check is off.
6. C10: worker tools off (empty or unregistered image).
7. C11: update checks not running. Keep the line until W5b constructs `maintain.Loop3`. W5b then removes it, with a test (see ASSUMPTIONS).
8. C12: routing changes held. The line says learning can't change how work is routed. Owner choice is excluded: no line while the owner has learning off.
9. Learning-cause line for A11: when learning is on by the owner's setting but can't run, STATUS names one cause from {memory too small (H4), no builder (C4), no model grant or route (C2), plane failed (C3)}. Today these are separate notes. Keep them, and add a test that each cause alone gives a STATUS that names it.

**Acceptance (each a test with a `REQ:` marker; one test per capability-off case):**

| ID | Criterion |
|---|---|
| OP-9 | For each of C1 (each path: runsc empty, vm open fails, guest plane fails, image missing), C2, C7, C9, C10, C11 and C12: with the condition induced, `Handler.Status()` holds exactly one line naming the capability, ≤100 characters, with a fix clause. With the condition absent, no such line. Table-driven is fine, but each case is its own subtest named for the row. |
| OP-9 | Each line above appears in the registry's `Digest()` while its condition holds and is gone from the next `Digest()` after it clears (C2: socket comes back; C11: a stub Loop3 source registered). |
| OP-9 | The registry is in STATUS when the learning plane failed to open (`lp == nil`), and its `Digest()` still returns lines then. |
| OP-9 | No registry line contains a flag name (`-runsc`, `-egress` …), a path, a socket name or `%v` error text. A planted line with one fails the test. |
| OP-9 | `digestSources` holds the registry, `Scheduler.Digest` (when learning opened) and `secondLine.Digest` (when configured). |
| A11 | Learning on but unable to run: memory too small, no builder, no model grant or route, each alone. STATUS names that cause. All three are subtests of one `REQ: A11, OP-9` test. |
| OP-9 | Order: the clock note stays first (`fit_test.go`'s order test still passes), and existing note tests are unchanged. |

**Checkpoint:** at ~70k, items 1–3 and the C2 test must be green. If not, or the projection passes 150k, stop and move C10–C12 to -b.

## OP9-status-b: fix clauses, loop lines and owner choices

**IDs:** OP-9, LOOP-3, RES-2 (H1: the agent is off on a too-small host and STATUS says so, with the fix), A11 (H4 and C4 wording, already tested in -a; keep those tests green).

**Scope:** `broker/cmd/agentosd/` (`learn.go`, `build.go`, `diskquota.go`, `cgroot.go`, `main.go`, `loop2.go`, the registry, tests, ASSUMPTIONS.md); `broker/loops/` for owner text only (`report.go` `waitNoFixer`, the `Guard.Status` join, a `Scheduler` owner-choice listing), with the wording scan (`TestOwnerWordingNeverClaimsDetection`) kept green; `broker/control/` (`text.go` `plainLine`, the apostrophe clip at `handler.go`) for item 6 only. Run `go test -race ./cmd/agentosd/ ./loops/ ./control/`.

**Intended change:**
1. Give a fix clause, per the definition, to each existing line that lacks one: H1 (name the memory needed), H2, H3 (for example "this box's disk format can't limit each machine; an update may add it"), H4, C3 ("restart the box"), C4 (the unset variant), C5 (say whether anything will make the check run: "a later box version adds the updater"), C8. Move each into the registry. H4's sleep-mode entry replaces the one-time `pe7:sleep-mode` Notice (`main.go`). Remove that Notice so the digest gets the line once, from the registry, every day sleep mode lasts. `sleepDigest`'s text may be the registry's digest wording, because digest lines aren't clipped to 100 characters.
2. C6 and LATER P3-4b-1 l6: "waits for a fix: I cannot build one yet" becomes "no repair is set up on this box yet; an update may bring one". LATER P3-4b-1 l8: one "Loop 2:" prefix when a partial line and a wait line join. Close both LATER rows in this PR.
3. O1 and LOOP-3: a STATUS line shows spare-time work by loop from `Scheduler.Shares()`: "off (you turned it off)", "unmeasured", or a share in words. Loop 2 reads "unmeasured" until it has carried a finding to containment (the P3-4b placeholder's owner item). LOOPS OFF and a paused loop are listed in `Digest()` (the scheduler's existing lines) and are never a registry alert entry.
4. D3 and O2: if W5b has merged `maintain.Loop3` wiring by the time -b starts, register `Loop3`'s pinned and ask lines (UPD-9) in the registry: D3 as a held decision with a fix ("reply UPDATES STABLE to take it"), O2 as an owner choice, listed in the digest only. If not, leave a W5b condition in ASSUMPTIONS (assumption 5) and don't build it here.
5. Worker tools named under H1/H2 (release, L3 R2 on #525; builder S10): when an H1 or H2 agent line holds, including `openMachines` failing and the cgroup failure, STATUS also names worker tools as off. Today `workers()` is not reached and only the agent line shows. Acceptance: each of H1, H2 and the cgroup failure gives a line (or the agent line) that names worker tools, with a fix clause.
6. `plainLine` keeps apostrophes (release, L3 R3 on #525; builder S9; UX point 3): `broker/control/text.go` `plainLine` drops `'`, so `noRoomNote` and `agentNoLimits` read "boxs" and "cant"; the clip applies at `broker/control/handler.go` to Machines and every Note. Let it keep `'`, safely: the reply grammar's concern is line breaks and leading characters. Add `broker/control/` to scope. Acceptance: a note holding an apostrophe renders intact in Machines and Notes, and line-break and leading-character injection tests stay green; `TestLearningUnableToRunNamesTheCause` drops its `ReplaceAll(c.want, "'", "")`.

**Acceptance:**

| ID | Criterion |
|---|---|
| OP-9 | For each of H1, H2, H3 (each variant), H4 (both no room and sleep mode), C3, C4 (both variants), C5, C6 and C8: with the condition induced, STATUS holds one line ≤100 characters with a fix clause. The existing tests (`TestPE6ABoxTooSmallForTheAgentSaysSo`, `TestQuotasOffIsAStatusLine`, `TestStatusSaysWhenTheBuilderDidNotStart`, `TestStatusSaysWhenNoBuilderIsSetUp`, `TestPE2NoRoomForReplayIsSaid`, the learn and loop2 note tests) are updated to the new text, not deleted. |
| RES-2 | On a host too small for the agent, STATUS's agent line says the agent is off, names the memory it needs, and gives the fix. `TestPE6ABoxTooSmallForTheAgentSaysSo` gains the `REQ: RES-2` marker and asserts the fix clause. |
| OP-9 | Sleep mode: the digest holds the sleep-mode line exactly once per `Digest()` call while it lasts, from the registry. `pe7:sleep-mode` is no longer queued through `Notice`. |
| OP-9 | Each of those lines is in the registry's `Digest()` while it lasts and gone after. |
| OP-9 | Owner choice: LOOPS OFF, and one loop paused, each give their confirmation reply once and appear in `Digest()` while set. They are never a registry alert entry and never a pushed text. After LOOPS ON, they leave `Digest()`. |
| LOOP-3 | STATUS's loop line reads "unmeasured" for Loop 2 before its first contained finding and a share after, and "off (you turned it off)" under LOOPS OFF. |
| OP-9 | C6 wording: the wait line holds "no repair is set up on this box yet", and a partial line followed by a wait line holds "Loop 2:" once. The wording scan stays green. |
| OP-9 (if item 4 is built) | A staged security update held by PINNED gives a STATUS line with the UPDATES STABLE fix and a `Digest()` line every day until it is installed or declined. PINNED itself is listed in `Digest()` only. |

## Assumptions to record (`broker/cmd/agentosd/ASSUMPTIONS.md`, section "Capability lines (OP9-status)")

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| 1 | "The digest repeats it while it lasts" is met by a live `Digest()` the digest sender reads each day. No sender exists until DIG-1. Until then the evidence is the `Digest()` tests, not a sent text. | OP-9, CH-15 | If DIG-1 dedupes repeated lines, OP-9 lines must be exempt, with a test there. |
| 2 | Accelerators, PSI, the modem bridge flag and the local page flag aren't OP-9 capabilities: nothing the owner uses is lost (RES-3, admission), or the shipped image always sets them. | OP-9, RES-3 | If the image can ship without the bridge or the page, add a line. |
| 3 | One line per cause, naming each capability that cause turns off, meets "names it in one line" (Q2). | OP-9 | If Mark rules one line per capability, split the cause lines. |
| 4 | Listing an owner choice in STATUS's loop line is not "repeating it as an alert": STATUS is pulled by the owner. | OP-9, CH-15 | Drop it from STATUS. |
| 5 | Update checks (C11), a held security fix (D3) and PINNED/ASK (O2) depend on W5b constructing `maintain.Loop3`. W5b removes C11's line and registers D3 and O2, with a test, if -b has not. | OP-9, UPD-9 | — |
| 6 | Route withdrawal and declined classes (D4) are CRED-5f's. Their line enters through this registry when CRED-5f wires it. | OP-9, CAP-9 | — |
| 7 | Build gaps the owner can't fix say "nothing to do; a later box version adds it" (Q1). | OP-9 ("what would fix it") | Reword per Mark's answer. |

## Open questions (for Mark; each has a recommended default the builder uses if no answer)

- **Q1. What is "what would fix it" when the owner can't fix it?** Several causes are build gaps (C10, C11, C5) or hardware (H1).
  - (a) Name what will fix it even if it isn't the owner's step: "nothing to do; a later box version adds it" or "needs a box with 8 GB or more". **Recommended.** It's true, it tells the owner whether to act, and it matches the clock line's "Nothing to do."
  - (b) Omit such capabilities from STATUS until an owner step exists. This contradicts "A log line alone is not enough."
- **Q2. STATUS length.** On a box where several capabilities are off, a line each can run to several SMS segments.
  - (a) One line per cause, naming each capability it turns off. All lines are texted, since STATUS is pulled and isn't paced by CH-15. **Recommended.**
  - (b) Text the first three by impact, then "+N more on the box's Wi-Fi page". Shorter, but OP-9 says STATUS MUST name each one.
- **Q3. Digest sender.** OP-9's digest half can't be met end to end until a daily digest is sent (CH-15). Nothing sends one today.
  - (a) New release row DIG-1, needing W5. OP9-status ships `Digest()` and its tests now. **Recommended**, and added to BOARD in this PR.
  - (b) Fold a minimal sender into OP9-status-a. That pulls in CH-15 pacing, quiet hours and the owner channel, which is too much for one package.

## Not in scope

The digest sender (DIG-1). Route withdrawal (CRED-5f). Constructing `maintain.Loop3` (W5b). Any SPEC.md change. LATER "OP9-status l2" (held-back field values, from #416) is about the A11 harness, not this row; it stays in LATER as is.
