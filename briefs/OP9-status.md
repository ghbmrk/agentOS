# OP9-status: STATUS names every capability that is off or can't run

Board section: Phase 3: compounding. LATER.md class: Release (A11, OP-9).

**Goal.** OP-9: when a capability is off or cannot run because of the host (memory, hardware), configuration (a missing image or grant) or a held decision (a security fix not installed, a provider refusing the line's sign-in), STATUS names it in one owner-worded line with what would fix it, and the digest repeats it while it lasts. A log line alone is not enough. Owner choices (LOOPS OFF, PINNED) are named once when made, then listed in the digest, never repeated as alerts. A11 also needs: with learning unable to run (memory too small, no builder, no model grant), STATUS names the cause.

**Requirement IDs.** OP-9 (acceptance A11). Related, owned elsewhere and not re-covered here: LOOP-1 to LOOP-6 (P3-2), LOOP-9/10 (P3-4, P3-4b-1), RES-2 (agent off on a small host), UPD-9 (held security fix).

**Needs.** P3-2, P3-4 (both merged).

**Scope (declared; touch nothing else).**
- `broker/cmd/agentosd/status.go` (new): one registry of capability lines, built from the sources below.
- `broker/cmd/agentosd/status_test.go` (new): tests carrying `REQ: OP-9`.
- `broker/cmd/agentosd/main.go`, `learn.go`, `agent.go`: wire existing `cfg.Notes` entries through the registry; no behaviour change to the lines that already exist.
- `broker/control/handler.go` (only if a note needs ordering or dedupe in `status()`).
- `broker/owner/channel.go` (only for the digest hand-off, `TakeDigestNotes`).
- `broker/cmd/agentosd/ASSUMPTIONS.md`.

**Tier.** `tools/risk_tier.py` gives **A** for these paths: `broker/cmd/`, `broker/control/` and `broker/owner/` are all in `TIER_A_BROKER`. The scope as drafted therefore does not fit the Sonnet pilot (builder runs `risk_tier.py` and must stop and hand off on A). Coordinator: start the builder on the strongest model, or have L1 narrow the scope to `broker/cmd/agentosd/status*.go` only; `cmd` is still A, so narrowing does not change the tier. The brief itself (this PR) is tier C.

**Usage estimate.** About 90k tokens to green, checkpoint at 90k. Split before starting if the audit below needs more than the `agentosd` package.

**What the builder must know.**

STATUS is `control.Handler.status()` (`broker/control/handler.go`). After "Running."/"Stopped." and the request lists it appends each `Handler.Notes` func's non-empty line, in order. The agent line is separate (`cfg.AgentStatus`). The local page reuses the same text (`owner.Channel.LocalStatusLines`). Each note returns "" when nothing is wrong, so a cause that never reaches a note is silent today. Capabilities that can be off, and where the state lives (verify each; this list is from a grep, not an audit):

| Capability | Cause | State and line today |
|---|---|---|
| Agent machine | host memory too small | `Params.AgentOff` set in `main.go` (~l.828) "Agent: off, this box has … of memory …" |
| Agent machine | no delegated cgroup | `agentNoLimits` (`cgroot.go`), set in `main.go` ~l.499 |
| Agent machine | plane not yet open | `agentNotSet` (`agent.go`), via `lateStatus` in `main.go` |
| Agent machine | asleep while learning | `sleepStatus` (`sleeper.go`), a state, not a fault |
| Learning (Loop 1) | memory too small for replay | `learning.noRoom`, `noRoomNote` (`learn.go`) |
| Spare-time work | learning plane failed to open | `learningOff`, `learningOffNote` "not running", gives no cause or fix |
| Loop 2 checks | never run, overdue, partial | `loops.Guard.Status()` with `NotRun` reasons (`loops/secure.go`) |
| Loop 3 updates | offline, checks off, not checked | `maintain.Loop3.Status().Line` (`maintain/maintain.go`) |
| Memory/recall | failed to open | `recalltool.LateExecutor.Status()` |
| Machine disk quota | quota unavailable or `-disk-quota=off` | `quotaNote` (`diskquota.go`) |
| Owner line | provider sign-in refused or line unreached | `secondLine.Note`/`TextsNote` (`secondline.go`) |
| Time check | clock unchecked | `clock.Guard.Status()`, `questions.go` `q.Clock` |
| Security fix | held (pinned, ask, box never free) | UPD-9; no STATUS source found: check `maintain` and `update` |

Known gaps to settle first, each classed per CLAUDE.md:
1. Cause-less lines (`learningOffNote`, recall failure) need an owner-worded cause and fix; same fix as a blocker.
2. `evidence.go` says the digest's sender "is not wired yet". OP-9's "digest repeats it" half may have no sender to attach to. If so, record it as a finding: blocker only if a sender exists; else a `release` row.
3. LEARNING OFF/LOOPS OFF/PINNED must be named once then listed in the digest, not repeated: no existing test covers this.
4. LEARNING "no builder" and "no model grant" (A11) have no line found; confirm in `broker/loops`/`loopbuild`.

**Tests first.** One failing test per row above that is a real cause: build the daemon config in that state and assert STATUS contains one owner-worded line with a fix; one test that an owner choice does not appear as an alert; one for digest repetition if gap 2 allows. Synthetic data only.

**Assumptions.** Record in `broker/cmd/agentosd/ASSUMPTIONS.md`: lines stay one per cause, ordering by existing `Notes` order, and a source returning "" means healthy.

**Out of scope.** New capabilities, new owner commands, spec changes (SPEC.md moves only via L1 spec-diff PR), the G4 floor-host run.
