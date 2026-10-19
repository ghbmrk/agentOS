# JRN-startup-reconcile-s3: pin where agentosd runs the FORGET boot resume

Board section: Security and architecture review (2026-10-08). Work item: #1410. Source: Security R1 and Potency PT1 on PR #1382. **Tier A** (`broker/cmd/agentosd`). Serves CAP-3, RCH-4. Edits `forget_resume_test.go`; do not run beside other work on `forget.go`.

**Why / failure path.** `TestForgetResumeIsWiredOnlyThroughWireResume` (`forget_resume_test.go:169`) counts call sites only (`calls != 1 || onOpen != 1 || boots == 0`), so each of these passes the whole suite while breaking the FORGET take-back:
- R1: `resumeBoot()` right after `wireResume`, before `daemon.Run`, which closes `booted` before the gate, owner channel and agent attach.
- Q1: `resumeBoot()` dropped from the recall-on arm (`main.go:~969`).
- Q2: dropped from the recall-off arm (`main.go:~976`): the owner is never told `forgetAgentNotOpen`.
- Q3: `wireResume(ctx, nil)` with recall configured: recall wired as off.

**Requirements:**
- JRN-s3-1: each arm of the `recallDir != "" && verifier != nil` if/else calls `resumeBoot()` (kills Q1, Q2).
- JRN-s3-2: every `resumeBoot()` call comes after `lp.attach(` and after `forgetOwner.agent.Store(` in source order (kills R1).
- JRN-s3-3: `wireResume`'s second argument is the identifier assigned from `recallExec.OnOpen` (kills Q3).
- JRN-s3-4: the existing production wiring passes all three (no `main.go` change expected; if one is needed, say why in the PR).

**Acceptance tests:** (REQ: JRN-s3-1..4)
- `broker/cmd/agentosd/forget_resume_test.go::TestForgetResumeIsWiredOnlyThroughWireResume`, extended: one subtest per requirement, each run against a mutated copy of the parsed `main.go` source (the five mutants above) that must fail, plus the real source that must pass.

**Out of scope.** s4, s5 and r3 of #1382 (separate rows; the coordinator may batch them into one build later).

**Scope:** `broker/cmd/agentosd/forget_resume_test.go`, `broker/cmd/agentosd/ASSUMPTIONS.md` (RO1 note), this brief; `main.go` only if JRN-s3-4 fails.

**Usage estimate:** 40k tokens; checkpoint at 30k.
