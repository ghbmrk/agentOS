# JRN-startup-reconcile-s3: pin where agentosd runs the FORGET boot resume

Board section: Security and architecture review (2026-10-08). Work item: #1410. Source: Security R1 and Potency PT1 on PR #1382. **Tier A** (`broker/cmd/agentosd`). Serves CAP-3, RCH-4. Edits `forget_resume_test.go` only, so it can run beside other work on `forget.go`; open #2285 (INFER-SVC) edits `broker/cmd/agentosd/main.go`, which this test reads, so a build that must change `main.go` waits for it (D-111). Moving the call sites into a helper was considered and dropped on purpose: the test pins the existing wiring instead.

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
- `broker/cmd/agentosd/forget_resume_test.go::TestForgetResumeIsWiredOnlyThroughWireResume`, extended: one subtest per requirement, each run against a mutated copy of the parsed `main.go` source (the four mutants above) that must fail, plus the real source that must pass.

**Out of scope.** s4, s5 and r3 of #1382 (their issues are closed).

**Scope:** `broker/cmd/agentosd/forget_resume_test.go`, this brief; `main.go` only if JRN-s3-4 fails.

**Usage estimate:** 40k tokens; checkpoint at 30k.
