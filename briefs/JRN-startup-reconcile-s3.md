# JRN-startup-reconcile-s3: pin where agentosd runs the FORGET boot resume

Board section: Security and architecture review (2026-10-08). Work item: #1410. Source: Security R1 and Potency PT1 on PR #1382. **Tier A** (`broker/cmd/agentosd`). Serves CAP-3, RCH-4. Edits `forget_resume_test.go` and the startup wiring in `main.go` (#2285, which also edited `main.go`, has merged). Step-back (coordinator, 2026-10-20, after the OPERATING §4 round cap on PR #2513): pinning main's data flow statically kept leaving shape escapes, so the recall guard and the boot order now live in one agentosd function, `wireBootRecall` plus its `finish`, which main calls once. A runtime test drives that function with fakes and asserts the call sequence; the static check pins only the single wire and finish calls.

**Why / failure path.** `TestForgetResumeIsWiredOnlyThroughWireResume` (`forget_resume_test.go:169`) counts call sites only (`calls != 1 || onOpen != 1 || boots == 0`), so each of these passes the whole suite while breaking the FORGET take-back:
- R1: `resumeBoot()` right after `wireResume`, before `daemon.Run`, which closes `booted` before the gate, owner channel and agent attach.
- Q1: `resumeBoot()` dropped from the recall-on arm (`main.go:~969`).
- Q2: dropped from the recall-off arm (`main.go:~976`): the owner is never told `forgetAgentNotOpen`.
- Q3: `wireResume(ctx, nil)` with recall configured: recall wired as off.

**Requirements:**
- JRN-s3-1: `bootRecall.finish` runs the boot resume whether recall is on or off, and main calls `wireBootRecall` and `finish` exactly once each (kills Q1, Q2).
- JRN-s3-2: main wires before `daemon.Run` and calls `finish` after `daemon.Run`, `lp.attach` and `lp.forgetOwner.agent.Store`, on those exact receivers (kills R1).
- JRN-s3-3: recall counts as on only when both `recallDir` and the verifier are set; then `wireResume` gets `recallExec.OnOpen`, and otherwise nil plus `recallExec.Off()` (kills Q3).
- JRN-s3-4: the production wiring in `main.go` passes all three.

**Acceptance tests:** (REQ: JRN-s3-1..4)
- `broker/cmd/agentosd/forget_resume_test.go::TestBootRecallFinishOrder`: drives `wireBootRecall` and `finish` with fakes, recall on and off, with and without learning, and asserts the call sequence (JRN-s3-1, JRN-s3-3).
- `broker/cmd/agentosd/forget_resume_test.go::TestForgetResumeIsWiredOnlyThroughWireResume`: the real `main.go` passes, and each mutated copy fails only its listed requirement (JRN-s3-1..4).

**Out of scope.** s4, s5 and r3 of #1382 (their issues are closed).

**Scope:** `broker/cmd/agentosd/forget_resume_test.go`, this brief; `broker/cmd/agentosd/main.go` (the wiring factored into `wireBootRecall`).

**Usage estimate:** 40k tokens; checkpoint at 30k.
