# JRN-startup-reconcile-s3: pin where the FORGET boot resume runs, and that it runs (with s4)

Board section: Security and architecture review (2026-10-08). Source: Security delta R1 with Potency PT1, and R2, on PR #1382 (https://github.com/ghbmrk/agentOS/pull/1382#issuecomment-6156722954). Rows s3 (#1410) and s4 (#1411), class release, tier A. One brief for both: they test the same `wireResume` and `resumeBoot` pair. s5 and r3 have their own brief (`JRN-startup-reconcile-s5.md`).

**Why it matters.** Recurring kind: a defence can be reverted and the suite still passes. `TestForgetResumeIsWiredOnlyThroughWireResume` counts call sites but not their position or value flow, and nothing exercises the boot resume `wireResume` returns when recall is on. Each of these mutants passes `./cmd/agentosd/` today:
- R1: main calls `resumeBoot()` right after `wireResume`, before `daemon.Run`. That closes `booted` before the gate, the owner channel and the agent are attached (Security S1 on #1382).
- Q1: `resumeBoot()` dropped in the recall-on branch. The boot's own OnOpen resume is gone.
- Q2: `resumeBoot()` dropped in the recall-off branch. The owner is never told `forgetAgentNotOpen`, and a resume reconcile started waits forever.
- Q3: `wireResume(ctx, nil)` with recall configured. Recall is wired as if off, so the owner is told "cannot" before recall opens.
- R2: with recall on, the returned boot resume is a no-op. Restored-log take-backs (`resumeRestored`), owed done-texts (`judgeAgent`) and journal-held item 2s from an earlier boot run only through it when startup reconcile queues nothing, so the agent keeps work the owner asked to forget.

**Requirements:** CAP-3, RCH-4.

**Fix (tests only; no production change expected).**
- S3: strengthen the AST test in `forget_resume_test.go`: each arm of the recall if/else in main calls `resumeBoot()`; every `resumeBoot()` call comes after `lp.attach(` and after `forgetOwner.agent.Store(`; `wireResume`'s second argument is the identifier assigned from `recallExec.OnOpen`. If that cannot be expressed cleanly, move the if/else (with `recallExec.Off()`) into one helper that the behaviour test calls and orders. A helper move touches `main.go`; keep it a pure move.
- S4: a behaviour test of the recall-on boot resume with no Reconcile call.

**Acceptance tests:** CAP-3, RCH-4: `TestForgetResumeIsWiredOnlyThroughWireResume` (extended, `broker/cmd/agentosd/forget_resume_test.go`) and `TestForgetBootResumeRecallOnWithoutReconcile` (new, same package).

**Tests first.**
- T1 mutation check per Q1, Q2, Q3, R1: apply each by hand to a copy of main.go (or by the AST test's own source) and see the extended test fail. Record the five in the PR as a table; do not commit the mutants.
- T2 `TestForgetBootResumeRecallOnWithoutReconcile`: recall on, no Reconcile call, a journal-held item 2 and a restored take-back present. After `boot()` and the recall open, both are taken back and the owner's done-text is judged. A no-op boot resume fails it.
- Control: existing `./cmd/agentosd/` tests stay green.

**Out of scope.** Changing `wireResume` behaviour, s5/r3 (fence replies), recall's open path.

**Guard files:** none.

**Scope:** `broker/cmd/agentosd/forget_resume_test.go`, `broker/cmd/agentosd/forget.go` and `main.go` only for the helper move above, this brief.

**Dependencies:** s5 (merged: `noRecall` is in `forget.go`). The s5 brief says s3 and s4 touch `main.go` and wait behind #2015; check that PR's state at start and do not build while it or any other open PR touches these files (D-111).

**Usage estimate:** 60k tokens, checkpoint at 60k. Builder model: strongest (tier A: `main.go`, `forget.go`).
