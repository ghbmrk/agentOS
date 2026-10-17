# JRN-startup-reconcile s5: recall off with no agent machine does not promise a later take-back

Board section: Security and architecture review (2026-10-08). Work item #1412 (Security delta R3 on PR #1382). The issue groups s3, s4, s5 and r3 into one follow-up brief; the coordinator dispatched s5 alone with scope `forget.go` (s3 and s4 touch `main.go` and wait behind #2015, dispatch 2026-10-17-0014), so this brief covers s5 only.

**Requirement IDs:**
- **CH-12** (SPEC): a text that reports a wait names a step that can work. With recall off and no agent machine, item 2's text promised "I will do it when it runs again", which cannot happen with recall off.
- **RCH-4** (SPEC): the take-back is told as recall can carry it; with recall off it cannot be carried.

**Failure path.** Recall off (`wireResume` called with `onOpen` nil) and no agent machine (runsc unset or machines disabled): the boot resume reaches `agentBack` with a nil agent and sends `forgetAgentNoAgent`. The owner waits for a take-back and a text that never come.

**Work.** `wireResume`'s recall-off branch sets a `noRecall` mark (and clears it on the recall-on branch); `agentBack` checks it before the nil-agent promise and sends `forgetAgentNotOpen`. Only `wireResume` assigns the mark; the AST wiring test covers it.

**Lifecycle (restart).** Integration owner: this package (`wireResume`, `agentBack`). Outcomes by stage, recall off or on × agent machine present or not × reconcile before or after boot setup:

| Recall | Agent machine | Told |
|---|---|---|
| off | yes | `forgetAgentNotOpen` once (unchanged) |
| off | no | `forgetAgentNotOpen` once (this package) |
| on | yes | `forgetAgentDone` once (unchanged) |
| on | no | `forgetAgentNoAgent` once (unchanged) |

**Acceptance tests:**
- CH-12, RCH-4: `broker/cmd/agentosd/forget_resume_test.go::TestForgetItem2ResumeWaitsForBootSetup`, four new rows (no agent machine, recall off and on, reconciled before and after boot setup); catches the recall-off, no-agent pair telling `forgetAgentNoAgent`.
- CH-12: `forget_resume_test.go::TestForgetResumeIsWiredOnlyThroughWireResume` fails if `noRecall` is assigned outside `wireResume`.

**Scope:** `broker/cmd/agentosd/forget.go`, `broker/cmd/agentosd/forget_resume_test.go`, `broker/cmd/agentosd/ASSUMPTIONS.md`, this brief. Tier A.

**Guard files:** none.

**Recurring kind** (Security lens): a problem text names a step that cannot work.

**Usage estimate:** small (one field, one branch, test rows).
