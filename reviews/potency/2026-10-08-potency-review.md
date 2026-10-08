# Deep potency review — 2026-10-08

**Purpose:** unlock more accepted work, reach, parallelism and compounding without weakening security or increasing the owner's routine burden.

**Scope:** main at 7b753eb87f606ea2268ca536d429d47989dba196, plus selected pending work inspected on 2026-10-08. This is a separate advisory review from the security review and [#380](https://github.com/ghbmrk/agentOS/pull/380). It proposes priorities and bounded experiments; it changes no specification, authority, runtime, defaults, lane ownership or existing package state. Recommendations are not implementation acceptance.

## Main assessment

AgentOS's strongest advantage is the combination of persistent execution, private memory, multiple sources of intelligence, explicit authority, and improvements tested against the owner's actual work. Its potential comes from completing that cycle repeatedly: a task produces a useful result, the owner accepts or corrects it, and the next similar task takes less effort.

The most valuable next step is to make one such cycle work end to end and measure it. More model routes, workers or learned artifacts are useful only when they improve that result. The repository already has substantial machinery: a real recall index, effect journal, worker lifecycle, held-out change pipeline, replay evaluator, compiler and managed-tree delivery. Several constraints below are at the seams between these components.

Two concrete findings deserve attention before broadening the learning system: harvested effect-parameter JSON and replay's free-text replies are graded as if they were the same kind of result (P3); and the attention optimizer merges distinct templates into a class that can stop earning suggestions indefinitely (P5). Other findings include deliberate conservative limits that can be lifted with a bounded design, and integration work already planned that should not be reinvented.

**No end-to-end potency gain is measured by this review.** Source inspection and local probes establish specific behaviors; gains remain hypotheses until matched owner-workload trials pass. “No security or UX sacrifice” is an acceptance condition to test, not a claim that adding code has zero risk.

## Priorities and novelty

| ID | Opportunity | Evidence / novelty | Proposed disposition |
|---|---|---|---|
| P1 | Prove complete useful workflows and measure total owner effort | Existing integration and A10 work; narrower completion criterion | Release: complete INT-A/H6/W7-A; avoid a second harness |
| P2 | Durable task attribution, result state and native edit pickup | Source-level composition limits; extends existing goal and A3 work | Release: scoped follow-ups to P3-7, W5/W7 and mail wiring |
| P3 | Grade broker-observed results and revise authenticated outcomes | New source diagnosis; feedback revision already acknowledged | Release: fix within assembled W3/W7-A qualification |
| P4 | Scoped recall, bounded excerpts and progressive fetch | New interface improvement on an existing index | Later optimization unless A10 demonstrates it blocks acceptance |
| P5 | Earn narrow approval suggestions without mixing templates | Synthetic reproduction against unchanged attention code | Release: bounded W7/attention follow-up for CAP-6 |
| P6 | Learn model specialization from accepted tasks | Source-level proposal-quality limitation in existing routing | Release: extend CAP-9/W3 routing evidence |
| P7 | Complete resource-aware plan delegation | Already approved design and pending libraries | Release: finish CAP-11/12, RES-5 and S8 qualification |
| P8 | Qualify one local leverage pipeline | Approved CAP-13 direction; absent from reviewed live path | Release: narrow CAP-13/A10 slice before breadth |
| P9 | Carry typed results between compiled skill steps | New bounded capability; current format limitation | Later until a measured recurring workload justifies it |
| P10 | Make fork/test/keep economical; measure artifact handoff | Existing primitives; potential transfer improvement | Release: qualify existing A15 workflow; later extension only if needed |

“Release” here identifies an existing acceptance requirement or an amendment proposed to its work stream. “Later” proposals must not be started before release without promotion under OPERATING §2. This review does not assign new BOARD IDs or claim these proposals have been scheduled. Primary should split the proposed amendments into bounded briefs when accepted; executor changes go through the existing claude2 lane. Existing security remediation remains independently tracked in [#380](https://github.com/ghbmrk/agentOS/pull/380).

## What the reviewed system can currently support

| Layer | Grounded state | Implication |
|---|---|---|
| Owner/guest channel | A synthetic owner-channel test drives a guest plane with fake machine metadata and a test verifier; separate tests exercise OpenClaw. [broker/e2e/owner_test.go:81](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/e2e/owner_test.go#L81) | Valuable component evidence; not proof of the whole production service chain or an accepted business task |
| Ordinary workers | Registered worker images expose exec/files, checkpoints, fork/diff/rollback and keep. [broker/cmd/agentosd/main.go:827](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/cmd/agentosd/main.go#L827) | Use and qualify these before inventing another worker substrate |
| Learning delivery | W4 delivers the managed tree to the live private guest; learning construction already has replay, compiler and routing targets. [broker/cmd/agentosd/learn.go:128](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/cmd/agentosd/learn.go#L128) | “Wire learning” is too vague; target outcome/grader/feedback seams |
| Recall/events | Recall has full text, structured facts and vector support. The live bus is constructed with the indexing trigger. [broker/recalltool/service.go:88](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/recalltool/service.go#L88), [broker/recalltool/service.go:104](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/recalltool/service.go#L104) | Retrieval exists; always-on task triggers still need a composed, goal-bound path |
| Plan agents/resources | [#220](https://github.com/ghbmrk/agentOS/pull/220), [#221](https://github.com/ghbmrk/agentOS/pull/221) and [#222](https://github.com/ghbmrk/agentOS/pull/222) contain quota, declaration/resource and wording work; reviewed main lacks the complete plan-run path | Library availability is not a usable route or custody qualification |
| Local leverage | Accelerator discovery exists; main explicitly says no local inference service exists to take leases. [broker/cmd/agentosd/main.go:445](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/cmd/agentosd/main.go#L445) | Reserve capacity and a specification are not measured frontier savings |
| Benefit measurement | compile.Measure measures first-effect to last-outcome spans; [#258](https://github.com/ghbmrk/agentOS/pull/258) supplies a proposed matched-trial collector | Both are useful; neither establishes owner benefit without workload results |

## The work-to-improvement cycle

Owner request → broker-bound task → qualified resources → bounded execution → observed result → owner acceptance/correction → frozen evaluation → qualified improvement → next task.

Each arrow needs durable identity and evidence. In particular, an allowed action is not necessarily successful, a successful action is not necessarily a good answer, a delivered reply is not necessarily completed work, and a fast HTTP response is not necessarily an accepted task. OP-7 already requires these distinctions. [SPEC.md:310](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/SPEC.md#L310)

## P1 — Complete one useful workflow before expanding the component inventory

**Evidence.** The existing owner-channel test verifies transport and data labeling, while using a synthetic verifier and machines. The live event bus currently registers the indexing trigger, not a guest-work trigger. INT-A [#261](https://github.com/ghbmrk/agentOS/pull/261) already proposes the real service/socket matrix and recovery cuts; H6 [#258](https://github.com/ghbmrk/agentOS/pull/258) already separates owner effort, outcome, latency and usage units; W7-A [#264](https://github.com/ghbmrk/agentOS/pull/264) already proposes assembled learning experiments. Reuse these. [broker/e2e/owner_test.go:93](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/e2e/owner_test.go#L93); [broker/recalltool/service.go:104](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/recalltool/service.go#L104)

**Proposal and gain.** Choose one recurring operation with an observable result and complete the production chain: authenticated request → task identity → actual guest → broker/vault → one qualified adapter → native artifact/result → acceptance → repeat-use improvement. Add one event-triggered variant only after explicit task/event provenance is carried through; event content supplies data, never owner authority. Run a simulated external service with durable receipts before an owner-authorized real account. A working vertical slice simultaneously exposes missing integration, establishes a baseline and supplies trustworthy learning evidence.

**Security cost.** More components cross existing boundaries; do not substitute one UID, an allow-all verifier, omitted quota/cgroup controls, or live external access in replay. Preserve account reconciliation, STOP and zero duplicate effects at acknowledgment-loss cuts. The fixture runner must distinguish production-equivalent service construction from a convenient unit rig.

**UX cost.** No new normal prompts. Include setup, clarification, correcting, unblocking and recovery effort in the total, rather than shifting work outside the measured span. A task that requires the owner to repeat it after a restart has not achieved the intended autonomy.

**Acceptance experiment.** Use INT-A's actual identities and existing e2e pieces for a single send/draft workflow and its read-only counterpart, then restart at each durable boundary. Require the right artifact/effect exactly once, truthful pending/unknown states and retained work. Pair against unmodified OpenClaw and a direct provider CLI on equal accounts/tools/data; use H6, separate first-use and repeat-use, and require a predeclared useful reduction in total owner effort at preserved acceptance. This is a scheduling recommendation, not a claim that integration alone guarantees advantage.

## P2 — Give long-running work a durable identity and a real completion state

**Evidence.** Goal attribution is deliberately conservative: when more than one unanswered owner message is held in a lineage, new requests get no goal; with none open, the last goal expires after the quiet period measured from handoff. This avoids guessing, but limits overlapping or long tasks. Missing task text causes outcome harvesting to skip the case. Native mail drafts can be saved, yet the general watcher excludes Drafts; this does not establish A3's “edit on the phone and picked up” cycle. [broker/guest/goal.go:13](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/guest/goal.go#L13), [broker/guest/goal.go:58](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/guest/goal.go#L58), [broker/cmd/agentosd/tasks.go:201](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/cmd/agentosd/tasks.go#L201), [broker/mail/watch.go:118](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/mail/watch.go#L118)

**Proposal and gain.** Extend the existing owner-message/goal record into a bounded task lifecycle: accepted, running, waiting on an identified dependency, result delivered, accepted/corrected, cancelled. First provide explicit broker-bound execution contexts for two overlapping tasks, not a guest-selected budget ID. Bind each model call, worker run, intent, artifact and result to that context. A progress reply must not finish the task. Preserve the current conservative fallback until the guest interface can support authenticated attribution; if it cannot, use one active task per admitted execution context rather than silently guessing.

Separately implement one native-artifact round trip: track the broker-created draft's account/object/version; observe edits only on those tracked artifacts; carry the changed content back to the original task as untrusted data. An edit is neither an owner command nor permission to send. A version change invalidates old material approval bindings. This saves copying and re-explaining work on the phone.

**Security cost.** New lifecycle/identity surface, with no authority increase. Cross-task/cross-account references, expired contexts and forged guest goal IDs must fail. Resolve unknown effects before a resumed task changes route; carry privacy labels, retention and FORGET through artifacts and dependent work. Reuse the journal rather than create an unrelated execution ledger.

**UX cost.** The owner should see one concise task status and only the action needed from them. Keep ordinary text usable; no new task-ID ritual or rating campaign. Normal corrections/UNDO supply feedback. Pauses must preserve progress, not trigger repeated clarification.

**Acceptance experiment.** Run two overlapping tasks, a delayed reply, a long pause, broker restart and a phone-side draft edit. Assert correct attribution and budget charging, no false completion, one resumable result, no repeated external action and no extra routine approvals. Contrast the owner effort with the current “ask again/copy the draft back” workflow. Coordinate P3-7, W5's delivery work, W7-A and mail wiring; the draft-edit seam is distinct from durable notification receipts.

## P3 — Make learning grade the result it actually recorded

**Evidence.** The production harvester serializes effect Params as expected output. Replay returns the guest's free-text answer. The live change pipeline supplies no class grader, so DefaultGrader checks byte equality for accepted cases and inequality for rejected ones. An unchanged correct effect followed by “Done” can therefore fail an accepted case; a rejected-effect case cannot prove the effect was avoided merely because the prose differs. This is a concrete mismatch, not evidence that every adoption gate can be bypassed. [broker/cmd/agentosd/tasks.go:206](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/cmd/agentosd/tasks.go#L206), [broker/loops/harvest.go:135](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/loops/harvest.go#L135), [broker/replay/replay.go:414](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/replay/replay.go#L414), [broker/cmd/agentosd/learn.go:134](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/cmd/agentosd/learn.go#L134), [broker/change/pipeline.go:80](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/change/pipeline.go#L80)

**Proposal and gain.** Start with one versioned, broker-observed result type for one effect class. Harvest required/forbidden effect fingerprints and terminal outcomes; replay returns observations from its recorded-effect handler, separately from display prose. A trusted deterministic class grader compares those observations. Keep arbitrary artifact quality explicitly ungraded until there is a suitable deterministic contract or authenticated owner judgment. This allows equivalent good behavior to qualify without training the system to mimic a JSON string.

The safe recorded-response substrate already refuses unmatched effects. Preserve it. In a separate bounded step, qualify read-response cassettes and pre-redaction keyed matching so supported tasks can replay necessary inputs without access to live recall. A deletion invalidates descendants and resumed evaluations. [broker/replay/recorded.go:42](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/replay/recorded.go#L42)

**Feedback correction.** The harvester currently retains the first suite case even if later quality changes. Its assumptions already acknowledge revision; fold this existing issue into W7-A rather than rediscover it. Use append-only authenticated corrections that supersede the expected version, keep the same dev/held-out side, invalidate stale cached results and never count one corrected task as two independent examples. [broker/loops/harvest.go:183](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/loops/harvest.go#L183)

**Security cost.** Grader changes are a CHG-2 owner-controlled policy change, not something a candidate approves for itself. Keep D-039's deterministic/no-model-as-judge rule, hidden expectations, no live replay effects, source deletion, private labels and frozen security fixtures.

**UX cost.** No JSON replies or per-task questionnaires for the owner. Reuse ordinary accepted/corrected/rejected signals; do not equate approval permission with goal quality.

**Acceptance experiment.** Through the assembled chain, an accepted action with natural-language completion passes; “Done” with no effect, wrong target, duplicate effect and forbidden action all fail. Rejected behavior remains rejected when wording changes. A later correction and restart use the new expectation with one sample and the same split. Measure trustworthy replay coverage and accepted improvement per evaluation cost, then demonstrate a repeat-use gain through H6. The local grader probe is only a boundary illustration, not this full test.

## P4 — Reduce recall ambiguity and context volume at the interface

**Evidence.** The index already has BM25, vectors and facts. Query exposes text, fact, kinds, count and public-only scope, but no account/time/byte budget; ranked hits load and render full text and facts. A count limit does not bound model context. [broker/recall/recall.go:1003](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/recall/recall.go#L1003), [broker/recall/recall.go:1119](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/recall/recall.go#L1119), [broker/recall/render.go:17](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/recall/render.go#L17)

**Proposal and gain.** Add narrowing metadata filters and a broker-enforced byte budget to the existing query. Return source/version-labelled excerpts and a bounded progressive fetch. Start with account/time scope and query-centred spans before changing the embedding model. This can reduce wrong-account/old-version retrieval, model disambiguation and needless context while retaining access to the full source. Coordinate oversized-result stand-ins [#196](https://github.com/ghbmrk/agentOS/pull/196) and lossless JSON compaction [#199](https://github.com/ghbmrk/agentOS/pull/199); neither replaces search selection or progressive fetch.

**Security cost.** No new data rights. A filter only narrows; every fetch rechecks current label/access/deletion state and records provenance before disclosure. Preserve public-only noninterference, including rankings/counts/snippets; private corpus changes must not alter public results. Excerpts remain scrubbed, escaped and untrusted. Distinguish source timestamps from trusted receipt time.

**UX cost.** Keep normal language search and automatic fetch; no owner-facing query syntax. Extra fetches and lost caveats are real failure modes, so smaller responses alone do not count as a win.

**Acceptance experiment.** Freeze a corpus with two accounts, duplicate quoted threads, long documents and old/new versions. Compare correct-source recall, accepted answers, total context bytes, extra calls and floor-host p95 latency. Include meaningful caveats near excerpt boundaries and deleted/stale references. Adopt only a declared useful context reduction with no accepted-task/relevance loss. Treat this as later optimization unless baseline A10 evidence makes it release-critical; no new RAG framework is justified yet.

## P5 — Earn precise approval suggestions without poisoning the whole action class

**Evidence.** Attention keys history by account/action/reply. Once fixed parameters differ, Templated becomes false and stays false until reset. The included synthetic probe uses unchanged production code, the default ten-approval ADP-9 threshold, one synthetic recipient and a synthetic non-user-content service (it does not exercise grants): 20 identical approvals yield one suggestion; 40 alternating approvals, 20 of each template, yield none; 10 of A, one of B, then 100 of A still yield none. This is not evidence to lower the threshold. [broker/attention/attention.go:181](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/attention/attention.go#L181), [broker/attention/attention.go:235](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/attention/attention.go#L235); [probe](evidence/2026-10-08/attention_cohorts.go).

**Proposal and gain.** For templated ADP-9 suggestions only, maintain a bounded set of narrow, canonical cohorts under the existing account/action class, using verified fixed template/predicate shape. Keep ADP-11's account-level reply threshold and edit-rate rule unchanged. Each cohort independently earns the current threshold, time-window and edit requirements. Negative evidence should conservatively reset relevant cohorts, initially the whole account/action class. Suggest a precise rule once; the owner still explicitly grants it through the existing high-tier flow. This lets two legitimate recurring routines earn separately instead of disqualifying each other.

**Security cost.** More classification/state to review, no broader authority. Never let a guest create trusted predicates, partition around a NO/UNDO, or turn observed repetition into an automatic grant. Bound cohort count and retention. Preserve ADP-9 source verification, recipient and amount limits, recent-edit holds, per-dispatch rate accounting and CRED-6 exclusions. SR3-2 and SR3-3 in [#380](https://github.com/ghbmrk/agentOS/pull/380) remain prerequisites for safely relying on broader pre-allowance use.

**UX cost.** Cohorts could generate more suggestions; deduplicate and pace them account-wide, show the exact scope, and respect decline/cooldown. The aim is fewer avoidable approvals without a new stream of rule-management questions.

**Acceptance experiment.** Retain the positive/alternating/outlier corpus; add NO, UNDO, correction, spoofed source, unseen recipient, amount change and restart. A cohort under threshold never earns from another cohort's examples; an earned suggestion authorizes nothing. Compare accepted work, total necessary/avoidable approvals and suggestion burden under the existing thresholds. Coordinate W7 and the full grant-card work, not a new permission engine.

## P6 — Let routing learn task specialization, not just transport reliability

**Evidence.** Candidate proposals order routes using global provider/model statistics: successful calls first, then mean header latency. The same statistics are used across task classes. Held-out adoption still gates changes, so the limitation is poor proposals rather than uncontrolled live routing. CAP-9 already calls for measured class acceptance, latency, cost and quota. [broker/route/route.go:160](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/route/route.go#L160), [broker/route/route.go:262](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/route/route.go#L262), [broker/route/route.go:273](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/route/route.go#L273)

**Proposal and gain.** Use class × qualified model/version evidence linked to completed tasks. Separate HTTP reliability from goal acceptance; among routes meeting the class's acceptance floor, compare full latency and usage per accepted task, including retries and fallbacks. Require minimum evidence and bounded replay comparisons so the currently favored route does not monopolize observations. Treat quota and labels as deterministic eligibility conditions, not learned permissions.

**Security cost.** Candidates still only reorder the same owner-granted routes; retain the vault's structural reorder check, private-data filter and held-out/security gates. Exploration uses allowed dev/replay cases, the separate capped evaluation budget and D-039's existing no-dearer-route price ceiling; Loop 1 cannot raise those limits. Never send private data to a disallowed route. A model change invalidates affected scores. [broker/cmd/agentos-egress/routing.go:92](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/cmd/agentos-egress/routing.go#L92)

**UX cost.** Better specialization should reduce correction burden. Churn and opaque fallback can worsen predictability; require stable evidence and existing digest/rollback behavior, not prompts at each call.

**Acceptance experiment.** Use two classes with different route strengths and one fast-but-wrong route. Compare global transport ordering to class-conditioned candidates on accepted/corrected/rejected outcomes, p95 task latency, cost/pool usage per accepted task and route churn. Leave uncertain classes unchanged. This depends on P2/P3's trustworthy outcome linkage and extends existing P2-7/W3 routing work.

## P7 — Turn declared resources into a complete admitted run

**Evidence.** Main exposes ordinary workers, while [#220](https://github.com/ghbmrk/agentOS/pull/220)/[#221](https://github.com/ghbmrk/agentOS/pull/221)/[#222](https://github.com/ghbmrk/agentOS/pull/222) provide pending quota, declaration/resource and wording libraries. Read-only inspection found that the resource view is narrower than CAP-12's full qualified-tool view, and a preference check is not a lease retained for the actual run. These are integration requirements, not allegations that advisory helpers bypass admission. [broker/cmd/agentosd/tree.go:185](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/cmd/agentosd/tree.go#L185); [SPEC.md:331](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/SPEC.md#L331)

**Proposal and gain.** Complete one sequence: qualified declaration → caller-specific resource view → preference → actual broker-acquired run lease → inherited worker task/label/budget → bounded result artifact → lease release and quota update → fallback/wait → digest. Keep discovered, qualified, available and running distinct internally. This makes “one participant builds, another checks” and simultaneous use of independent pools practical without assuming unlimited concurrency.

**Security cost.** S8-W1 and provider/version qualification remain hard activation gates. Workers get declared inference egress and no guest/owner/adapter tools. Recheck grant, label, reserve and admission at dispatch despite a stale resource view. Bind quotas to broker identity; provider telemetry cannot create budget. No overage, shared credential volumes or unreviewed worker-held login route.

**UX cost.** No new setup questionnaire or per-run approval. Spare work yields before foreground waits; authorized foreground fallback stays within budget, while spare work waits for reset. Report actual fallback/cost once through existing wording.

**Acceptance experiment.** Through real construction, exercise independent/shared pools, exhausted reserve, stale telemetry, full spare slots, foreground arrival, mid-run exhaustion, wrong-label preference, cancellation and restart. Require retained lease accounting, no extra grant/disclosure/spend, no spare-induced foreground delay and A15's eligible fallback target. Measure accepted tasks per reset window and owner effort. Live provider qualification remains separately authorized work; this review makes no plan access or terms assumption.

## P8 — Prove one local leverage pipeline before building breadth

**Evidence.** CAP-13 and D-051 already define local passes and owner compute hosts; current main reserves inference memory and discovers accelerators but has no inference service to use them. [broker/cmd/agentosd/main.go:445](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/cmd/agentosd/main.go#L445); [SPEC.md:332](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/SPEC.md#L332)

**Proposal and gain.** Start with one class that has a deterministic output contract, such as structured extraction from long public documents. Compare main route alone, extractive reduce → main route, and cheap-first inference → deterministic check → escalation. Build the minimum isolated service/route representation to measure those arms. Increase local-model size, pass count or compute-host reach only after a class shows useful net savings. A local step is valuable when it reduces total expensive work or owner effort, not merely because its tokens are inexpensive.

**Security cost.** Inference stays outside the broker. Router-applied passes see only the call being wrapped, never hidden recall or extra data. Reduce selects original spans; generated summaries remain guest-requested untrusted artifacts. Deterministic checks govern a qualified cascade; model self-confidence never grants authority. Keep private-data permissions, pinned encrypted owner-host endpoints, model-identity requalification, optional-host fallback and per-call metering. Resolve SR3-7's request normalization before relying on tighter reservations.

**UX cost.** Extra local passes can slow the first response or omit needed context. Keep foreground admission/preemption and baseline fallback; do not expose pipeline settings during normal use.

**Acceptance experiment.** Freeze loss-sensitive, distractor-heavy cases; measure acceptance, full latency, frontier usage per accepted output, CPU/memory and owner-channel p95 on the floor. Predeclare a useful savings threshold and latency margin. Count all escalations and failed attempts. A failed pipeline leaves the current route alone. This is a narrow implementation of an approved requirement, not a proposal for a fleet or remote worker platform.

## P9 — Compile short workflows whose later steps need an earlier result

**Evidence.** Skill nodes currently represent literals, initial slots and objects; every step is filled before any executes. A source-assigned new object ID therefore cannot feed a later step unless provided at entry or hidden inside a composite adapter operation. That limits recurring data-dependent routines even when their authority is unchanged. [broker/skill/format/format.go:59](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/skill/format/format.go#L59), [broker/skill/run.go:25](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/skill/run.go#L25), [broker/skill/run.go:84](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/skill/run.go#L84)

**Proposal and gain.** After proving W7 repeat-use benefit, qualify one versioned reference to an allowlisted typed object handle from an earlier successful step in the same run. Resolve it immediately before the dependent step. Keep the runner in the guest; no arbitrary expressions, scripts, loops, general response-body extraction or forward references. A narrow composite operation may be cheaper for the first workload; compare that before generalizing.

**Security cost.** This is a genuine new parser/provenance surface. Handles must be bound to account, object kind, goal/run and source version, carry no credentials/authority, and be rejected across tasks or failed steps. Dynamic recipients/amounts still pass source verification or ordinary approval. Preserve canonical files, step bounds, idempotent request IDs, label propagation, FORGET and all per-effect gates.

**UX cost.** The owner sees the actual object in existing broker wording, never internal handles. On an assumption failure or unknown result, hand back completed/pending/remaining work so the model can resume without making the object twice.

**Acceptance experiment.** A synthetic adapter returns unpredictable IDs for new objects. Compare current runner/composite operation/typed-reference prototype on a repeated two- or three-step workflow. Require zero extra reasoning turns on the qualified success path, equal acceptance, no duplicated effects after retry and refusal of stale/wrong-account/wrong-run handles. This remains later unless a measured first-release workflow requires it; do not build a general automation language.

## P10 — Turn forks into tested alternatives, then reduce transfer overhead if it matters

**Evidence.** Workers already support fork, fit and keep. The eight-worker test uses a fake runtime without cgroups/quotas and tiny sequential file operations; it establishes control behavior, not eight-way accepted-work throughput. Tools bound inputs/outputs and describe directory transfer through base64 tar, which may make large cross-worker review expensive. [broker/workers/fit_test.go:264](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/workers/fit_test.go#L264), [broker/workers/workers_test.go:100](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/workers/workers_test.go#L100), [broker/workers/workers.go:170](https://github.com/ghbmrk/agentOS/blob/7b753eb87f606ea2268ca536d429d47989dba196/broker/workers/workers.go#L170)

**Proposal and gain.** First qualify a guest procedure using existing primitives: prepare one worker, fork only as many as admission allows, try bounded alternatives, collect deterministic tests, keep one winner and destroy siblings. Use disagreement to create a testable alternative, not longer discussion. If measurements show transfer dominates, add broker-custodied artifact handles and small manifests so a second worker can inspect a result without the coordinating model copying every byte.

**Security cost.** Existing-tool procedure adds no permission; artifact handoff adds a custody surface and needs separate review. A handle is not a bearer grant. Enforce identity, destination label/grant, quota, safe extraction and deletion reach; raise the destination before exposing private bytes. Provider reviewers still receive no adapter or owner-channel authority. A passing test never approves an external effect.

**UX cost.** No new owner decisions for already-authorized sandbox work. More branches can increase latency/cost rather than reduce it; limit fanout by measured benefit and preserve foreground responsiveness.

**Acceptance experiment.** Compare sequential, current branch/test/keep and—only if justified—handle handoff on one build/test task and one larger multi-file artifact. Measure accepted result, elapsed time, coordination tokens/calls, peak memory and owner-channel latency on real floor admission. An interrupted branch has no test result; do not count preemption as a bad solution. Release work is proving existing A15 behavior; the transfer extension is conditional and later. Coordinate CAP-12 artifact work and P2 task attribution.

## How to establish an actual advantage

Use the existing A10/H6 design and a broad mix of recurring work. The following is a proposed workload selection, not a claim that these tasks have been run:

| Family | Useful result / oracle | Primary opportunity |
|---|---|---|
| Evidence-backed research | Correct source/version and retained caveats, judged against a frozen corpus | P4, P8 |
| Spreadsheet or document transformation | Exact structural checks plus owner acceptance of the artifact | P3, P8 |
| Small code repair | Held-out tests and independently reviewed patch; no automatic merge | P6, P10 |
| Recurring report | Correct current inputs, accepted report, second-use effort | P3, P9 |
| Mail organization | Right messages, alert exceptions preserved, working UNDO | P1, P5 |
| Native draft revision | Owner edits in their app; correct revision returns without stale send | P2 |
| Parallel implementation/review | Independent evidence changes the chosen result; not just more discussion | P7, P10 |
| Recovery and quota exhaustion | Same task resumes or truthfully waits without repeated effects | P1, P2, P7 |

1. Freeze a small synthetic pilot to validate the harness, then owner-selected recurring tasks for benefit. Predeclare task identities, starting state, account/grant policy, model/image versions, acceptance predicates, repeat count, workload mix, gain threshold and regression margins.
2. Compare AgentOS, unmodified OpenClaw and a direct provider CLI on the same permitted inputs, accounts and host profile. Counterbalance order and reset source/workspace state; report missing capabilities instead of silently changing tasks. Keep first-use and repeat-use separate. The direct CLI is a real capable baseline, not an artificially weakened chatbot.
3. Measure all owner-active effort, including setup, clarification, review, correction and recovery. Count rejected/reworked attempts in effort per accepted task, and show acceptance/abandonment alongside the ratio. Preserve wall time separately; report tails, not only a successful-run median.
4. Keep resource units separate: API dollars, tokens, plan pool units, local compute time and peak memory. Include all retries, branch work, discarded candidates and cascade calls. More unused quota consumed is not itself a benefit.
5. Preserve security/UX gates: no unauthorized effects, disclosures or credentials surfaced; no duplicate effects or stale approvals; no lost edits; no unreported unknown results; preserved STOP/foreground latency; no rise in routine prompts or suggestion burden. These are test conditions, not proof that a finite test set eliminates every vulnerability.
6. Predeclare the minimum useful effort/usage improvement and acceptable latency margin before the confirmatory run. Review per-class regressions and uncertainty; a faster class must not mask worse results in another. Promote a capability only when the existing held-out/security gates and the benefit evidence agree. Otherwise keep the baseline route or workflow.

Two diagnostics should remain subordinate: compile.Measure's effect-span speedup excludes planning and reports stopped runs outside its median; attention's “avoidable” counter is a classification, not a measured minute saved. H6 already accounts for failed-attempt effort, but its evidence hashes do not authenticate who judged the result. Independent judgments and production-equivalent profiles still need verification.

For skills and new local passes, evaluate the payback period: qualification, setup and maintenance effort must be recovered by actual saved effort across repeated accepted tasks. Do not repeatedly compile low-frequency tasks because the system has spare tokens.

## Recommended order

**First, establish the useful-work contract.** Extend the existing INT-A/H6/W7-A packages; fix P3's result mismatch; carry the current task ID through result delivery and authenticated feedback before introducing broader parallel-task bindings. Complete one native result/revision path. Security work in PR #380 remains a prerequisite wherever the corresponding authority boundary is exercised.

**Next, exploit existing assets.** Use ordinary workers for one measured branch/test/keep procedure, integrate the already-planned resource/plan path under S8 qualification, and improve route evidence. Implement the narrow ADP-9 cohort fix with unchanged thresholds. Benchmark scoped recall before spending on a new embedding model.

**Then add compounding capacity selectively.** Qualify one local pipeline and, only for a demonstrably common workflow, a bounded skill result reference. Broader pass catalogs, artifact stores and compute-host breadth follow measured demand. Each is a small separately reviewed package, not one architecture rewrite.

No change to an invariant or owner authority is recommended. New task-continuation semantics, trusted grader versions, skill format changes and promotion policy require the repository's normal L1/design and risk-tier reviews before implementation. This advisory record does not approve them.

## Considered, not proposed

- Reducing approval thresholds, treating repetition as permission, or automatically sending an edited draft. Precision and better evidence can reduce interruptions while keeping the existing grant.
- Giving guests/provider workers credentials, direct adapter access, unrestricted network access or shared login state. Complete S8 qualification; do not make output scanning the custody boundary.
- Using model confidence or another model's favorable review as an authority decision or a replacement for deterministic qualification.
- Letting more workers violate headroom, quotas, foreground responsiveness or STOP. Qualify real workload concurrency rather than maximizing worker count.
- Giving router-applied passes invisible access to recall or adding generated instructions to a private call. Scope reduction to content already present.
- Buying potency by introducing an AgentOS service, relay, remote fleet or consumer-inference UI route. Main's dependency/custody contracts remain authoritative; separate substrate/spec proposals are pending, not silently adopted here.
- Restarting the owner-deferred active Loop 2 testing. This review does not reverse D-040.
- Rebuilding W4 delivery, the recall engine, fork/keep primitives, the H6 collector or the W5 outbox. Extend the missing seams rather than duplicate working or actively reviewed components.

## Evidence, reproducibility and limits

Three independent review tracks covered owner value, compounding, and execution/resources; the coordinating pass checked integration, measurement and overlap. The source facts cite pinned main. Pending proposals were treated as pending even when local Git objects made their code readable. The broad workload mix above is an assumption for this review; it is not a substitute for Mark's eventual A10 workload.

Local verification used the bundled Go 1.26.8 toolchain on macOS:
- Existing attention, route, change, recall and events package tests passed.
- The compile package's test build was blocked by Linux-specific overlay/syscall dependencies. No Linux runtime or hardware qualification is claimed.
- The attention probe imports the real public optimizer with synthetic decisions; it creates suggestions only, with no grant or external effect.
- The grader probe invokes the real DefaultGrader on representative expected JSON and a textual completion. It illustrates the boundary mismatch; it does not run the assembled harvester/replay chain.
- No live model/account calls, production mailbox changes, hardware benchmarks or owner-minute trials ran. All projected gains remain unmeasured.
- Documentation validation and the fresh independent review of this report are recorded on its PR.

[Reproduction instructions and outputs](evidence/2026-10-08/README.md) accompany the probes. They are review evidence, not new passing regression coverage. Implementation should replace each relevant probe/scenario with retained failing-then-passing package/composition tests.

### Pending work checked for overlap

| PR | Observed head | Role in this review |
|---|---|---|
| #196 | a47df8c149386790b908cdb7000d43b1d3dc21a0 | Oversized result stand-ins; reuse for P4/P10 where appropriate |
| #199 | 9aa8e8d7535556243f022454a6ba206f267b417b | Lossless JSON whitespace compaction; not semantic retrieval |
| #220 | 721e89dbe2298caa15669ab7b76bc73b3560930b | Plan quota/admission library |
| #221 | fc2e31bd55e6aaf3b869537a6cb9620746f26ae7 | Provider declarations/resources |
| #222 | 5b976fbcdd0163ec0ddc471a96d6fd3da3bf1600 | Pool STATUS/page wording |
| #258 | 331e8b301c5e637ede6db021f4cb4445169ae7f4 | H6 matched-trial collector and measurement protocol |
| #261 | 628e0e82809d2e168f437b8fd7f1b4bf2b942f1b | INT-A service/recovery fixture design |
| #264 | db35692e74bd502a3925c9dcaead4c3e2cda2ed3 | W7-A verified feedback and benefit experiment design |
| #346 | 2060d963ef7341bb9e042d233d069cc082be98ee | SUB-3 pending spec proposal; its new authority/substrate semantics are not assumed |
| #380 | 4e088aaec1226b69c8b48a554ddd03dd5b92bc11 | Separate security remediation intake; not merged at review time |

W5's notification/receipt stack was checked for overlap by titles and descriptions, not exhaustively reviewed here. Refresh related heads, lane ownership and main before implementation. No pending PR in this table receives implementation approval from this review.
