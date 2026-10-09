# Simple conversation, powerful and secure outcomes

Record: PR #447 · package ARCH1 · head a52a678a4f4d854eaf737ffaa8c3777781efea56

**Purpose:** Mark asked that the architecture keep complexity and technicalities abstracted from the owner, enabling simple text/call interactions with powerful, secure outcomes. This supplements the [cross-silo review](2026-10-08-cross-silo-architecture.md). Source is pinned above; earlier reviews retain their own source and evidence. This is a design/acceptance review, not a runtime change or a usability study.

## Architectural judgment

**The OS should absorb the coordination cost of its power.** Connecting more accounts, private datasets and devices is useful only if the owner does not become the scheduler, permission engineer, data courier and recovery operator for every joined task. The intended interface is an outcome request, useful progress within established authority, the smallest necessary consequential decision, and an honest result.

The architecture already points this way. CH-8 removes the local page from daily operation; CH-12 requires brief actionable texts without internal part names; CH-15 limits interruptions; ONB-3/9 minimize setup and automate eligible fallback; CAP-9/12/13 put resource selection and placement in the system. These are existing obligations, not new features discovered here. The near-term recommendation is to finish and qualify their composition. [Owner interface](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/SPEC.md#L177), [onboarding](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/SPEC.md#L269), [resource selection](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/SPEC.md#L328).

The rule is **hide mechanisms, expose consequences, retain inspectable evidence**. Simplicity must not be scored by short messages alone. A short message that forces investigation, repeated explanation, copying between services or an avoidable trip home is expensive. Conversely, a brief confirmation that makes a real recipient, expense or irreversible action legible earns its interruption.

## What the owner should have to understand

| System handles by default | Owner decides when consequential | Detail available when useful |
|---|---|---|
| Source retrieval, compatible joins, freshness checks and provenance | Missing facts or genuinely ambiguous identity/purpose | Source coverage, attribution, uncertainty and why an answer changed |
| Eligible models, retries, quotas, compute placement and capacity | New processing recipient, higher spend authority or a material unresolved deadline/cost tradeoff | Route history, estimates versus actual cost, technical diagnosis |
| Credential use through qualified executors, connector mechanics | Connecting an account or widening permitted access/effects | Exact scope, credential mode and how to restrict it |
| Drafts, version checks, artifact transfer and effect reconciliation | Exact audience/recipient, material payload/consequence, required approval and undo limit | Full artifact, per-effect receipt and evidence |
| Task continuity, status aggregation and notification pacing | Correction, cancellation or a decision the system cannot safely infer | Outstanding tasks and the exact restrictive control |

This table is an interface division, not a new permission model. Broad owner-authorized private context remains valuable. Do not require project silos, individual join approvals or repeated approval of already-granted routes. Source, processor, actuator and credential-custody roles remain independently bounded underneath. Resource inventories should be principally machine-facing; the owner should not need a dashboard to orchestrate them.

## 1. Give each outcome one coherent account

**Text and voice are both conversational interfaces.** An owner can start a task, explore options, ask follow-up questions, clarify intent and revise a result through ordinary text messages, with context preserved across turns. A complete text-only journey must work without requiring a call; switching between text and voice is optional. This does not remove channel disclosure rules, required local steps or broker proof. Detailed private results still use the authorized destination where CH-20 requires it.

A task should retain its identity across turns, channel switches, lock/unlock, corrections, outages and restarts. The conversational goal label can help navigation, but it is untrusted input: it cannot select authority or certify a recipient. Project existing task, intent, artifact and journal facts into a concise account of what is happening. Reuse POT-P1/W3-goal and ARCH1-2/3, rather than adding a second lifecycle or authority ledger.

Current primitives are narrower. The guest inbox provides durable at-least-once message delivery; its association logic conservatively declines ambiguous goals. An answered inbox message is removed before output delivery. STATUS reports journal counts and `action/account` samples, with separately attached exceptions. Those are useful foundations, but not proof of a coherent multi-turn result. These lifecycle/status seams already belong to POT-P1 and UX3-8; do not file them again as new vulnerabilities. [Inbox](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/guest/owner.go#L17), [association](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/guest/goal.go#L58), [answer boundary](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/guest/owner.go#L287), [STATUS](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/control/handler.go#L301).

Use a small owner vocabulary: working; waiting for your decision; waiting for a service; result ready; delivered; unable to confirm an action. Keep the distinctions internally and in the claims made. A joined task is not an atomic transaction: one calendar update may succeed while an external message remains uncertain. Neither transport acceptance nor an agent's confident narrative establishes completion or useful quality.

Only ask for disambiguation where it matters. With two pending tasks, “do that” cannot choose an effect just because it is conversationally plausible. A reconnect should restore verified context without requiring the owner to reconstruct execution order. Duplicate SMS, stale replies, changed recipients and old approval codes must not redirect work.

## 2. Spend attention on decisions, not on machinery

Automatic route selection, safe retries, alternate qualified hosts and source lookups should be quiet within established privacy, authority and cost bounds. ONB-9 already says eligible failover is reported rather than approved again; CAP-13 already recalculates capacity. A powered-off host should not require owner troubleshooting if a permitted alternative still meets the task. [ONB-9](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/SPEC.md#L282), [CAP-13](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/SPEC.md#L332).

Ask about the outcome when there is a meaningful choice: finishing sooner at an estimated cost within an existing cap versus waiting for an already-authorized route. Do not ask the owner to pick a route class, adjust a reserve percentage or tune concurrency merely to finish routine work. A default must never introduce a new private-data recipient, enable an unaccepted credential mode, consume a protected reserve or raise a budget.

CAP-10 questions already have defaults, bounded waits, coalescing and an explicit no-authority contract. An exact untagged choice is accepted only for one texted question with no open approvals. Preserve that useful simplification. A formatting answer can guide drafting; it cannot authorize sending. Approval silence expires denied. [Question contract](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/question/question.go#L21), [single-question guard](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/question/question.go#L1284), [daemon budget and approval wiring](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/cmd/agentosd/questions.go#L106).

Evaluate questions, approvals and notices together. The daemon shares a send budget, but its question constructor does not set the optional Quiet callback; this requires a composed quiet-hours check, not an unsupported conclusion that no downstream pacing exists. Reuse W5/W9 and existing CH-15 obligations. Preserve the specified daily health digest, including its minimal one-line form; deleting it to improve an interruption metric would change the contract.

Standing delegation should make repeated successful work easier. The owner expresses an outcome; the system proposes a concrete bounded rule through existing verified policy machinery. State what will happen, for whom, within what limits, and how to stop it. Repeated suggestions should not pressure someone who declined. No new global “handle everything” grant or quiet conversion of task chat into authority. [Existing proposal-only attention mechanism](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/attention/attention.go#L1).

## 3. One conversation still needs an unmistakable approval boundary

Ordinary text and speech both support natural-language goals, questions, corrections and preferences. In text, the broker recognizes the exact supported control/approval syntax and routes ordinary conversation to the agent under the existing session rules; during calls, the specified keypad path supplies control/proof. Consequential authority remains deterministic and independent of models. The broker renders the verified action, canonical recipient, material amount/payload, reversibility, expiry and exact supported reply. These facts belong at the decision, not buried behind MORE. Deeper evidence may be optional; the facts needed to decide are not.

Preserve short request identifiers where they disambiguate decisions, and print the valid reply instead of requiring memorized syntax. Do not replace canonical destinations with reassuring display names. Batch only where existing rules permit and all material actions are legible. Prior UX3-6 already owns hidden-item/pagination concerns; a new outcome summary does not excuse them. [CH-3/10–13](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/SPEC.md#L159), [fixed rendering](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/owner/render.go#L137), [recipient fidelity](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/owner/render.go#L229).

The existing `Agent: ` prefix separates agent text from broker requests. CH-21e's queued code-request/reply-grammar withholding is part of secure conversational coherence, not merely cosmetic copy work. Do not remove the current distinction in pursuit of a seamless persona. A fluent source, guest or agent must never impersonate the broker's approval prompt. [Prefix](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/owner/channel.go#L891), [CH-21e](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/briefs/CH-21e.md).

STOP, STATUS and narrowing controls must remain usable with models down. Ordinary phrases such as “stop emailing Acme” are not already closed-grammar controls. Help the owner reach the exact valid restrictive command, and never claim a restriction happened before the broker recorded it. Friendlier deterministic aliases or broader control grammar require an explicit L1 design. Preserve STOP's honest distinction between held work and effects that may already have happened. [Parser](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/owner/parse.go#L29), [STOP](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/control/handler.go#L212).

## 4. Qualify calls as a complete interaction

The modem driver separates speech and keypad material, and narrow synthetic tests exercise that boundary. But M5/M6/M13 explicitly leave owner call handling, owner-channel integration, speech and keypad-unavailable fallback for integration. The bridge excludes owner voice. `broker/voice` is wording lint, not an audio conversation service. A merged driver therefore does not establish qualified text/call continuity. [Modem limits](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/modem/at/ASSUMPTIONS.md#L16), [bridge scope](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/modem/bridge/DESIGN.md#L76), [wording lint](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/voice/ASSUMPTIONS.md#L3).

Under CH-5/17, speech is conversation; keypad input is the broker control/proof path. A spoken “yes,” spoken code or spoken STOP is not authoritative today. The owner call integration must make that seam short and clear, bind the selected request, and keep keypad material away from speech services and guests. Do not invent a keypad grammar in this review. If the owner cannot use the keypad, preserve safe planning and text the pending approval for later under the existing rule. Hands-free authorization is not a current guarantee.

Reuse P2-3/S2 integration and PE7-call wake handling. Qualify actual modem/carrier audio, intelligibility, echo, interruption, partial/repeated tones, concurrent requests, disconnect during proof and model failure. Include an owner away from home or unable to touch the phone. Synthetic tone decoding cannot stand in for that study. Accessibility is a design requirement; weakening proof is not an implicit solution.

## 5. Deliver the outcome without making the owner move data

Text/call should control work, not become a lossy replacement for native artifacts. Use the existing authorized destination automatically. Say where the actual result is available, support corrections against its actual version, and retain individual effect receipts. If delivery fails, distinguish result-ready from delivered and give a next step that exists. Never claim a kept-reply page, inbox or recovery route is usable solely because planned copy mentions it.

Current evidence code explicitly lacks a configured mailbox in this build. Long replies are retained and clipped; a successful full-reply notification follows a delivery attempt. CH-20w and selected output adapters own the assembly. CH-20p/a/m retain their existing later classification unless a separately justified release acceptance decision changes it. UX3-7 and UX4-6 already own withheld-result/first-value concerns. [Current evidence path](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/cmd/agentosd/evidence.go#L55), [delivery boundary](https://github.com/ghbmrk/agentOS/blob/a52a678a4f4d854eaf737ffaa8c3777781efea56/broker/cmd/agentosd/evidence.go#L178).

Do not expose private data on a convenient channel or silently change its audience. CH-19/20 disclosure rules still apply to task names, summaries and diagnostic detail. Some setup, site login, new authority and recovery still require the local Wi-Fi page or other specified proof. Abstract their mechanics, state their practical consequence honestly, and avoid making local access an everyday workaround. “Everything by call” must not quietly become a remote control relay or weaker enrollment contract.

## Proposed interaction targets and acceptance

These are synthetic design targets, not observed product transcripts or replacement approval templates. All content must fit the channel's disclosure policy.

| Owner situation | Target behavior | Negative case |
|---|---|---|
| “Compare the inspection photos with the maintenance emails and prepare the contractor brief.” | Join authorized sources, produce a native draft and describe coverage; ask only a material ambiguity | Source instructions cannot change recipient or grant an effect |
| Owner continues by text: “What are my options?” then “Use the shorter version, and explain the tradeoff.” | Carry the established task through clarification, comparison and revision by text, with authorized result delivery and no required call | No lost context, forced voice step or conversion of ordinary conversation into approval |
| Owner then asks to send it | Broker supplies the full verified decision and exact required reply/proof | Conversational “yes,” preference default or silence cannot authorize |
| Call drops and owner returns by text | Restore the same established task, state what changed, retain current approval/expiry semantics | No duplicate effect or stale-code reuse |
| Remote service has not confirmed an action | Say the outcome is unknown; reconcile only where the adapter supports it | No invented success, promised recovery or blind duplicate retry |
| A qualified host is unavailable | Use an eligible alternative within existing bounds, without a routing question | No new private-data recipient or spending authority |
| Owner cannot use keypad | Continue safe work and offer the real text approval path for later | No spoken-code substitution; no claim that saying STOP is broker control |

[ARCH1-4](../../briefs/ARCH1-4.md) registers the scoped release acceptance extension. It reuses existing owners rather than reopening their defects. Compare matched cross-silo tasks with and without these integrated abstractions under identical data/authority policy. Count accepted quality, owner active minutes, interruptions, repeated context, technical choices, setup, maintenance, corrections and recovery. Measure comprehension of recipient, consequence, uncertainty and restriction path; do not test recall of architecture. Freeze targets before qualification. Unauthorized effects, code leakage and misleading completion remain failing invariants, never a trade for fewer prompts.

## Evidence and limits

Three bounded source reviews informed this synthesis. Existing owner/question package tests passed on macOS; control tests could not compile because their dependencies include Linux-specific overlay calls. Seven focused synthetic owner/modem tests passed. [Evidence](evidence/2026-10-08-holistic/simple-interface-evidence.md) records commands and scope. No actual call, real account, device effect, hardware qualification, large-space workflow or owner-comprehension study ran. No runtime gap is declared fixed. The recommendation is to make the current security and capability contracts compose into an experience whose complexity is carried by the OS.
