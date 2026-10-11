# Deep owner-experience review — 2026-10-08

**Advisory review of `c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1`.** Separate from the [security review](../security/2026-10-08-architecture-review.md) and [potency review PR #384](https://github.com/ghbmrk/agentOS/pull/384). Requested by Mark: review UX without sacrificing potency or security. This is a cross-lane proposal to primary, not a lane claim, adopted design, runtime change, or release qualification. The README describes a pre-alpha system not yet usable by an owner. All runtime conclusions refer to this fixed main snapshot; open PRs are not assumed merged.

The largest UX risk is **losing continuity at a boundary**: between setup steps, between a task and authentication, between an approval summary and its remaining items, and between a failure notice and the place that can resolve it. More capable agents would encounter these gaps more often. The remedy is to preserve task identity, show complete broker-owned state, and provide a working next step—not remove approvals or hide problems.

## Method and limits

Four parallel review slices covered setup/first value, messaging/approvals, recovery/control/learning, and mobile rendering. We traced actual handlers and templates against SPEC, prior reviews, BOARD, LATER and package assumptions. Synthetic probes exercised public Go interfaces, including the real local HTTP renderer with fake hooks and an owner fixture. Observed outputs and portable reproduction instructions are in [evidence](evidence/2026-10-08/README.md). No real account, modem, model, credentials, external effect, or private owner data was used.

Localui depends on Linux socket helpers unavailable on this Darwin host. The HTTP probes use explicit panic-only build shims for those uncalled functions. These probes establish renderer/state-machine behavior, **not** Linux socket authorization, device isolation, real provider sign-in, or assembled daemon correctness. Four focused existing setup tests passed with that overlay. A browser inspected actual generated HTML at 390 and 320 CSS pixels in its existing dark mode. We measured DOM dimensions and computed colors; we did not run a screen-reader trial, physical-device trial, or study with owners. Usability targets below are proposed acceptance criteria, not measured success rates.

## Findings and work-item index

Priority expresses owner impact, not exploit severity. P1 prevents a supported minimum journey; P2 obstructs informed decisions, control or recovery. All twelve are proposed **release** work because they affect the cited acceptance contracts. UX3-12 is an extension to queued W6, not a newly discovered implementation defect. Registration leaves every remedy open.

| Work item | Priority | Evidence/state | Owning work to reuse |
|---|---|---|---|
| [UX3-1](../../briefs/UX3-1.md) Visible provider sign-in and retry | P1 | Reproduced renderer defect; lifecycle gap | P2-2w c4 |
| [UX3-2](../../briefs/UX3-2.md) Repair network after pairing | P2 | Reproduced state-machine dead end | P2-2w c3/c4 |
| [UX3-3](../../briefs/UX3-3.md) Explain verified-update waits | P2 | Source projection gap; generic page rendered | UPD-b2, P2-2w c4 |
| [UX3-4](../../briefs/UX3-4.md) Qualified route and first task | P1 | Source/interface gap; empty-provider fixture | D-051 route work, S8, c4 |
| [UX3-5](../../briefs/UX3-5.md) Multi-message task across lock | P2 | Reproduced; deliberate O5 policy needs L1 | CH-14, W5 |
| [UX3-6](../../briefs/UX3-6.md) Inspect the whole approval batch remotely | P2 | Reproduced incomplete MORE | CH-12/13; L1 command grammar |
| [UX3-7](../../briefs/UX3-7.md) Retrieve withheld results truthfully | P2 | Reproduced notice plus missing storage/view path | CH-20p minimum, CH-20w |
| [UX3-8](../../briefs/UX3-8.md) Complete status and working next steps | P2 | Reproduced truncation; local view source/render | W5, localui |
| [UX3-9](../../briefs/UX3-9.md) Preserve STOP consequences | P2 | Source-proven discarded receipt | Control/journal/localui |
| [UX3-10](../../briefs/UX3-10.md) Identify what FORGET changes | P2 | Source-proven preview limitation | W3-forget-a/b |
| [UX3-11](../../briefs/UX3-11.md) Read critical controls on a phone | P2 | Browser dimensions and contrast | Localui, SR3-3 compatibility |
| [UX3-12](../../briefs/UX3-12.md) Owner-completable recovery drills | P2 | Queued integration acceptance gap | W6, BAK-1, W3-forget-b |

## Setup and first useful result

### UX3-1 — Device-code sign-in has no visible start control

At Connect AI, the template tests `with index $.Device .ID`. The map value is a two-element array; a missing entry yields a zero array whose length is still nonzero, so the template takes the pending-challenge branch. A fresh synthetic plan provider renders **“Open [empty link] and enter [empty code]”**, “I signed in”, and no Sign in form. A browser confirmed the empty link and absence of a form. This is a concrete renderer defect independent of pending real-provider wiring. The existing device-code test directly POSTs the start endpoint, bypassing the missing affordance.

After a diagnostic direct POST, advancing the fixture clock by 24 hours leaves the same challenge and no renewal action. The stored pair has no expiry/status. Distinguish not started, pending, expired, declined, failed and connected; offer a provider-specific retry while retaining completed enrollment. Keep native provider authentication and vault custody. A provider challenge is not an AgentOS authenticator code. [Template](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/pages.go#L311), [state](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/setup.go#L403), [stored challenge](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/setup.go#L959).

### UX3-2 — Network repair disappears after pairing

The paired setup sequence never returns to the network step, and the network handler declines changes once Owner is set. In the offline paired fixture the page has no repair form; manually posting returns 303 and calls JoinNetwork zero times. An owner who mistyped Wi-Fi details or changed networks cannot repair that dependency from the page. Add a narrow network-repair path for the authorized setup device that preserves enrollment and subsequent steps. Do not let another Wi-Fi client replace owner identity, reset factors, or broaden the network helper. [Step selection](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/setup.go#L275), [network handler](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/setup.go#L565).

### UX3-3 — Update failure reasons become an indefinite wait

Firstboot status distinguishes unreachable, unverified, installing and fallback states, including when AI must remain closed until a newer update. Its Progress projection and the local setup view reduce much of this to generic updating text and a ten-second reload. The rendered fixture establishes the generic wait; it does not simulate a real rejected image. Project bounded, broker-authored reasons with a viable next step or an explicit no-action state. Keep verified-update gates closed; no “continue anyway”, invented percentage, or unattended secret disclosure. UPD-b2/c4 own the assembly. [Backend status/projection](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/firstboot/firstboot.go#L210), [page](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/pages.go#L305).

### UX3-4 — Setup completion and examples are not tied to qualified capability

The Provider interface exposes API key/device-code/connected/private flags; completion requires a connected Provider. A zero-cloud-provider fixture cannot select local-only and never finishes. This demonstrates an interface/flow gap against ONB-3/8 and CAP-9/13, **not** proof that particular hardware has a qualified local model. “All set” examples depend only on connected account names/private permission, not route qualification: travel planning, a landlord note and recurring news appear without evidence those task classes work. “Add more later” has no corresponding authenticated model-management route in the current mounts after setup closes.

Represent qualified route readiness explicitly, including supported local-only and plan choices. Finish with one optional, achievable task that reaches an accepted result; count total owner effort. If no route is qualified, say what is missing. Do not silently add a cloud account, default private work onto plan/hosted routes, or broaden grants to make an example work. Preserve optional later setup and the minimum path. This extends existing D-051/c4/S8 work; it does not assert pending plan libraries are usable. [Provider interface](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/setup.go#L37), [completion](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/setup.go#L974), [welcome text](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/text.go#L23).

## Daily tasks, approvals and results

### UX3-5 — A second locked message destroys the task the owner just composed

Probe: send “Draft the supplier email”, then “Use the revised Friday date” while locked; authenticate; send RUN. Both messages were dropped and no task reaches the agent. A mistaken code can also clear held text. This is deliberate O5 safety behavior, but conflicts with CH-14's no-resend intent for natural multi-bubble composition.

**L1 design gate:** reconcile O5 and CH-14 before implementation. Propose a small, expiring quarantine with explicit authenticated inspection/selection and RUN bound to the selected content, or another bounded design achieving the same no-retype outcome. Possession of a later code must not authenticate earlier spoofable text. Do not concatenate, replace, execute or pass pending text to a guest automatically. Define count/size/rate/TTL/overflow/restart behavior and show disposition truthfully. This preserves potency by retaining composition, and security by keeping content selection a separate act. [Locked messages](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/owner/channel.go#L513), [O5](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/owner/ASSUMPTIONS.md#L13).

### UX3-6 — MORE cannot reveal the later items that YES can approve

A ten-item fixture shows items 1–3 initially and directs the owner to MORE for 4–10. MORE always shows 1–4 and sends the owner to the box's Wi-Fi page; a second MORE is identical. Yet YES can approve all ten. The gate can produce batches up to twenty. An owner away from home must either stop or approve unseen items, undermining the phone-first approval promise.

Add deterministic, read-only pagination or item inspection, with an L1 decision for command grammar. Bind each view to the existing request/fingerprints, show item range, expiry and valid answers, and preserve one code per batch. Changed, expired or reissued requests cannot inherit stale views. Keep full canonical recipients, CH-10 tier separation, separate local-only actions, current partial-YES denial semantics and OP-3 commit checks. This is distinct from SR3-3's incomplete grant-rule display and CH-20m's redirected private reply retrieval. [MORE](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/owner/approvals.go#L274).

### UX3-7 — A withheld result promises a page without preserving a retrievable result

The benign sentence “The source code has 1234 lines and the build passed.” triggers the conservative code/key filter and produces “Read it on the box's Wi-Fi page.” Notify replaces the text without retaining it. The short-reply production path bypasses the kept-reply store; the existing kept-reply list has no production page caller. A long-reply store alone would not repair the short-result loss.

Keep the conservative filter. Before promising retrieval, durably address a policy-allowed, redacted result to the authorized destination, or report truthfully that it could not be retained. Never retain raw credentials just to make a pointer work. Provide authenticated exact-result retrieval with bounded retention, restart behavior and an expired/unavailable state. Propose promoting **only this minimum portion of CH-20p** to release under CH-12/20; broad history and remote MORE can stay later. CH-20w's delivery wiring is complementary. [Filter](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/owner/disclose.go#L8), [Notify](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/owner/channel.go#L899), [short replies](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/cmd/agentosd/evidence.go#L178).

## Control, recovery and learning

### UX3-8 — STATUS cuts off remedies, and local status has no complete alternative

The real clock status line ends “Nothing to do.” Passing it through STATUS clips it to “Nothing ”. Notes are clipped at 100 characters; final GSM-7 fitting silently removes later exceptions in a multi-note fixture. The local status page renders box phase and actions running/stopped, without calling the already-authenticated OpLines endpoint. Broker readiness is not task capability. A synthetic rendered page confirms that limited presentation; co-occurrence of every fixture fault is not asserted.

Compose complete exception records with action/no-action, reserve an explicit overflow count and working retrieval route, and show all authorized records locally with a check time. Preserve three-segment SMS limits and private detail boundaries. A refresh must not erase entered codes. This extends W5 acceptance, not its implementation claim. [Clipping](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/control/handler.go#L301), [status route](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/server.go#L389).

### UX3-9 — Local STOP hides consequences already reported by SMS

The SMS path reports held, uncertain and cancellation-requested effects and says nothing was undone. LocalStop discards the journal StopReport; the local server returns only “Stopped”; the page replaces even that with a fixed confirmation. This is a source-proven information loss, not evidence that STOP fails to block dispatch.

Keep immediate unauthenticated STOP. Show only a safe generic explanation before sign-in; afterwards present the broker-owned receipt, unresolved effects, actual cancellation status and real undo windows. Receipt creation must not delay STOP. RESUME must retain current authentication and explain which held work can restart. No model should invent outcome certainty. [LocalStop](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/owner/local.go#L343), [page result](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/server.go#L497).

### UX3-10 — FORGET identifies a count, not which learned changes it affects

CAP-3 requires identifying which learned skills would change. The preview obtains only a learned-change count. SMS task labels clip to 24 characters; non-SMS tasks show a date/time only, deliberately protecting private content. Two similar tasks or learned changes can be hard to distinguish before deletion.

Use stable task/adoption identities and safe owner-recognizable metadata; retain SMS privacy restrictions and offer authenticated detail. Distinguish live recall deletion, backup replay and external actions that remain done. Preserve the existing second-item notice about taking back later agent work. Execution-time take-back scope already has an explicit deferred policy (`W3-forget-b2b q`); changing it needs L1, not an incidental UX patch. W3-forget-b still owns restored-backup deletion. [Preview and labels](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/cmd/agentosd/forget.go#L323).

### UX3-11 — Critical decisions are hard to read in dark mode and narrow layouts

The actual dark-mode approval page uses white 17px text on `#6ea8fe` (contrast **2.42:1**) and `#ff6b81` (**2.74:1**). Default blue links on `#121212` measure **1.99:1**. These miss the [WCAG 2.2 normal-text benchmark of 4.5:1](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html). A synthetic valid 191-character filename expands the document to **1,716px at a 320px viewport**; object and explanatory paragraphs do not wrap it. Ordinary short labels did not overflow at 390px.

Choose readable foreground/background pairs and wrap long fields without truncation, ellipsis or altered canonical values. Preserve the existing full recipient display, escaping and look-alike cues. Add contextual accessible names for repeated controls, visible focus and meaningful page titles; those are acceptance improvements, not claims from a screen-reader study. Test the [320 CSS-pixel reflow benchmark](https://www.w3.org/WAI/WCAG22/Understanding/reflow.html), zoom and both themes. [CSS](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/pages.go#L18), [full fields](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/localui/approvals.go#L244).

### UX3-12 — W6 needs a recovery journey an owner can finish

Recovery primitives and assumptions describe re-enrollment, partial card rotation, new-number persistence, re-trusting PCs and backup-key compatibility. W6's brief currently says to wire recovery into vault/localui; those primitives do not establish a finished owner journey. Extend W6 with drills for a new PC, lost phone, lost drive with backup, number replacement and interrupted rotation. Entry points must work when signed out or unable to use the old phone. Show what works, what remains restricted and what still needs securing. Retain possession factors, no inference/service dependency, restricted restored grants, revocations and spent budgets. This is planned integration, not a claim that merged recovery is broken. [W6](../../briefs/W6.md), [recovery follow-through](https://github.com/ghbmrk/agentOS/blob/c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1/broker/recovery/ASSUMPTIONS.md#L35).

## Preserve potency while reducing owner work

Three broader experiments should reuse existing integration work, not add another test framework:

1. **Task continuity:** interleave three tasks, corrections, delayed results and restart. Every result and authenticated correction binds to one stable task; ambiguous references ask once. Reuse pending POT-P2/P3 and INT-A. Transport delivery is not task success.
2. **Attention over a week:** zero heartbeat events, twenty background events, three active tasks, urgent quiet-hour exceptions, expiry, restart and failed/recovered SMS delivery. W5 must show exact-once outcomes and expired/defaulted questions without losing required notices. Measure total owner minutes, interruptions and segments, including recovery. W7 attention accounting alone is not proof of a low-burden product. Reuse H6/INT-A/W7-A (#258/#261/#264).
3. **First accepted result:** compare qualified local/API/plan configurations only where implemented, from fresh setup to an accepted useful result. Record setup time, retyped content, approval comprehension, failures and model/host cost. Do not trade lower prompt counts for concealed actions, weaker authentication, or unsupported capabilities. Voice fallback must carry the same batch by SMS when keypad approval is declined; codes never pass through ASR or the guest.

Retain the good foundations: phone-first commands, explicit STOP, code distinctions, canonical approval fields, bounded batches, optional setup, local pages without external assets, and recovery independent of model availability. No recommendation needs a compulsory dashboard, approval on every low-tier action, a longer blanket authentication window, hidden errors, a cloud-only onboarding dependency, or raw-secret retention.

## Decisions and sequencing

First repair visible setup initiation, batch inspection and truthful result retrieval; these directly prevent completion or informed consent. Next align status/STOP/FORGET and mobile readability. Carry route, recovery and attention acceptance into existing assembly packages rather than treating library tests as owner-readiness evidence.

Primary/L1 decisions are explicit: reconcile O5 with CH-14 for UX3-5; choose read-only pagination grammar for UX3-6; accept the minimum CH-20p release split for UX3-7; resolve any route-readiness contract beyond D-051/ONB/CAP before UX3-4 code. This PR changes no SPEC or DECISIONS. Each implementation must recheck current main, claim its owning row, add meaningful regressions and receive the required risk-tier reviews.

Later proposals are [recorded in LATER](../../LATER.md#deep-ux-review-intake-2026-10-08): distinguish learned-change receipts by useful outcome (UX3-L1); allow selecting older FORGET records (UX3-L2); make backup age/staleness actionable (UX3-L3). Existing five-task selection and backup-age policies are deliberate scope choices, not newly asserted defects. No recommendation here closes security SR3 findings or pending potency PRs.
