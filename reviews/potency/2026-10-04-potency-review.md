# Potency review 1 (spec v0.11 @ e841b78)

**Scope:** where the spec limits what the box can do for the owner without buying matching security or UX. Inputs: SPEC.md, PLAN.md, DECISIONS.md, spike results S3, S4, S7. Open PR #8 (UX review 1) was read so IDs don't collide; nothing here depends on it merging.
**Yardstick:** owner-minutes per accepted task (§1), broken into the bottlenecks the design already names: owner attention, reach, parallelism, compounding, and frontier quota.
**Labels:** [Fact] verifiable · [Measured] from a spike · [Inference] reasoned, untested · [Risk] needs a spike · **[Decision]** Mark's call.
**For the arbitrator:** every finding carries a potency / security / UX line. "Conflict" marks the ones where the lenses pull apart and the arbitrator should weigh in before Mark decides.

The paired spec diff (same PR) implements findings marked **→ spec**. Findings marked **→ later** are recorded for a future run or a spike.

---

## Summary

| # | Cap in the spec today | Potency gain | Security cost | UX cost | Proposal |
|---|---|---|---|---|---|
| 1 | Speculative parallelism is N ≤ 2 at the floor because each branch is a full OpenClaw machine (~1.54 GB PSS, S4) | Fork width set by the work, not the runtime: tens of branches at the floor instead of 1–2 [Inference from S3's ~25 MiB idle worker] | None new: same isolation, custody, and admission | None | **Worker machines** (no agent runtime) driven by the guest → spec CAP-8 |
| 2 | Agent-machine egress is "declared" (§4) yet browsing has "full power" (CAP-2); neither says what is open, and open egress from a machine holding private data is an unmediated disclosure path (REV-2) | Open internet by default for machines that hold no private data, instead of a builder defaulting to deny | **Gain:** closes an unstated leak path for machines that do hold private data. Residual: a few bytes can still leak through fetch URLs | None | **Egress follows data**: open and private machine classes → spec REV-5. **Conflict** (residual leak) |
| 3 | Model access is per guest; no requirement to use all the owner's AI accounts or fail over when one is out of quota | Work continues when one subscription hits its window; each task class goes to the provider that measures best | Private data reaches more providers; mitigated by per-provider data limits | Fewer "out of quota" stalls | **Model routing** across granted providers and local models → spec CAP-9 |
| 4 | Every Loop 1 improvement is a behavior change needing owner approval (CHG-3, OP-5) unless a standing grant exists, and none is defined | Compounding runs at machine speed instead of owner-attention speed | A bad skill can adopt silently; bounded by held-out suite, unchanged authority, gated irreversible effects, and one-word undo | Fewer prompts; one digest line per adoption | **Default standing grant** for authority-neutral local improvements → spec CHG-6 |
| 5 | Pre-allowances (ADP-9) allow templated content only, so no reply with agent-written text can ever run without a prompt | The most common routine (answering an existing thread) can run unattended | **Conflict:** an agent-written reply can make a commitment or say something wrong. Disclosure is bounded structurally: the composer sees only that thread | Owner opts in per account; undo window | **Context-scoped replies** → spec ADP-10. **Conflict** |
| 6 | The box's own SIM is used only for the owner channel | Reach into the phone-only world: book, ask, confirm by call or text | Shares the SIM with the owner channel, so carrier filtering of outbound traffic could take down the owner channel | Owner sees transcripts; carrier-filtering risk (UX review finding 18) | **The SIM as a tool** with disclosure and rate limits → spec ADP-11. **Conflict** (availability), **[Decision]** MVP or later |
| 7 | Away from home, evidence is limited to text (§6.3); reviewing a diff or a document waits for the box's Wi-Fi | Rich review from anywhere without a relay | Content leaves the box to the carrier (MMS) or to an account the owner already uses; destination changes are high-risk intents | Big gain for remote approvals | **Evidence delivery** to an owner-owned destination → spec CH-18, §6.3 |
| 8 | Owner questions block the task until answered | Work keeps moving overnight on reversible decisions | None: a default carries no authority; irreversible effects stay gated | Fewer blocking questions; defaults listed in the digest | **Default-on-timeout questions** → spec CAP-10 |
| 9 | Credentialed executors: one account each, one browser at a time at the floor | More accounts served at the floor by time-sharing | Executor snapshots hold sessions; they must stay broker-encrypted | None | Executor parking → later (P2, S5) |
| 10 | Action protocol is single-step (CRED-4) | Fewer model calls per logged-in task | None if verbs are broker-implemented, with no JavaScript exposed | None | Composite verbs (`extract_table`, `fill_form`) → later (S5) |
| 11 | Broker tools reach OpenClaw through tool search: one or two extra model calls per effect (S4 finding 3) | Fewer calls per effect | None | Faster replies | Check config promotion of MCP tools → later (ARC-5 follow-up) |
| 12 | All compute is on the box | Burst parallelism beyond the floor | Data and snapshots leave the box | None | Burst workers on owner-held compute, open-class work only → later (post-MVP) |

Net effect [Inference]: findings 1, 3, 4, and 8 raise throughput and autonomy at no cost to any invariant; 2 raises potency and security together; 5, 6, and 7 trade a stated, bounded security or availability cost for large attention savings and go to the arbitrator and Mark.

---

## Findings

### 1. Parallelism is capped by the runtime, not the work (CAP-1)
[Measured] S4: one OpenClaw machine is ~1.54 GB PSS with a 27 s cold start. S3: a gVisor sandbox with idle Node costs ~23 MiB; full-state fork of a 1.6 GB machine takes ~4 s for n=2. So CAP-1 as written gives N ≤ 2 at the floor.

But speculative parallelism needs branches that **run** approaches and tests, not branches that each **think**: the reasoning is remote. One guest can plan and drive many lightweight sandboxes.

Proposal (CAP-8): guests may create **worker machines**: agent machines without an agent runtime, built from a base image, driven through broker tools (exec, files, checkpoint, fork, diff, rollback). Workers inherit the creator's isolation, snapshot custody, budget reservation, and egress class (REV-5). CAP-1's N counts workers, and RES-2 admission sizes it.
- **Security cost:** none new. More machines under the same boundary; resource exhaustion is RES-2's job and Loop 2 already probes it (LOOP-7).
- **UX cost:** none.
- **Evidence still needed:** worker fork timings on the N95 (S3 "still to measure").

### 2. Egress is undefined, and the gap cuts both ways (§4, CAP-2, REV-2)
§4 allows "declared uncredentialed egress"; CAP-2 promises "uncredentialed browsing with full power". A careful builder reading "declared" will default-deny, which cripples research, package installs, and documentation lookups. A permissive builder will allow everything, which lets an injected agent that has read the owner's mail post it anywhere: an irreversible disclosure that REV-2 says must be journaled but nothing mediates.

Proposal (REV-5): egress follows the data a machine holds.
- **Open** machines have received only public data and the owner's task text. They get full uncredentialed egress.
- **Private** machines have received anything else: recall results, owner files, credentialed-executor output, mail or document content. Their egress is limited to owner-allowlisted read sources (package mirrors, documentation) and a broker `fetch` tool that is journaled and bounded in request size and rate.
- Class only escalates during a machine's life. Rolling back to a snapshot from before the private data arrived restores open.
- **Potency gain:** an explicit, maximal default for most research and build work.
- **Security cost:** none relative to today's text; it closes a gap. **Residual [Risk]:** a private machine can still leak a little through fetch URLs. The bound is size, rate, and the journal, not zero. Owner task text is treated as open, which means a task statement the owner writes can reach the internet; that is the stated tradeoff.
- **UX cost:** none for the owner.
- **Conflict for the arbitrator:** whether task text should count as private (safer, much less potent) and what fetch bounds are acceptable.

### 3. One guest, one provider, no failover (§4, CRED-5, LOOP-1)
The owner pays for several AI accounts, each with its own rate window. The spec uses spare quota for loops (LOOP-1) but says nothing about routing foreground work across accounts, so a task stalls when one window closes. S4 already showed the guest sees a single placeholder endpoint at the broker, so routing can be invisible to the guest.

Proposal (CAP-9): the broker routes each model call across the providers the owner has granted, and local models, by task class, scored on measured acceptance, latency, cost, and remaining quota. Routing rules are a Loop 1 candidate class (as ADP-4). When one route is exhausted, the call fails over to the next granted route. The owner may restrict data per provider, enforced from the machine's egress class (REV-5).
- **Security cost:** private data may reach more providers than one. The per-provider restriction is the mitigation; routing never adds a provider the owner hasn't granted.
- **UX cost:** none; fewer stalls.
- Spend metering at model egress (OP-8, proposed in S4's result) is the natural place for this; the two should land together in v0.12.

### 4. Compounding waits on the owner (CHG-3, OP-5, LOOP-6)
Loop 1 produces procedures, compiled skills, and routing rules. Each is a behavior change, and CHG-3 requires owner approval unless a standing grant covers the class. No such grant is defined, so by default every improvement is an approval prompt, and compounding runs at the speed of the owner's attention.

Proposal (CHG-6): a default standing grant, changeable under LOOP-0, for local candidates that change only procedures, compiled skills, routing among already-granted routes, or context rules, **and** pass the held-out suite with no regression, **and** change no grant, verb class, custody, check, or security-suite coverage (LOOP-10). They adopt without a prompt, appear in the digest, and revert with one reply. Upstream and shared packages keep CHG-3 and UPD-5.
- **Security cost:** a candidate mined from injected content could encode bad behavior. Bounds: the held-out suite comes from real owner outcomes (CHG-1), authority can't change, every irreversible effect stays gated (REV-2), and rollback is one reply.
- **UX cost:** one digest line per adoption, instead of one prompt.

### 5. Pre-allowances can't cover written replies (ADP-9)
ADP-9 requires templated content with no free text. That is right for payments and notifications, but it excludes the commonest routine there is: answering an existing thread ("yes, Tuesday works"). Every such reply costs an approval forever.

The risk ADP-9 guards against is disclosure: an agent steered by injected content writing private data to someone. That can be bounded by information flow, the same principle as the clean room (OSS-2), instead of by banning free text.

Proposal (ADP-10): the owner may pre-allow **context-scoped replies**, per account. The recipients are exactly the thread's existing participants, read by the broker from the source. The reply is composed in a fresh machine that receives only that thread plus owner-approved style preferences, with no recall, no other files, and no egress, so it can disclose only what the participants already have. No attachments. It sends after an undo window (default 10 minutes, REV-3) and appears in the digest. Scope bounds, STOP, and the journal apply as in ADP-9. Money, new recipients, and CRED-6 content are excluded.
- **Security cost:** disclosure is bounded structurally. **What is not bounded:** a reply can still make a commitment or say something wrong to a real person. The undo window and digest are the mitigations, not prevention. **Conflict** for the arbitrator.
- **UX cost:** opt-in per account; the owner sees replies in the digest and can undo within the window.
- **[Decision] D2.**

### 6. The SIM is idle reach (CAP-2, CH-1)
The box has its own number. Much of daily life (booking, confirming, asking a business) is still phone-only. The spec uses the SIM only to talk to the owner.

Proposal (ADP-11): the box's SIM is reachable as an adapter for outbound texts and calls to third parties, both mapped to the `send` verb. Calls open with a disclosure that an automated assistant is calling for the owner. Recipients are verified (owner contacts, or a number the broker fetched from a source) or supplied by the owner. Transcripts are journaled. Calls are rate-limited separately from owner texts.
- **Security cost:** impersonation risk is limited by the opening disclosure. **Availability conflict:** carrier filtering or suspension caused by outbound traffic would also take down the owner channel (CH-1), which DEP-1 relies on. Mitigation: strict rate limits; a second SIM post-MVP.
- **[Risk] legal:** automated calls are regulated. [Fact] In February 2024 the US FCC ruled that AI-generated voices count as "artificial" voices under the TCPA, so calls to consumers need prior consent. The default should therefore be business numbers and owner contacts only, and jurisdiction rules need checking before release.
- **UX cost:** carrier-filtering risk (UX review finding 18); live-call quality depends on S2.
- **[Decision] D3:** MVP or post-MVP. [Rec] spec it now, build after S2 qualifies voice.

### 7. Remote review is text-only (§6.3, risk 5)
Without a relay, the owner reviews diffs and documents only on the box's Wi-Fi. That makes every evidence-heavy approval wait until the owner is home. The UX review left this as a recorded tradeoff (its finding 17).

The relay ban doesn't require text-only. The owner already has places to receive rich content: MMS on the phone, and an email inbox or cloud folder.

Proposal (CH-18): evidence beyond one text (diffs, screenshots, documents) may be delivered as broker-rendered MMS images, or to **one owner-owned destination** chosen at setup or later (an email address or cloud folder the owner already uses), through its adapter. Delivery to that fixed destination is a pre-allowed `share` to the owner only. Changing the destination is a high-risk intent. CRED-7 redaction applies.
- **Security cost:** content leaves the box to the carrier (MMS) or to the owner's existing provider. That is a privacy cost, not a custody one. The destination is fixed by the owner, so an agent can't redirect it.
- **UX cost:** none; a large gain. Approvals can be decided with evidence from anywhere.
- DEP stays intact: it's an optional dependency (DEP-3), and text-only still works without it.

### 8. Questions block work (CAP-6, §8.3)
An agent that needs a choice from the owner stops until the owner answers, often hours later. When every option leads only to reversible work, waiting buys nothing.

Proposal (CAP-10): the agent may ask with a stated default and a deadline. Without a reply it proceeds on the default and lists it in the digest. The default carries no authority: any irreversible effect that follows still needs its own approval (REV-2).
- **Security cost:** none.
- **UX cost:** fewer blocking questions; one more kind of message. It follows CH-12's format and CH-15's pacing if PR #8 lands.

### 9–12. Later
- **Executor parking (9):** at the floor, snapshot an idle credentialed executor (broker-encrypted, CRED-1) and restore it on demand, so more accounts time-share one browser slot. Measure in P2 with S5.
- **Composite protocol verbs (10):** broker-implemented `extract_table`, `fill_form(map)`, `wait_for(text)` cut model calls per logged-in step with no JavaScript exposed. Feed into S5's verb list.
- **Tool-search hop (11):** S4 finding 3. Check whether OpenClaw config can put broker tools on the direct surface.
- **Burst workers (12):** open-class workers (REV-5) on owner-held compute (another PC on the LAN, or the owner's cloud account) as an optional dependency. Post-MVP, since the snapshot custody story changes.

### Considered, not proposed
- **Arbitrary JavaScript in credentialed browsers.** It would make logged-in automation much stronger, but page scripts can read non-HttpOnly cookies and stored tokens, which breaks Invariant C (CRED-1). Composite verbs (10) get most of the gain.
- **Agent-supplied recipients in pre-allowances.** That breaks ADP-9's verified-inputs rule and opens injection-driven sends. ADP-10 keeps recipients broker-verified.

---

## Revisions after L3 review (PR #11)
The L3 security review found five blocking gaps. All are fixed in the spec diff:
1. **REV-5 propagation.** Any broker-mediated write from X into Y raises Y to X's class. Rollback restores open only when no higher-class machine can write in. A14 tests a private guest writing into an open worker.
2. **ADP-10 disclosure.** The composer sees only thread messages that every recipient of the reply received, computed from source headers.
3. **ADP-11 inbound.** Texts and calls from non-owner numbers are untrusted data, never control words, task chat, or approvals.
4. **CHG-6 classification.** The broker classifies from artifact type and diff, the security suite runs on every auto-adoption, re-enabling is an owner-approved intent, and "context rule" is defined.
5. Compiled `.pyc` files were removed and a `.gitignore` added.

Non-blocking changes taken:
- Allowlisted read sources narrowed to content-addressed mirrors. `fetch` bounds are frozen before A14.
- CAP-9 routing can never override a data restriction. By default, private data goes only to providers marked as allowed for it.

**Two positions changed:**
- **D1:** task text is now **private by default**, and the owner can mark a task public. A private machine can start an open research machine through a query bounded like `fetch`. That keeps most of the research potency without making "tell the attacker's URL what the task says" a one-step leak. The potency claim in finding 2 now rests on that research channel.
- **D2:** a queued reply now sends a text to the owner with `UNDO`, because the undo window is useless if nobody sees it. The reviewer recommends not shipping ADP-10 in MVP.

## Decisions for Mark
- **D1** Egress default (REV-5): task text is private unless marked public, and open research goes through a bounded query (proposed after review), or task text counts as open (more potent, one-step leak risk).
- **D2** Context-scoped replies (ADP-10): opt-in per account, with a notification and undo for each reply, or not for MVP (reviewer's recommendation). [Rec] Not for MVP; revisit once A14 and A10 data exist.
- **D3** Box SIM for third-party calls and texts (ADP-11): in the spec now and built after S2 (proposed), or deferred to post-MVP.
- **D4** Authority-neutral improvements auto-adopt by default (CHG-6, proposed), or each one asks.
