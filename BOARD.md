# BOARD

Index of work packages, one line each. Each row links its brief in `briefs/<ID>.md`; the State column is last and starts with one of: `queued` → `building` → `in review` → `merged` | `escalated` | `dropped`, optionally followed by a short note in parentheses. Detail goes in the brief, not the row (docs/OPERATING.md §5). Which rows the first release needs is LATER.md.

## Harness and operating model

| ID | Package | Needs | State |
|---|---|---|---|
| PILOT-S | [Sonnet builder pilot](briefs/PILOT-S.md) | — | building (2026-10-08 through the 2026-10-18 reset, D-060) |
| DOC-1 | [One home per fact; review pipeline; per-PR lens records](briefs/DOC-1.md) | — | merged (#355) |
| DOC-3 | [BOARD index and briefs; DECISIONS format](briefs/DOC-3.md) | DOC-1 | merged (#356) |
| DOC-2 | [doclint and cause metrics](briefs/DOC-2.md) | DOC-3 | merged (#357) |
| DOC-4 | [Per-file review records; no shared run tables](briefs/DOC-4.md) | DOC-1, DOC-2 | building |
| SR3 | [Register the security and architecture review](briefs/SR3.md) | DOC-3 | in review (Codex proposal to primary; documentation only) |
| HK-1 | [depaudit self-test flake fix](briefs/HK-1.md) | — | in review |
| DEP-2 | [depaudit evidence out of the tracee's reach](briefs/DEP-2.md) | HK-1 | queued (release; #401 L3 R1 and lens) |

## Security and architecture review (2026-10-08)

Primary lane; remediation is unclaimed. [Review record](reviews/security/2026-10-08-architecture-review.md).

| ID | Package | Needs | State |
|---|---|---|---|
| SR3-1 | [Bind local sign-in to the authenticated lock generation](briefs/SR3-1.md) | P2-2w a, P2-2w b | in review (#431) |
| SR3-2 | [Enforce pre-allowance rate limits at dispatch](briefs/SR3-2.md) | P2-grants, P2-gr8 | queued (P2; release) |
| SR3-3 | [Show and bind the complete pre-allowance rule at approval](briefs/SR3-3.md) | P2-grants, P2-2a | queued (P2; release) |
| SR3-4 | [Make update finalization durable and idempotent](briefs/SR3-4.md) | UPD-a, P4-3, P3-1 | queued (P2; release) |
| SR3-5 | [Preserve IMAP message identity through mutations and undo](briefs/SR3-5.md) | P2-6m | queued (P2; release) |
| SR3-6 | [Invalidate verified updates when attestation policy narrows](briefs/SR3-6.md) | P4-3, P3-1 | queued (P2; release) |
| SR3-7 | [Use one validated request for model reservation and routing](briefs/SR3-7.md) | P2-7, P1-7 | queued (P2; release) |
| SR3-8 | [Commit clean-room output durably before recording completion](briefs/SR3-8.md) | P4-2 | queued (P2; release) |

## Phase 0: harness and risk spikes

| ID | Package | Needs | State |
|---|---|---|---|
| H0 | [Repo scaffold](briefs/H0.md) | — | merged |
| H1 | [Metrics harness](briefs/H1.md) | H0 | merged (00c298d; tools/metrics.py) |
| TR1 | [Trace gaps the code already meets](briefs/TR1.md) | H0 | merged (#107) |
| S7 | [Host foundation](briefs/S7.md) | Cloud only | merged (result, systemd image stack on Debian 13; HW-5a decided) |
| S3 | [Agent machines at 8 GB](briefs/S3.md) | Cloud first, then N95 | merged (cloud part; Firecracker + N95 timings wait on hardware) |
| S4 | [OpenClaw unmodified as a guest via broker tools; record any…](briefs/S4.md) | Cloud only | merged |
| S5 | [Credentialed browser](briefs/S5.md) | see brief | building (fixture suite passes (interim result); live run blocked on network policy) |
| S6 | [Consumer AI CLIs in no-tools relay mode](briefs/S6.md) | Mark's accounts | dropped (superseded by S8 (CRED-5 now covers full provider agents)) |
| S8 | [Provider agents as workers](briefs/S8.md) | Cloud first (stubs), then Mark's accounts | merged (03641d1; #186 cloud part and spec diff) |
| S8-W1 | [Image fix for worker-held custody](briefs/S8-W1.md) | S8, #186 | queued |
| S8-live | [S8 live part](briefs/S8-live.md) | see brief | queued |
| S8-codex-terms | [Read OpenAI's current terms on a proxy holding ChatGPT-managed…](briefs/S8-codex-terms.md) | openai.com reachable | in review (decided: broker-held, unconfirmed route, #328; [note](spikes/S8-provider-workers/CODEX-TERMS.md)) |
| CRED-5f | [CRED-5 fallback when no API key is granted](briefs/CRED-5f.md) | #328 | queued |
| CRED-5t | [Broker-held route failure triggers and fail-closed refresh test](briefs/CRED-5t.md) | #328 | queued |
| CRED-5w | [Owner pause and withdrawal notice for broker-held routes](briefs/CRED-5w.md) | #328 | queued |
| S1 | [Screenless USB4-SSD boot on ≥3 unmodified PCs](briefs/S1.md) | Mark: hardware + hands | queued (test kit ready; waiting on hardware) |
| S2 | [USB LTE modem](briefs/S2.md) | Mark: 2 modems + SIM | queued (test kit ready; waiting on hardware) |
| P0X | [Spec v0.12](briefs/P0X.md) | — | merged (cada7c1; SPEC.md v0.12) |

Exit of P0: spike results → spec v0.12 diff → Mark approves → budget re-estimate.

## Phase 1: core in a VM

Started before spec v0.12 on parts unlikely to change; each package lists its spec assumptions.

| ID | Package | Needs | State |
|---|---|---|---|
| P1-1 | [Journal and intent engine](briefs/P1-1.md) | Cloud only | merged (05913d0; broker/journal) |
| P1-2 | [Broker skeleton](briefs/P1-2.md) | P1-1 | merged (7ff7417; broker/daemon) |
| P1-3 | [Vault and credentialed egress proxy](briefs/P1-3.md) | P1-2 | merged |
| P1-4 | [Agent-machine lifecycle](briefs/P1-4.md) | P1-2 | merged (f19f97c; broker/vm) |
| P1-6 | [Canary harness](briefs/P1-6.md) | Cloud only | merged |
| P1-5 | [Owner channel on a modem simulator](briefs/P1-5.md) | P1-2 | merged |
| P1-7 | [OpenClaw as first guest](briefs/P1-7.md) | P1-3, P1-4, P1-5, P1-6 | merged (847ea23; broker/guest) |

## Phase 2: real hardware, cloud parts first

| ID | Package | Needs | State |
|---|---|---|---|
| P2-grants | [Grants and approval policy](briefs/P2-grants.md) | P1-7 | merged (a390f03; broker/grants) |
| P2-rev3 | [Reversible conversions](briefs/P2-rev3.md) | P2-grants | merged (04be62e; broker/reversible) |
| P2-gr8 | [GR8 fix: approval used up inside the dispatch commit](briefs/P2-gr8.md) | P2-rev3 | merged (a390f03; broker/grants) |
| P2-2 | [Owner Card and local web UI](briefs/P2-2.md) | P1-5 | merged (a0bb643; broker/localui; LocalUI still off) |
| P2-7 | [Provider adapters](briefs/P2-7.md) | P1-3, P1-7 | merged (e7c419b; broker/modelroute) |
| P2-3 | [Real modem integration, cloud part](briefs/P2-3.md) | P1-5, S2 | merged (46e3885; broker/modem) |
| P2-3b | [Second line as an owner-held VoIP/SIP account](briefs/P2-3b.md) | P2-3 | merged (27f6fe9; broker/sipsign) |
| P2-3c | [SIP second line wired](briefs/P2-3c.md) | P2-3b, P2-4c | merged (0a6c2c7; #159 part 5) |
| P2-3w | [Modem bridge](briefs/P2-3w.md) | P2-3, P2-3c | merged (65b48ef; #170 part 1; later parts not on board) |
| P2-6m | [Mail adapter](briefs/P2-6m.md) | P2-grants, P3-3 | merged (c5feca1; broker/mail) |
| P2-4a | [Vault passphrase key slot and vault process](briefs/P2-4a.md) | P1-3, P1-7, P2-7 | merged (ad55ae2; broker/vault) |
| P2-4c | [Vault verify operation](briefs/P2-4c.md) | P2-4a | merged (ad55ae2; broker/vault) |
| P2-4b | [Trusted-host TPM slot, cloud part](briefs/P2-4b.md) | P2-4a | merged (6303190; broker/tpmseal) |
| P2-4d | [Vault rollback counter](briefs/P2-4d.md) | P2-4b | merged (ad55ae2; broker/vault) |
| P2-9 | [Box time check](briefs/P2-9.md) | P2-3 | merged (#68, ef4c1dc) |
| P2-4-hw | [Argon2id tuned to about 1 s on the N95](briefs/P2-4-hw.md) | Mark: hardware | queued |
| P2-4e | [Vault unlock page](briefs/P2-4e.md) | P2-2, P2-4a, P2-4c | merged (#50) |
| P2-4f | [One code unlocks the box and signs the phone in](briefs/P2-4f.md) | P2-4e, P2-4b (#42) | merged (#65) |
| P2-4g | [Interrupted passphrase change on the unlock page](briefs/P2-4g.md) | P2-4d (#63), P2-4e | merged (ad55ae2; broker/vault) |
| P2-4h | [Interrupted passphrase change follow-ups (#93)](briefs/P2-4h.md) | P2-4g | merged (ad55ae2; broker/vault) |
| P2-8 | [Recovery and portability, cloud part](briefs/P2-8.md) | P2-4a, P2-2 | merged (#35; re-encryption in review) |
| P2-8b | [Remove a trusted PC now and re-encrypt later](briefs/P2-8b.md) | W6 | queued |
| BAK-1 | [Backup choice and the only-copy notice](briefs/BAK-1.md) | P2-8 | merged (#80) |

## Phase 3: compounding

| ID | Package | Needs | State |
|---|---|---|---|
| P3-1 | [Change pipeline](briefs/P3-1.md) | P1-1, P2-7 | merged (cff139d; broker/change) |
| P3-1b | [Change wiring in the grants gate](briefs/P3-1b.md) | P3-1, P2-grants | merged (cff139d; broker/change) |
| P3-1a | [Replay evaluator](briefs/P3-1a.md) | P3-1, P1-7 | merged (30d601c; broker/replay) |
| P3-2 | [Loop scheduler and Loop 1](briefs/P3-2.md) | P3-1, P3-1a | merged (0302131; #189; broker/loops) |
| P3-4 | [Loop 2, self-securing, defensive part, as a scheduler Source](briefs/P3-4.md) | P3-2 | merged (c5feca1; broker/loops Guard) |
| P3-4b | [Loop 2 active testing from inside the sandbox](briefs/P3-4b.md) | P3-4 | queued (escalated 2026-10-08 after a third stop by an automated safety check; Mark split A11 loop 2, D-070); re-brief against D-070 (A11 loop 2: seeded failing test); D-070 merged (#408, eb65f4d), re-brief in progress |
| P3-5 | [Loop 3, maintenance, as a scheduler Source](briefs/P3-5.md) | P3-2, P4-3 | merged (4672fe8; broker/maintain) |
| P3-3 | [Recall index and event bus](briefs/P3-3.md) | P1-1, P1-2 | merged (5980098; broker/recall) |
| P3-7 | [Goal IDs on guest intents](briefs/P3-7.md) | P1-7 | merged (847ea23; broker/guest goal.go) |
| P3-6 | [Compiled skills](briefs/P3-6.md) | P3-1, P3-1a | merged (04be62e; broker/compile, skill) |
| P3-6b | [Attention optimizer](briefs/P3-6b.md) | P2 grants | merged (04be62e; broker/attention) |
| P3-1c | [Split the change pipeline's suites by task, not case ID](briefs/P3-1c.md) | P3-1 | merged (#70, c8bf480) |
| P3-6c | [Seed the managed tree's `skills/` and `procedures/` only into…](briefs/P3-6c.md) | P3-6, P1-4 | merged (done by W1 (#56, 13eb221): `vm.CreateSeeded` refuses any machine not…) |
| P3-6d | [Change digest](briefs/P3-6d.md) | P3-6, W5 | queued |
| P3-6e | [Condition before wiring a model-backed builder for the slow-step…](briefs/P3-6e.md) | P3-6 | merged (2a0a5610) |
| P3-3b | [Recall at mailbox scale and wired into the broker](briefs/P3-3b.md) | P3-3 | merged (44975b6; 2/2, #59; wired in #152 469c644) |
| P3-8 | [Default-on-timeout questions](briefs/P3-8.md) | P1-7, P2-grants | merged (2b1bd8a; broker/question) |
| P3-8b | [Questions: potency follow-ups (#71)](briefs/P3-8b.md) | P3-8, W9 | merged (2041b06b) |

## Phase 4: open source

| ID | Package | Needs | State |
|---|---|---|---|
| P4-1 | [Hint schema](briefs/P4-1.md) | — | merged (#40, e7f84a6) |
| P4-2 | [Clean-room builder](briefs/P4-2.md) | P4-1 | merged (d6a5046; broker/cleanroom) |
| P4-3 | [Release signing tooling and update verification](briefs/P4-3.md) | Cloud only | merged (8bab3fe; broker/update) |
| P4-4 | [Attestation schema](briefs/P4-4.md) | P4-3 | merged (#73, da8599a; follow-up in review) |

## Backlog refill (2026-10-05)

Gaps found by comparing the build plan (§3) and spec v0.12 with this board, TRACE.md (31 of 144 IDs uncovered at a0feaa7) and the open PRs. **Unblocked** rows can start now in the cloud. Rows are in suggested order. P2-1 (plan P2 item 1) has a draft PR, #41, but no row of its own; IMG-1 adds its missing checks. Not listed: hardware-only IDs (HW-3 to HW-7, the N95 halves of HW-4 and A2), OSS-12 (Mark chooses the license), LOOP-7 (P3-4b, re-brief against D-070's A11 after a third stop by an automated safety check on 2026-10-08; finding a seeded vulnerability is later, P3-4c), CRED-2 (a scope statement, not testable), and CAP-7 (guest behavior, which the spec says is not infrastructure).

| ID | Package | Needs | State |
|---|---|---|---|
| P2-5r | [Revive P2-5: resource admission and budgets](briefs/P2-5r.md) | P1-4, PE6 merged | merged (#124) |
| RES-2c | [Lift the 4500 MiB admission cap on larger boxes](briefs/RES-2c.md) | P2-5r merged, A2 large-host run | merged (9fa31bc; #140) |
| RES-t | [P2-5r carry-forward (#124): checkpoint cut short](briefs/RES-t.md) | P2-5r merged | merged (#129) |
| TR2 | [Trace gaps the code already meets, tests only](briefs/TR2.md) | — | merged (#128) |
| CAP-8 | [Worker machines](briefs/CAP-8.md) | P1-4, P1-7 | merged (#146) |
| CAP-8b | [Worker follow-ups (#146): file offsets, tar over exec](briefs/CAP-8b.md) | CAP-8 merged | merged (244974b; #150) |
| CAP-8c | [Worker follow-ups (#150): layer cap, delete-only commands](briefs/CAP-8c.md) | CAP-8b merged | merged (c4c2366; #166) |
| CAP-1 | [Speculative parallelism](briefs/CAP-1.md) | CAP-8 | merged (49cc421; commit on main; item D merged via #166) |
| UPD-a | [Update apply, broker side](briefs/UPD-a.md) | P3-5, W5b; P2-1 for real activation | merged (#133) |
| UPD-b | [First boot updates before trust](briefs/UPD-b.md) | UPD-a | in review (broker side: `broker/firstboot`, applier first-boot path, local page wording; wiring UPD-b2 and image side UPD-b3 queued) |
| UPD-b2 | Wire the first-boot gate into agentosd (UPD-3; conditions in broker/firstboot/ASSUMPTIONS.md F7, including the clock-guard condition and a test that no connect path skips `Hold()`; brief to write) | UPD-b, W5b, UPD-a wiring (apply A7) | queued |
| UPD-b3 | First-boot update, image side: preloaded root metadata and mirror list, real activator (UPD-3; broker/firstboot/ASSUMPTIONS.md F8; brief to write) | UPD-b, P2-1 (#41) | queued (blocked on P2-1) |
| UPD-c | [Update channel and cadence as owner settings](briefs/UPD-c.md) | P3-5; W5b to reach the live box | merged (#130; carry: local page, quiet-window jitter (UPD-a), standing grant for…) |
| CH-20 | [Evidence delivery](briefs/CH-20.md) | P2-6m; P2-3 for MMS | merged (#148: destination path; MMS waits on P2-3) |
| CH-20p | [Kept replies on the local page](briefs/CH-20p.md) | CH-20, P2-2 | queued (blocked on P2-2) |
| CH-20a | [Bounded attachments in `mail.deliver`](briefs/CH-20a.md) | CH-20w | queued (needs security review) |
| CH-20m | [MORE for a redirected reply](briefs/CH-20m.md) | CH-20w | queued |
| CRED-4b | [Credentialed browser executor in the broker](briefs/CRED-4b.md) | S5 fixture suite | building (claude2; part 1 in review, #300; part 2 per K1-K13) |
| ADP-8 | [Adapter mismatch check and the §11 adapter path](briefs/ADP-8.md) | P3-1, P2-7 | queued (unblocked; lane claude2) |
| ADP-5 | [Desktop-app executor, Linux](briefs/ADP-5.md) | CRED-4b | queued (blocked on CRED-4b; lane claude2) |
| OSS-6 | [Publication identity](briefs/OSS-6.md) | P4-1, P4-4 | merged (#163, 8a67351) |
| OSS-6s | [Publication sender](briefs/OSS-6s.md) | OSS-6 | dropped (split into OSS-6s-a and OSS-6s-b on #325) |
| OSS-6s-a | [Constant daily batch, idempotent ledger, cover send](briefs/OSS-6s-a.md) | OSS-6 | merged (6790cf4; #411) |
| OSS-6s-b | [Tor transport to Nostr relays, and the pull job](briefs/OSS-6s-b.md) | OSS-6s-a, OSS-6p, OSS-6i, OSS-6j | queued |
| OSS-6m | [Measure the daily publication batch constant](briefs/OSS-6m.md) | OSS-6s-a | queued (optional, non-blocking) |
| OSS-6j | [Spec: what the repository's pull job is](briefs/OSS-6j.md) | #330 | queued (L1 spec diff) |
| OSS-6i | [Fresh Tor circuit per batch and signing key](briefs/OSS-6i.md) | #330 | queued (L1 clause, then test in OSS-6s) |
| OSS-6p | [Relay count, delivery rule, queue bound, relay list source](briefs/OSS-6p.md) | #330 | queued |
| OSS-6a | [Spec: where ask-each-time prompts appear](briefs/OSS-6a.md) | #330 | queued (L1 spec diff) |
| OSS-5t | [Spec: transport for the embargoed security report](briefs/OSS-5t.md) | #330 | queued (L1 spec diff) |
| OSS-9 | [Attestations as evidence and following forks](briefs/OSS-9.md) | P4-3, P4-4 | merged (4329b1d; #180) |
| OSS-6c | [Publication clock hardening](briefs/OSS-6c.md) | OSS-6 | merged (4329b1d; #180) |
| OSS-6e | [Floor across restarts](briefs/OSS-6e.md) | OSS-6c | in review (A) |
| OSS-10w | [Follow-fork executor wiring](briefs/OSS-10w.md) | OSS-9, HOST-1b, P2-2w | merged (#323) (A) |
| OSS-10w2 | [Follow-fork wiring part 2](briefs/OSS-10w2.md) | OSS-10w, P2-2w b, P2-2w d | in review (A) |
| OSS-10w2u | Follow page wording: UX lens picks between the page's text and `maintain.FollowPrompt`/`FollowCheckHeading`, and the page names the current source (L3 R3 on #370) | OSS-10w2 | queued (needs brief) |
| IMG-1 | [Image checks for P2-1](briefs/IMG-1.md) | P2-1 (#41, draft since 01:07Z) | queued (blocked on P2-1) |
| SR2-1 | [Approval texts show only canonical recipients](briefs/SR2-1.md) | — | merged (#144) |
| P2-2a | [Local-page approvals](briefs/P2-2a.md) | P2-2 | merged (6239bd4; #178 part 2) |
| P2-2w | [Local UI process and owner socket](briefs/P2-2w.md) | P2-2a | building (in sub-rows a, b, d, c (P3-2 thread)) |
| P2-2a f1 | [Page result after a changed item](briefs/P2-2a-f1.md) | P2-2a | merged (#329) |
| P2-2a f2 | [Page result for a changed release adoption](briefs/P2-2a-f2.md) | P2-2a f1 | in review (#363) |
| P2-2a f3 | [Re-offer an awaiting-owner release the pipeline dropped](briefs/P2-2a-f3.md) | P2-2a f2 | queued (after #363; release finding from L3 on #363) |
| P2-2w a | [`localui.sock` in agentosd](briefs/P2-2w-a.md) | P2-2a | merged (b00db30; #184) |
| P2-2w b | [`agentos-localui` command under its own uid](briefs/P2-2w-b.md) | P2-2w a | merged (0302131; #189) |
| P2-2w d | [LocalUI on (part 1)](briefs/P2-2w-d.md) | P2-2w b | merged (#322; split 2026-10-08; part 2 is d2) |
| P2-2w d2 | [Home page shows `Link.OwnerLineNote` and `Link.LastOutage`](briefs/P2-2w-d2.md) | P2-2w d | building (split into d2a, d2b) |
| P2-2w d2a | [Home page shows the owner line's note, last outage and counts](briefs/P2-2w-d2a.md) | P2-2w d | in review (#378) |
| P2-2w d2b | [Page control to confirm a SIM swap and set up the owner number](briefs/P2-2w-d2b.md) | P2-2w d2a | queued (A) |
| P2-2w c | [Setup moves into agentosd](briefs/P2-2w-c.md) | P2-2w b | building (split into c1-c3, each under one session) |
| P2-2w c1 | [Code seed made in the vault process and handed out once](briefs/P2-2w-c1.md) | P2-2w b | merged (#320) |
| P2-2w c2 | [Pairing and finish in agentosd](briefs/P2-2w-c2.md) | P2-2w c1 | in review |
| P2-2w c3 | [`agentos-netjoin`](briefs/P2-2w-c3.md) | P2-2w c2 | queued |
| P2-2w c4 | Setup's remaining hooks in agentosd (networks, box number, host trust, texts, providers, real progress) and `agentos-localui` given `AgentosdSetup` (release finding on P2-2w c2; localui L28) | P2-2w c2 | queued |
| P2-2w c2 r1 | Setup on a vault whose enrollment is closed: the vault answers "never opened" apart from "sealed", and the page says the box cannot finish setup instead of "already set up" with a Continue that finish refuses (release finding, L3 on #367; localui L28). Also: if the seal succeeds but the setup record is lost and the owner resets setup before retrying, every finish is refused; the vault answering "sealed by setup" apart from "never opened" lets agentosd accept the former at finish (release, L3 re-review on #367) | P2-2w c2 | queued |
| SR2-2 | [Restore refuses symlink chains that escape the root](briefs/SR2-2.md) | — | merged (#151) |
| SR2-3 | [Disk quotas for machines and an enforced reserve](briefs/SR2-3.md) | #143 (RES-4 text) | merged (a10b5fe) |
| SR2-3i | [Image side of SR2-3](briefs/SR2-3i.md) | SR2-3, P2-1 | merged (d40fb31; #174) |
| SR2-3s | [Step snapshots that fail are not silent](briefs/SR2-3s.md) | SR2-3i | merged (847ea23; #179) |
| SR2-3d | [A too-deep worker can be flattened](briefs/SR2-3d.md) | SR2-3i, CAP-8c | merged (d40fb31; #174) |
| SR2-3f | [Worker tools answer no raw vm error](briefs/SR2-3f.md) | CAP-8c | merged (f19f97c; #181, commit fcdce51) |
| SR2-3g | [Agent-visible tool errors name no host path](briefs/SR2-3g.md) | RES-4, CAP-8 | merged (#324; recall thread) |
| SR2-3h | [runsc's own messages never reach the guest](briefs/SR2-3h.md) | RES-4, CAP-8 | merged (#362) |
| SR2-3j | [Effect denial reasons reach the guest only as fixed text](briefs/SR2-3j.md) | SR2-3g | building (recall thread) |
| SR2-3m | [A runsc panic after the guest starts reaches no guest output](briefs/SR2-3m.md) | RES-4, CAP-8, SR2-3h | building (release finding 362-1, Security on #362) |
| SR2-3k | [guesterr.Guest values checked at run time](briefs/SR2-3k.md) | SR2-3g | building (recall thread) |
| SR2-3n | [No runsc crash trace reaches the guest, and the guest cannot pick the logged part](briefs/SR2-3n.md) | SR2-3m | queued (release findings S2, S3, S4, Security on #391) |
| SR2-3o | [Malformed-request refusals keep a field-level hint for the guest](briefs/SR2-3o.md) | SR2-3j | queued (release item 2, lens on #396) |
| SR2-3p | [A command that cannot start is not told to retry](briefs/SR2-3p.md) | SR2-3j | queued (release item 3, lens on #396) |
| SR2-3q | [A runsc failure after the command may have started is not told it did not start](briefs/SR2-3q.md) | SR2-3j | queued (release, Security on #396 delta) |
| SR2-4 | [cgroup cpu, io and pids controllers](briefs/SR2-4.md) | #143 (RES-2 text) | merged (#155) |
| SR2-4i | [Host side of SR2-4](briefs/SR2-4i.md) | SR2-4 merged; host image | queued (blocked on the host image) |
| SR2-5 | [Second-line sends](briefs/SR2-5.md) | #143 (ADP-12 text) | merged (2e85d06) |
| SR2-7 | [Per-sender cap on the multi-part text buffer](briefs/SR2-7.md) | — | merged (5cddc94) |
| SR2-8 | [METRICS.md counts only collaborators](briefs/SR2-8.md) | — | merged (64220e9; #162) |
| SR2-9 | [ci.yml pins actions by SHA](briefs/SR2-9.md) | — | merged (64220e9; #162) |
| CH-21 | [Name and first-person voice](briefs/CH-21.md) | CH-12 strings; P2-3 | queued (split into CH-21a to CH-21e) |
| CH-21a | [First-person voice: lint test and tier-B sweep](briefs/CH-21a.md) | CH-12s | building (primary lane) |
| CH-21b | [Box name: setup suggestion and `NAME`](briefs/CH-21b.md) | CH-21a | queued (tier A) |
| CH-21c | [First-person voice: owner-page and recovery texts](briefs/CH-21c.md) | CH-21a | queued (tier A) |
| CH-21d | [First-person voice: daemon and egress texts](briefs/CH-21d.md) | CH-21a | queued (tier A) |
| CH-21e | [Agent text asking for a code is withheld; welcome-text code line](briefs/CH-21e.md) | CH-21b | queued (tier A; security first) |
| CH-12s | ["Local page" rename in owner texts](briefs/CH-12s.md) | CH-12 | merged (a390f03; #185) |
| ADP-13 | [The box's own mailbox](briefs/ADP-13.md) | CRED-4b; P2-6m; CH-21 | queued |
| HOST-1 | [Spec: the host PC is left as it was](briefs/HOST-1.md) | — | merged (fa52b76) |
| HOST-1a | [No host disk is mounted or used](briefs/HOST-1a.md) | P2-1 image | queued (part 2; part 1 merged (#172); part 2 queued on P2-1) |
| HOST-1b | [No hardware-clock writes](briefs/HOST-1b.md) | P2-1 image | queued (part 2; part 1 merged (#177); part 2 queued on P2-2w (R1 needs the live page)) |
| HOST-1c | [Firmware-change disclosure and BitLocker prevention](briefs/HOST-1c.md) | HOST-1a, P2-2 | queued (part 2; part 1 merged (#183); part 2 queued (needs P2-2)) |
| HOST-1d | [Internal-disk opt-in](briefs/HOST-1d.md) | HOST-1a, P2-2, P2-4 | queued |
| HOST-1e | [Host-untouched acceptance check](briefs/HOST-1e.md) | HOST-1a, HOST-1b | merged (part 1, #326); part 2 (HOST-1e2) queued on P2-1 |
| HOST-1f | [Give the TPM's dictionary-attack settings back as they were](briefs/HOST-1f.md) | P2-4b (tpmseal, boot PIN #42) | merged (de01c80; #188) |
| CI-SOAK | [Unattended soak workflow](briefs/CI-SOAK.md) | — | merged (8bab3fe; #187) |
| OSS-10w2 r1 | Follow names: the reserved-name check (`grants.followName`, localui `askFollow`) also refuses look-alikes of "the AgentOS project" (folded as `owner.fold` does for CH-10, or a confusable skeleton), so a named follow never reads as switching back (release, security lens 370-1 on #370; supersedes LATER OSS-10w2 f4) | OSS-10w2 | queued (needs brief) (A) |

## Integration: wiring merged packages into the box

Built packages reach the running box through small wiring PRs, in this order. A row whose precondition is unmet is not wired.

| ID | Wiring | Precondition | Owner | State |
|---|---|---|---|---|
| W1 | [Agent machine kept running by `agentosd`](briefs/W1.md) | — | this package (`pkg/wire-agentosd`) | merged (#56, #60, #62) |
| W2 | [Recall as a broker tool on the guest socket, `vm.Manager` labeler,…](briefs/W2.md) | P3-3b segmented store | recall thread (P3-3b) | merged (recalltool wired into agentosd by P3-3b: #152, #174, #181) |
| W3a | [Evaluation route](briefs/W3a.md) | W1 | this thread | merged (#62) |
| PE1 | [Resume a preempted evaluation from completed probe pairs](briefs/PE1.md) | W3 | Next build item D | merged (#103) |
| PE2 | [Set the replay machine's `MemMB` deliberately](briefs/PE2.md) | W3, S1 | Next build item D | merged (#114) |
| PE3 | [Replay machine admission refusal interrupts, not fails](briefs/PE3.md) | PE1 | Next build item D | building |
| PE4 | [Preempted Loop 2 fix proposal](briefs/PE4.md) | PE1, P3-4 | Next build item A | merged (#112) |
| PE5 | [Count only real interruptions toward MaxInterruptions](briefs/PE5.md) | PE3 | Next build item B | merged (04be62e; #127) |
| PE5b | [Bound owner-exempt cuts per candidate](briefs/PE5b.md) | PE5 | Next build item B | merged (273b2c5; #145) |
| PE6 | [Default -capacity-mb](briefs/PE6.md) | PE2 | Next build item D | merged (#118) |
| PE7 | [Degraded mode: evaluate only while idle](briefs/PE7.md) | PE2, PE5, PE5b | Next build item B | merged (135c0c0; #153 part 3) |
| PE7-bus | [PE7 condition 4, bound to the package that wires the events bus to…](briefs/PE7-bus.md) | PE7, events bus wiring |  | queued (waits on the events-bus package) |
| PE7-call | [PE7 condition 5, bound to the package that answers inbound calls](briefs/PE7-call.md) | PE7, inbound calls |  | queued (waits on the inbound-call package) |
| W3 | [Learning process](briefs/W3.md) | W3a, W3-goal | loops thread (P3-2) | building (step 1 merged (#83: `routerule` split, import-graph test…) |
| W3-goal | [Goal-ID plane](briefs/W3-goal.md) | #55 merged | goal-ID thread (P3-7) | merged (#55) |
| W4 | [Managed tree to the live agent machine](briefs/W4.md) | W3, P3-6 merged | Next build item A | merged (68948e90) |
| W3-off | [Say when the learning plane could not start](briefs/W3-off.md) | W3 | Next build item B | merged (#99) |
| W3-off-a | [Learning plane can start late](briefs/W3-off-a.md) | W3-off, PW6 | — | queued |
| W3-route | [Tell the owner when a learned route is refused](briefs/W3-route.md) | W3 PW4 | Next build item A | merged (#108) |
| W3-route-a | [Project the owner's -rule refusal](briefs/W3-route-a.md) | W3-route | Next build item A | merged (#110) |
| W3-values | [W3 step 3b: keep non-secret param values](briefs/W3-values.md) | W3 step 3a | loops thread (P3-2) | merged (commits on main, #119) |
| W3-values-mix | [HMAC explicit runs in mixed shapes](briefs/W3-values-mix.md) | W3-values, after W4 | loops thread (P3-2) | merged (d9683787) |
| W3-builder | [W3 step 3c: model-backed Loop 1 builder](briefs/W3-builder.md) | W3 step 3a | loops thread (P3-2) | merged (#126) |
| W3-builder-image | [The minimal builder image for W3-builder](briefs/W3-builder-image.md) | W3-builder | loops thread (P3-2) | merged (4b0d00e) |
| W3-builder-tune | [Builder per-job counters (#126)](briefs/W3-builder-tune.md) | W3-builder-image | loops thread (P3-2) | merged (61cfd90) |
| W3-builder-ship | [Ship the builder so owners never see the repeats-only line](briefs/W3-builder-ship.md) | W3-builder-image, P2-1 | this package (P3-2) | queued (agentosd side merged, bb7c40d in #154; the P2-1 side waits on P2-1) |
| W3-tasks | [Learn-side forget primitive](briefs/W3-tasks.md) | W3 PW3 | Next build item B | merged (538d180; #160 part 2; wiring waits for forget action) |
| W3-forget | [Owner-facing forget command](briefs/W3-forget.md) | W3-tasks part 2, W5 | Next build item B | building (split into sub-rows) |
| W3-forget-a | [FORGET by text in an unlocked session](briefs/W3-forget-a.md) | W3-forget | Next build item B | merged (05913d0; #182) |
| W3-forget-b | [Authenticated forget log replayed over backups](briefs/W3-forget-b.md) | W3-forget-a | Next build item B | building (split into sub-rows) |
| W3-forget-b1 | [Authenticated forget log checked on restore](briefs/W3-forget-b1.md) | W3-forget-a | Next build item B | merged (01c8515; #409; items 1–3 ruled by Mark on #317, 2026-10-08) |
| W3-forget-b1-4 | [Owner confirms a restore with no anchor](briefs/W3-forget-b1-4.md) | W3-forget-b1, D-065 (#406) | Next build item B | queued, ruled (D-071), ready to build (stale-backup option ruled, D-065; must land before A8/G3) |
| W3-forget-b1-5 | Vault serves AppendForget/ExportForgetLog and agentosd wires its forgetLog after the restore check is wired; forgetLog stays nil until then (#409 R1; brief to write) | W3-forget-b1, W3-forget-b1-6 | Next build item B | queued (needs brief) |
| W3-forget-b1-6 | Wire the restore command: ForgetLogs from every destination, the PC's Counter, Layout.ForgetLog always set, and Box.Counter set by the vault process (#409; brief to write). Release conditions from #409 Security R5 and L3, each with a test: (a) Layout.ForgetLog and the marker path are `<learn dir>/forget-log.json`, matching agentosd's restoreHold; (b) agentosd is stopped before the restore; (c) a start without the marker cross-checks State.Pending; (d) decide whether a failed TPM anchor (Define/Read at storeBackupKey) fails storing the recovery key or falls back to anchoring at the first forget. A held restore must not be silent toward the owner (UX), hence b1-7. Also (#409, release): Security R2, a corrupted destination copy must not make the restore `forged` when a good copy exists (proposal: use the copy's verified prefix); Security R3, cap `decodeForgetLog` and each `Options.ForgetLogs` copy (for example 4 MiB) at decode and in the restore command's reader | W3-forget-b1, W3-forget-b1-7 | Next build item B | queued (needs brief) |
| W3-forget-b1-7 | Text the owner the held restore's PendingNotice (CH-12) from the marker agentosd refuses to start on (#409 U2; brief to write). Also (#409 UX U6, release): add the CH-12 recurring-kind check ("a step that cannot work") for owner texts, per reviews/ux/README.md | W3-forget-b1, W3-forget-b1-4 | Next build item B | queued (needs brief) |
| W3-forget-b2 | [Builder-lineage rollback with A/B](briefs/W3-forget-b2.md) | W3-forget-a | Next build item B | merged (#321) |
| W3-forget-b2b | [Agent machine's work taken back as item 2](briefs/W3-forget-b2b.md) | W3-forget-b2 | Next build item B | merged (#327) |
| W3-forget-b3 | [Promised done text survives a restart](briefs/W3-forget-b3.md) | W3-forget-b1 | Next build item B | queued |
| W3-forget-b2c | [Owed take-backs for W3-forget-b2b](briefs/W3-forget-b2c.md) | W3-forget-b2b | Next build item B | queued |
| W3-implicit | [Report accepted-implicitly guest effects](briefs/W3-implicit.md) | W3 PW3 | — | queued |
| W5 | [Owner channel](briefs/W5.md) | W3 | loops thread | queued |
| W5a | [Loop 2 passive checks](briefs/W5a.md) | #54 merged, W3 | builder B (lenses) | merged (3d2daab; #169) |
| W5a-resume | [Per-grant resume on the local page](briefs/W5a-resume.md) | W5a, local page | builder (session_014jQE43g7uFA46BsQJD3VGh) | in review (tier A) |
| W5b | [Loop 3 update checks](briefs/W5b.md) | #53 merged, W3, network state (P2-3 modem or Wi-Fi) | Loop 3 thread (P3-5) | queued |
| W5c | [Clean-room builder](briefs/W5c.md) | #43 merged, W3 | clean-room thread (P4-2) | queued |
| W6 | [Recovery into the vault process and local UI](briefs/W6.md) | `vault.Reencrypt` (#45, P2-4d) merged and used by rotation | recovery thread (P2-8), after #64 | queued |
| W7 | [Compiled skills in live use](briefs/W7.md) | `suite.go` split, #52 merged | compiled-skills thread | queued (blocked) |
| W8 | [Owner builds](briefs/W8.md) | P2-4f | — | queued (blocked) |
| W9 | [Questions in the guest plane](briefs/W9.md) | P3-8 merged, #68 merged | — | merged (f38aeed8) |
| W9a | [Questions follow-ups (#95)](briefs/W9a.md) | W9 | Next build item A (part 2) | merged (#125 (part 2; part 1 #98)) |
| CH-20w | [Evidence delivery](briefs/CH-20w.md) | CH-20 merged; P2-6m wired into the vault process | — | queued (blocked on mail wiring) |
