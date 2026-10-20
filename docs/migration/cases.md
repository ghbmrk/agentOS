# Migration cases: what the old core proved, kept for the capability kernel

Mark chose to rebuild the trusted core around signed, narrowable capability keys, one holder (the clerk) as the only exit, and one append-only log ("Do it", cmsg_01R63S2yrPkq32thy8WQCuvDDKzJjXejfaM6St46V4sDg2, 2026-10-20 02:45Z; [D-139](../../decisions/D-139.md)). The old-core work below stops. What it learned survives here as cases: each line is a behaviour the new system must keep or a failure it must prevent, with its source and requirement IDs. The spec step maps each case to the key, the clerk or the log; the kernel and slice steps turn them into tests. A case is dropped only by a spec PR that says why.

Old core means the broker packages journal, grants, vault, recall, recalltool, egress, holder, checker, projection, replay, durable and sim, plus their wiring in `broker/cmd/agentosd`. A requirement shown as "none named" has no SPEC ID in its source; the spec step assigns one.

## 1. Open pull requests

| Source | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #2513 JRN-startup-reconcile-s3 (head 1cee73ef) | Boot order is fixed: with recall off, `Off, wired(false), boot`; with recall on, `boot, OnOpen, open`. Nothing runs at wire time | OP-4, CAP-3 |
| #2513 | The open step gets the wiring's context, verifier and executor, not fresh ones | OP-4 |
| #2513 | A wiring that leaves recall off sets the STATUS off line | CH-12 |
| #2513 | Forget resume is reached only through one resume entry, and finishes only after the daemon, the listener and the agent store are up | CAP-3, OP-4 |
| #2519 CRED-5f-mr-addkey (head 0bfeaaa6) | A provider key can be added after setup, from the local page, with the one-time code; a request without the code never reaches the provider | CRED-1, CRED-5, ONB-3 |
| #2519 | The provider checks the key before the code is spent, so a refused key burns no code | ONB-3, CH-10 |
| #2519 | The key is never in the page, a log, a redirect or the daemon's disk; only the holder stores it | CRED-1, CRED-5 |
| #2519 | The no-key line names a step the owner can take ("add a key on my Wi-Fi page") | OP-9 |
| #2499 SEC-backs-append-latch, #2500 | A store that latched after a failed write must not deliver a trigger-matched event and then error, so a retry redelivers it | CAP-3, RES-4 |
| #2499, #2500 | A latched log must not drop delivery records, so events re-run without backoff or the attempt limit | CAP-3, RES-4 |

## 2. Deterministic simulation oracles (SIM-sim part 1, branch pkg/sim-sim-bwcvu2 at 6cf8b16)

The kernel is a pure function of its log, so these oracles run against the kernel from its first commit.

| Oracle | Behaviour | Requirements |
|---|---|---|
| Acknowledged writes survive | Every append the disk acknowledged is in the reopened log and readable; a torn prefix is never acknowledged (mutant: a short write acked) | OP-4 |
| A failed write halts | After a failed write or fsync the engine is broken or stopped until reopened, never running on, and writes nothing before the reopen | OP-4 |
| RESUME needs a fresh code | A RESUME lifts STOP only with a code texted after the latest STOP and the latest boot (mutant: an older RESUME code lifts STOP) | CH-2 |
| Stopped holds | "Stopped." told to the owner holds across a restart | CH-2, OP-4 |
| Fault model | A fake disk injects write and fsync failures and crashes that drop the page cache; the judge runs after every boot and at the end; seeds are replayable (seed 101 found the STOP defect fixed in #2521). Owner numbers come from the fictional 555-01xx range | OP-4 |

## 3. STOP orderings (#2521, merged)

| Ordering | Behaviour | State |
|---|---|---|
| A | STOP recorded, RESUME's fsync fails, then STOP: the reply is "STOP failed to record", never "Stopped." | fixed on main |
| B | No STOP in force and the STOP's fsync fails: the reply is "STOP failed", and if the record replays the engine comes up stopped (errs safe) | fixed on main |
| C | STOP recorded, RESUME's fsync fails, restart: the failed RESUME replays and the engine comes up resumed although the owner was told "Still stopped." Root cause: a write that failed can still replay. The kernel log must make a failed append either never replay or be reported as done | open; kernel log (OP-4, CH-12) |
| D | The STOP record is durable and a later cancel commit fails: the reply is "STOP failed to record", a safe false negative | fixed on main |
| Wording | The failed-STOP text asks the owner to "reply or press STOP again", which cannot work while the engine is broken; the kernel's text must name a step that works | open (CH-12) |

Requirement: CH-2. Tests on main: `TestSTOPThatFailsToRecordIsNotReportedDoneWhenAlreadyStopped`, `TestLocalStopThatFailsToRecordIsAnErrorWhenAlreadyStopped`.

## 4. W5-D crash, acknowledgement and forget cases

[briefs/SIM-cases.md](../../briefs/SIM-cases.md) lists the W5-D drafts' cases (draft, case, what the owner sees, where). They carry over unchanged as cases for the kernel and the first slice.

## 5. Queued rows with a brief

| Source | Behaviour | Requirements |
|---|---|---|
| GR-reissue-deadline ([brief](../../briefs/GR-reissue-deadline.md); its issue is closed) | A request re-issued after a restart keeps its original absolute deadline; a YES after the deadline is an expired decision; a passed deadline is refused with nothing opened, not renewed; a text send that outlasts the deadline closes the page request as expired | CH-10, OP-4 |
| EGRESS-rule-1 (#1321) | The route check reads the router's own rule, not a copy, so the check and the route cannot disagree | see section 6 |

## 6. Harvested issues

Each issue below is closed as superseded once this file merges. Its text stays readable on GitHub through the link.

### Journal, replay and startup reconcile

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #2507 JRN-startup-reconcile-s3 later | Go/types identity check for recall OnOpen wiring | none named |
| #1414 JRN-startup-reconcile l3 | Single executor list, follow re-key residual and STATUS wording (L2, L3, U4, U5, U6 on #1382) | CH-12, OP-2, OP-4 |
| #1410 JRN-startup-reconcile s3 | Pin where agentosd runs the FORGET boot resume and what it passes into wireResume | CAP-3 |
| #1375 JRN-startup-reconcile l2 | A18 says every Reconcile only reads state, but forget and follow do more | OP-4 |
| #1374 JRN-startup-reconcile l1 | Pin SettleUnknown's pacing and lifetime (5 min cap, doubling, round bound, daemon ctx) | OP-4 |
| #1446 REPLAY-journal-snapshot | Baseline and candidate replay read the journal separately; snapshot it with a digest in resumeKey once a failing path is shown | none named |
| #1949 journal | A cancel committed after an erase keeps its detail | OP-2 |
| #1948 journal | Erase keeps the quality note | CAP-3 |
| #1956 SM-JL follow-ups | Restrict the `journal` manifest kind; UndoPlan and later effects | DEV-5, OP-11 |
| #1955 SM-JL follow-up | UNDO can restore a redacted prior state | DEV-5 |
| #1942 SM-journal-lifecycles | New lifecycles are journal intent kinds; a guard fails packages that keep their own store (release; tier A; from state-machine audit R4) | CRED-11, DEV-5, OP-11 |
| #1930 UPD-applier-journal | Move the applier decision points onto the journal (later; tier A; from state-machine audit R6) | none named |
| #1929 CHG-adoption-journal | Move the adoption lifecycle onto the journal; add the OP-7 quality-revision trigger (release; tier A; from state-machine audit R6) | OP-11, OP-7 |
| #1963 CHG-adoption-journal-later | Residue from SM-adoption-journal-a (later) | none named |
| #1967 SM-adoption-journal-a follow-up (later) | C36 narrowing wording; replay confirm guard untested | none named |
| #1976 SM-adoption-journal-b follow-up (later) | Retry gate, skipped recheck, mutant coverage, revert wording | none named |
| #1975 SM-AQ later findings | Quality trigger retry gate, mutants, revert attribution (from PR #1974 reviews) | OP-7 |
| #1996 CHG-forget-revert-journal residue | Owed-revert edge cases (later) | none named |
| #2000 CHG-proposal-delete-edges | Replay skips the proposal delete on a journal Get error; forget skips stray retry when broken (later) | none named |
| #2013 CHG-legacy-revert-journal follow-ups | Crash-window test, conflicting revert reasons (later) | none named |
| #2099 CHG-adoption-body-seal | A forged Goals list in an adoption body makes ForgetGoal skip it (release) | CAP-3 |
| #1876 CAP-11-plan-fu1 | OP-8 Journal wiring for provider runs | CAP-11, OP-8 |
| #2306 CH-photo-e | Admit the photo store's journal intents in the daemon's grants gate | CH-26 |
| #1149 CAP-15 l1 | Quote and length-cap target-controlled destinations in refused-connection journal entries | CAP-15 |
| #1947 OP-11 debt | Broker stores the 2026-10-16 audit did not cover | CAP-10, OP-11 |
| #1933 APPROVAL-tla-model | One TLA+ model of approval expiry × gate freshness × intent state × restart (later; tier C; from state-machine audit R8) | none named |

### Forget and deletion

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #2509 CAP3-held-forget-task | A forget drops only the deleted task's held agent texts (CAP3-F2) | none named |
| #2391 CAP3-held-forget-scope | A forget drops held agent texts from unrelated tasks without telling the owner; key held texts by task, count the drop meanwhile; O44 wording for a leading ellipsis (release; tier A) | none named |
| #2436 W3-forget-reach r2/r4 later notes | Multi-name STATUS grammar; restart loses approval for hook-unset TakenBack | CH-12 |
| #2020 FORGET-FOLDS follow-up | A result folded between the reset notice and the restart survives the forget | CAP-3 |
| #2107 DEL-1-f2 | A deletion with no outbox attached, and unkeyed hashes in the outbox's done list | CAP-3 |
| #2079 DEL-1-f1-l2 | A deletion drops every waiting reply, not only its subject's | CAP-3 |
| #2078 DEL-1-f1-l1 | Guest outbox `done` keeps an unkeyed hash of a deleted reply | CAP-3 |
| #1569 RECOVERY-one-putmany | Seal the recovery factor and forget-log with one PutMany instead of three seals and advances (later) | none named |

### Recall and events stores

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #2500 SEC-events-latch-retry | Latched events stores redeliver on retry and drop backoff | CAP-3, RES-4 |
| #2474 SEC-recall-open-torn-cut | Recall.OpenFile does not cut a torn tail | none named |
| #2473 SEC-backs-latch-clear | A latched back-marks file stays latched until restart | CAP-3 |
| #2461 SEC-backs-append-latch | A failed recall append must not swallow the next back mark | CAP-3 |
| #2358 RECALL-entropy-order | Entropy() sums in map-iteration order, so a token exactly at the 3.0/3.5 threshold is scrubbed on some runs and kept on others (later; tier A) | CRED-1 |
| #2227 RECALL-canary-3 residuals | Shapes still kept, over-removals, neutral marker | CRED-1 |
| #1675 RECALL-unlink-dirsync | Retry a failed directory sync on the empty-segment unlink path | CAP-3 |
| #1239 RECALL-scrub-read | Recall scrub is write-only; old records stay unscrubbed | none named |
| #1171 RECALL renew | Test the !first.Equal(since) guard term and the duplicate-YES owner text | none named |
| #1167 RECALL-renew-done | Tell the owner when a carried renewal finishes | CAP-3 |
| #1653 RECALL-canary-5-doc | OPERATING §3's tier-A row names recall and events (CRED-1 custody) | CRED-1 |

### Vault and key custody

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #2018 VAULT-RETRUST-pin | An interrupted re-trust that changed the TPM PIN needs the passphrase | none named |
| #1847 VAULT-RETRUST | Interrupted same-host slot replacement breaks unattended restart | CRED-8 |
| #1820 VAULT-reencrypt-decided | Tell step 1 from step 3 when vault.Reencrypt returns ErrSlotDecided | CRED-9, REC-4 |
| #1782 VAULT-REDACT-fu | JWT parts echoed without dots, and the *_id identifier rule | CRED-1 |
| #1742 VAULT-slot-decided-3 | Egress test proves trust by reopening through the TPM slot; rotate.go sets the decided value twice (later; PR #1734 P/UX/L3 6 and 8) | none named |
| #1547 VAULT-dirsync-refusal-message | A save refused by a failed directory sync before the counter catch-up reads to the owner as a refused credential (later; from #1527 delta N1) | OP-4 |
| #1541 VAULT-dirsync-notice | The warning for a landed but unsynced vault write reaches only the log and does not name the change (later; from #1527 U1) | CRED-8, OP-4 |
| #1473 VAULT-putmany-later | PutMany with no items should not write or advance the counter; the rotation sweep should fail after the write; the 410 text should say a save failed | CRED-7, REC-4 |
| #1252 P2-2w c4d s3 | Host trust changes race a card provision: check the vault generation around the slot write | none named |
| #1207 Setup vault notes and lock during setup  | Setup vault notes and lock during setup (#1203 L5, L6) | CH-12 |
| #1206 Setup vault opening | Stop-between-renames test, failed keys rename, leftover .card, remanence (#1203 L1 to L4) | none named |
| #1201 Owner wording for the card vault ops' re | Owner wording for the card vault ops' refusals | CH-21 |
| #1200 Card vault reset leaves a .card temporar | Card vault reset leaves a .card temporary after a crash and an open; K21 residuals | none named |
| #2041 Failed trust | "nothing was changed" overstates when vault entries stay | none named |
| #2303 CAP-11-plan-fu4 follow-up | Wire declared credential formats into the vault process redactor | CAP-11, CRED-7 |
| #1278 CRED-5f-mr-addkey | Serve a provider add-key step past setup | CRED-5, ONB-3, OP-9 |
| #1279 CRED-5f-mr-derived | Builder and replay grants follow stored keys | CRED-5 |
| #1310 CRED-5f-mr-grant l1 | Pin #1280's surviving mutant: wireModel without its checkAgentMachine call stays green | CRED-5 |
| #1401 CAP-11-broker-held-hardening | Per-worker placeholders required, placeholder scan, and a label-laundering control for broker-held plan routes (later; CRED-5, CRED-7, CAP-11) | CAP-11, CRED-5, CRED-7 |

### Egress proxy and plan route

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #1321 EGRESS-rule-1 | EvalRoute reads the router's rule | none named |
| #1611 P2-2w-c4e3-s1-proxy | Pin that egress.DefaultTransport takes no proxy from the environment (DEV-2) | CRED-1, DEV-2 |
| #2112 Egress ASSUMPTIONS W1 | Describe the plan route's declared tool list | none named |
| #1874 egress ASSUMPTIONS | Update K27 once #1588 merges | none named |
| #1873 egress | Test that a refresh without its own placeholder is refused before joining a flight | none named |
| #1872 egress | Overlapping refreshes keep one flight open (CRED-5t liveness) | none named |
| #1871 egress | A panic in the refresh leader pins its flight until restart | none named |
| #1763 S8-W1-tunnel-fu | Correct W5's PKCE claim; stop the plan route on a refused refresh (release; CRED-5, CRED-5t, E11, ONB-9) | CRED-5, ONB-9 |
| #1756 Plan worker route | Field-aware placeholder resolve and measured header and refresh-field lists (release; CRED-5, CRED-1) | CRED-1, CRED-5 |
| #2479 ARC-6(d) egress must deny CLI guests' pr | ARC-6(d) egress must deny CLI guests' provider cloud hosts | ARC-6 |

### Holders, keeper and checker (credential split)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #2515 SIM-split-wire | Later items from #2514 review | ADP-9 |
| #2506 SIM-split-wire part 4 follow-ups | Grid cell on act items, act bound, untested refusals | CH-10, CH-4 |
| #2502 SIM-split-wire part 3 follow-ups | Wiring mutants, flag pairing, same-step enrol wording, fixed clocks | none named |
| #2498 SIM-split-wire | Enrolment confirms the pending seed in the vault process, not the checker | none named |
| #2496 SIM-split-wire | Approvals held past the checker's 15-minute TTL are refused at the holder | none named |
| #2455 SIM-split-wire | Cache the per-request hash redactor | none named |
| #2454 SIM-split-wire | Keeper checks the holder socket's uid | none named |
| #2322 CRED-route-stop-mutants | Tests that kill the surviving route-stop mutants M5, M9, M10, M11 | none named |
| #2016 CRED-route-stop-followup | Release findings from PR #2015's reviews | CRED-5, OP-11 |
| #2014 CRED-route-stop-persist follow-up | Wire the egress proxy's stops to the journal and give Requalify a caller | none named |
| #2009 CRED-holder-revoke | Holder and keeper never re-hand a refused login (split from #2001, waits on G1) | CRED-5 |
| #2004 CRED-signin-guard later | In-flight requests and untested keeper record paths (from #2001) | CRED-5 |
| #2003 CRED-signin-guard follow-up | Refused-login revocation gaps (release findings from #2001) | CH-11, CRED-5 |
| #1926 CRED-route-stop-persist | Persist or journal route stops across restart (release; tier A; from state-machine audit R2d) | OP-11 |
| #1925 CRED-signin-guard | `Runner.SignedIn` needs `SignInStored`; `Hand` refuses a revoked account (release; tier A; from state-machine audit R2c) | CRED-1, CRED-5 |
| #1635 SIM-check l8 | "could not run" STATUS note carries the read error text | none named |
| #1634 SIM-check l7 | Checker claims independence but OP-3 calls journal.Narrowing | OP-3 |
| #1633 SIM-check l6 (recheck at SIM-cap) | OP-3 revocation check is idle in production | OP-3 |
| #1232 SIM-core-allow-tier follow-ups (later) | Indirect write paths through an allowed package; parser fixture; duplicate tier A listing | ARC-1 |

### Mail through the vault (SR3-mail)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #2490 SR3-mail-k18g later | Review follow-ups from #2482 | none named |
| #2484 SR3-mail-k18g later | Reuse egress.WithWriteDeadline in workerroute.go | none named |
| #2315 SR3-mail-k18f follow-up | Check request bodies by streaming tokens, not a map[string]any tree | CRED-8 |
| #2296 SR3-mail-k18g | Egress proxy body check memory and slot fairness (release findings from #2294) | CRED-8 |
| #1256 SR3-mail-k18d | Later points from PR #1245's reviews: vendor/third_party drift check, third_party tier, fuzz registries, malformed-reply status (later, recheck) | none named |
| #1244 SR3-mail-k18 later | A panic in go-imap's greeting leaves that IMAP connection open | none named |

### Updates and approvals (SR3, W5-Dc)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #2310 SR3-6-f6-later | Pin retireClaims' held-copy race guard with a test | CH-12, UPD-8 |
| #2104 SR3-6-f5c brief and issue #783 still quo | SR3-6-f5c brief and issue #783 still quote the third-person notice text | CH-21 |
| #2094 SR3-4f-r1-f1-f1 | Make activatortest's wholeness and default fit a real P2-1 adapter | UPD-1, UPD-1a |
| #1657 SR3-4f-r1-f2 l1 | Previous-version line keyed on inequality; Booted under the applier lock; untested in-flight guards (later) | CH-12, UPD-1 |
| #2068 W5-Dc-r23 fu | GR37 wording implies a request text for held install intents | none named |
| #2211 W5-Dc-r23-f1 follow-up | Annotate's doc comment sits on HeldInstallNotice; recheck whether the no-action notice belongs in STATUS only (later, L3 on PR #2210) | CH-15 |
| #2271 W5-Dc-r16 | Urgent approval texts skip coalescing (one text per gate tick) | CH-10, CH-15 |
| #2442 W5-Dc-r16 later | Held marker shows only HH:MM for holds over a day | none named |
| #2451 W5-Dc-r16 follow-up | Held-marker nits (zero At guard test; 13-byte pack window) | none named |

### Simplification rows superseded with D-095 (SIM-*)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #761 SIM-sd | L1 spec diff: one log, owner messages as intents, one outcome, learning off until it wins | none named |
| #1107 SIM-outer | L1 spec diff: narrow provider scopes, provider limits at ~2x the box cap | none named |
| #762 SIM-check | One journal invariant checker: test, CI and runtime | none named |
| #763 SIM-proj | Journal snapshots and a projection API | none named |
| #764 SIM-owner-hold | Owner texts are intents; the pacer hold becomes a projection | none named |
| #765 SIM-pull | STATUS is the owner's view; only urgent texts pushed; digest deleted | none named |
| #766 SIM-cases | W5-D drafts' crash, ack and forget cases become tests against main; list | none named |
| #767 SIM-outcome | One revisable outcome record per goal | none named |
| #768 SIM-erase | Forget once, in the journal | none named |
| #770 SIM-shred | Forget by deleting a per-subject key; reaches backups and snapshots | none named |
| #771 SIM-policy | Policy as data with one match-and-compare evaluator | none named |
| #772 SIM-cap | Capability grants scoped per intent | none named |
| #773 SIM-sim | Deterministic simulation of the broker, judged by SIM-check | none named |

### Credential split rows (SIM-split)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #1102 SIM-split-refresh | Refreshed tokens persist through the unlock step | none named |
| #1103 SIM-split-wire | Production wiring: custody leaves egress, a Keeper per holder, the checker holds the seed | none named |
| #1104 SIM-split-msg | Mail, SMS and SIP through holders | none named |
| #1105 SIM-split-check | Predicate: no secret outside its account's holder | none named |
| #1106 SIM-split-fix | #1053 and #1057 findings: short-secret hashes (H-4), holder re-applies BodyRule (H-3), approvals bound to the account | none named |
| #2497 SIM-split-wire | Per-login public-fetch setting, launcher flag and holder/checker image units | none named |

### Forget and owner hold (W3-forget, W5-Dc, DEL)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #965 W3-forget | Owner-facing forget command | none named |
| #966 W3-forget-b | Authenticated forget log replayed over backups | none named |
| #967 W3-forget-b1-5 | The vault keeps the forget log for agentosd: #409 R1 and P3; #409 R5 (c) and Security R4, moved from b1-6 and b1-7; the vault's log replaces the learn-dir file as the replay source (from b1-6); #409 Security L1 (f3), sealed destination copi | none named |
| #968 W3-forget-b1-6 | The restore entry checks the forget log safely: #409 R2, R3, R5 (a), (b), (d), L2 (f4) and L3; #436 Security point 2; #487 UX point 1 (no held page; the restore prints the hold); #519's L3 points; R5 (c) and R4 moved to b1-5 Also (#503 L3 r | none named |
| #972 W3-forget-b2c-f1-w | L1 wording for take-back texts: the permanent no-lineage case (errNoLineage) needs its own text with an owner step, since "I keep trying" misleads there (UX U2 on #602); restored take-backs are silent until done, so add a count-only not | CH-12 |
| #974 W3-forget-b2c-f1-r4 | Hold the digest when learning did not open after a restore: when openLearning fails after a restore (forgotten.add or replayForgotten errors, or forget-log.json does not read), lp == nil but dg.run still starts (main.go:716-720), so no | CAP-3 |
| #976 W3-forget-reach-r2 | MarkBack writes to the store whose MarkReset just failed, so on a persistent store failure and a restart Retry runs the approved take-back's ForgetSince again: show unrecorded backs on STATUS while they are held only in memory, or write | none named |
| #978 W3-forget-reach-r4 | With OnTakenBack unset, Retry now sends TakenBack for take-backs TakeBack returned nil for and for unasked ones, not only after ErrCarried: limit the no-hook text to approved take-backs, or record the change in recalltool ASSUMPTIONS T4 | none named |
| #979 W3-forget-reach-r5 | The OnTakenBack wiring is untested (mutants W1 and W2 survive): add a test through NewService that sets ServiceConfig.OnTakenBack and sees the hook fire from a Retry pass, plus a constructor helper that main.go and the test share (relea | none named |
| #983 W5-Dc-r5 | Source-side forget duty end to end: a forgotten reference re-offered by a source in a higher generation is never sent; test it across ownerForget, the sources and the queue | none named |
| #984 W5-Dc-r13 | Provider mail security alerts (new sign-in, recovery change, forwarding added) reach the owner at once, outside digest pacing (SPEC line 396; CH-15): broker/mail only flags them (guard.go isAlert, AlertWording) and no path texts the owner; send  | CH-15 |
| #986 W5-Dc-r15 | Hold eviction priority: past MaxHeld the hold drops the oldest texts whatever their class, so a flood of agent or update texts can push out a held approval or broker text. Evict agent, then update, before approval or broker texts, or cap the hol | CH-12, CH-15, OP-9 |
| #987 W5-Dc-r16 | Held-text visibility: the owner cannot see that texts are waiting. Add a STATUS note "N texts wait until HH:MM" and a held or late marker on packed released texts (CH-15, CH-12); the STATUS half ("N texts wait until HH:MM", owner.Channel.HeldNot | CH-12, CH-15 |
| #988 W5-Dc-r17 | Forget reach into the owner hold (CAP-3): held texts carry no forget reference, so a forget does not reach a text held overnight and it is sent on release. Give HeldText a reference and let forget drop it (owner ASSUMPTIONS O25) (release, brief  | CAP-3 |
| #795 DEL-1 | An accepted owner reply survives a crash: persist before 204, idempotent reply, guest retries what it holds | none named |
| #796 DEL-2 | Send outcomes for owner replies: retry known-unsent, flag uncertain, stable email intent | none named |
| #1133 P3-3-erase | An erase that fails part-way is never reported done on retry: bus Forget after a failed rewrite, journal Erase after a failed read, a torn seen line losing the next ID | CAP-3, CAP-4 |

### Updates and mail follow-ups (SR3)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #778 SR3-4f-r2 | The owner's retry control ships with W5b (release, tier A, UX on #597 R1 (6080675106); a W5b "Done" gate): the control calls Applier.Retry, and a held-owner-text test covers the applier's refused and unrecorded lines | none named |
| #780 SR3-4f-3-f1 | Follow up an open security Concern: a security Concern still unreverted after one day or N Recheck passes adds one digest line with a step for the owner | none named |
| #781 SR3-4f-r3 | Re-ask the owner about a refused or unrecorded security fix (release, tier A, UX on #597 R2 (6080675106)): a refused or unrecorded security fix gets a repeated digest line and an ask on the A7 channel, paced per GR9 | none named |
| #784 SR3-6-f6 | A narrowing leaves ordinary-release claims standing, and W5b must bind the copy it stages (OSS-9, UPD-5; after SR3-6f-4). (a) retireClaims walks only TestedBy, which holds security claims, and a version already proposed is never decided again, so | OSS-9, UPD-5 |
| #787 SR3-mail-w2-r1 | W2 carries from #643, to add to the SR3-mail-w2 brief and tests: (1) the scanner fence: mailsock imports broker/mail, which imports golang.org/x/text/encoding/htmlindex, so the first commit that links mail.New or mailsock into agentosd fail | CH-12 |
| #788 SR3-mail-w2-f1 | Journal redactor keeps mail message ids so organize runs in production: agentosd gives daemon.Run a redactor that keeps mail.Change evidence readable while redacting vault values and CH-19 patterns. Which fields stay is a privacy decision ( | ADP-2, CH-19, CRED-7 |
| #791 SR3-5-f4 | Mail: errChanged ("changed since approval") is reported where nothing changed (an Execute with no pin, a Reconcile Unknown after a restart, a movedFrom failure): give each its own fixed reason words (CH-19); brief to write (release, tier A; lens  | CH-19 |
| #2300 SR3-4f-3-f1 finding | Resume commits a boot into an image being withdrawn | CH-19, OP-7, UPD-1 |
| #2483 SR3-mail-k18g later | List FuzzBodyCheck in the image fuzz manifest | none named |

### Model routes, vault and egress (CRED-5, TRUST, S8-W1, W6)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #811 CRED-5f-mr | Model line for STATUS through modelroute: C2 grant, lock and reachability state, replacing agentosd's socket stat (#525 records) | none named |
| #812 CRED-5f-mr-busy | C2: a probe that times out while the vault process is busy (an unlock's key derivation, say) reads "not reachable ... restart the box", like a dead process; tell a slow answer apart from none, or retry before naming a restart (release, tie | OP-9 |
| #816 CRED-5t | Broker-held route failure triggers and fail-closed refresh test | none named |
| #817 CRED-5w | Owner pause and withdrawal notice for broker-held routes | none named |
| #818 CRED-5b | Build and test broker-held route failure, fallback and owner pause | CAP-11 |
| #1559 TRUST-anchor-sync-audit | Audit the Anchor and counter-creation paths for the same landed-but-not-synced gap | HW-8 |
| #1794 TRUST-stagefault-tests | Pin the stage fault after the .next file lands, test InjectStageFault restore and nesting, and fix the giveBack comment | HW-8 |
| #1796 S8-W1 plan route body check | Item/part field sets and two surviving mutants | ADP-10, CRED-5 |
| #2024  | Two provider workers together can still hold every route call | none named |
| #1328 S8-W1-tunnel-peer | Restate the tunnel's SO_PEERCRED check against gVisor's shared host UID | none named |
| #999 W6 | Recovery into the vault process and local UI | none named |
| #932 P2-2w c2 r1 | Setup on a vault whose enrollment is closed: the vault answers "never opened" apart from "sealed", and the page says the box cannot finish setup instead of "already set up" with a Continue that finish refuses (release finding, L3 on #367; loca | none named |

### Recall (RECALL)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #884 RECALL-canary-4 | A neutral marker for shape-only removals (CRED-1; owner-visibility): a phone, order or tracking number removed by the even-group rule reads [credential removed], which tells the owner it was a credential and not "withheld, look in the sour | CRED-1 |
| #885 RECALL-canary-5 | Tools/risk_tier.py maps broker/recall/scrub.go (and the vault redactor) to tier A: it prints B for a CRED-1 custody change, so a Sonnet-pilot builder and a lighter review follow; raised twice on #624, so it becomes a check (L3 6084938278 p | CRED-1 |
| #886 RECALL-canary-6 | Credential predicates spelled with an acronym run into a lower-case word (APIkey splits as ap_ikey, SSHkey, PINcode, OTPsecret, 2FAcode, SEEDphrase) or as run-together lower-case words (sshkey, masterkey, accesstoken, wifipassword) keep th | CRED-1 |
| #1134 RECALL-EMB | A real local embedder for recall (CAP-3; release; tier B). EmbeddingGemma 2 270M text embeddings with Matryoshka truncation to 512 or 256 dimensions; RSS and per-query latency measured on the N95; BM25 fallback when the model is missing or fail | CAP-3 |
| #1237 REACH-plan-lazy | Compute Plan only when approved | none named |

### Grants and approvals (P3-4b, OSS-10, OP2, PE3, W5a)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #849 P3-4b-4e-earned | ADP-11 "Earned" is not enforced where a reply rule is granted: a meta.grant.change carrying Rule.Reply from any origin is validated and asked on the local page with no CAP-6 run of 20 unedited approvals behind it, and Gate.matches never co | ADP-11, CAP-6 |
| #850 P3-4b-4e-composer | No production code sets grants.Config.Isolated, so on a box no machine is an ADP-11 reply composer and reply rules never match; the composer machine (fresh, thread messages only, no recall, no egress) and its wiring in agentosd are unbui | ADP-11 |
| #851 P3-4b-3b | Owner decision: does a probe failure pause grants on the probed machine? DECISIONS says a fuzz crash is "noticed, not contained"; the probe case is open (#523 Potency 2) (brief to be written) | none named |
| #852 P3-4b-3f | Socket probe wired on a machine whose journal is the probe's own, so Journaled raises no false High on a busy machine; takes row 3g. Open question for Mark: dedicated probe machine (recommended), idle live machines, or per-effect attribution (#52 | none named |
| #957 OSS-10w2 r1 | Follow names: the reserved-name check (grants.followName, localui askFollow) also refuses look-alikes of "the AgentOS project" (folded as owner.fold does for CH-10, or a confusable skeleton), so a named follow never reads as switching back (re | CH-10 |
| #1680 OP2-later-d9 | Pin covers for implicit and late approvals, say why a re-ask comes, drop D-116's unreachable erased clause, fix the PR body's erased scope | OP-2 |
| #2185 OP2 | SendID fallback compares recipient lists with duplicates | OP-2 |
| #959 PE3 | Replay machine admission refusal interrupts, not fails | none named |
| #996 W5a-resume | Per-grant resume on the local page | none named |

## 7. Left open

- Kept by Mark's go: the STOP and RESUME defects (#2458, #2459, #2463, #2465, #2475, #2481, #2489, #2264, #2120, #1565, #1444); #2518 permission allow rules; hardware, image, modem and Wi-Fi items (#935, #936 and the M6 chain); CI flake fixes (#1917); Codex-lane and Codex-route rows (#2117, #2115, #2111, #2084, #1720, #1014, #1264).
- Left for the spec PR, which owns SPEC.md, PLAN, BOARD, LANES and OPERATING: L1 spec-diff rows (except SIM-sd #761 and SIM-outer #1107, which fall with D-095), SIM-repo-2b (#775), the owner channel and UX rows, CRED-4 browser custody (#316), the CTRL-card, ROT-*, CAP-15 and PLAN-* rows, and the board itself (its rows leave as their issues close).
