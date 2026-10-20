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
| #2513, #2507 | Recall's open step runs only inside the recall guard, checked by identity so an alias, parentheses or a method expression cannot call it outside | OP-4 |
| #2519 CRED-5f-mr-addkey (head 0bfeaaa6) | A provider key can be added after setup, from the local page, with the one-time code; a request without the code never reaches the provider | CRED-1, CRED-5, ONB-3 |
| #2519 | The provider checks the key before the code is spent, so a refused key burns no code | ONB-3, CH-10 |
| #2519 | The key is never in the page, a log, a redirect or the daemon's disk; only the holder stores it | CRED-1, CRED-5 |
| #2519, #1278 | A box past setup serves the add-key step (owner-authenticated, through the vault path); the no-key line names a step the owner can take ("add a key on my Wi-Fi page"), never "wait for a later version" | CRED-5, ONB-3, OP-9 |
| #2499 SEC-backs-append-latch, #2461 | A failed append is cut back to its start size and synced (or the store stays latched until reopened), so the next mark never joins torn bytes and is lost, and an approved rollback does not repeat after a restart | CAP-3, RES-4 |
| #2500 SEC-events-latch-retry | An event is delivered at most once per publish, with a bounded attempt count: a latched store never delivers a trigger-matched event and then errors (so a retry would redeliver it), and never drops its backoff and attempt records | CAP-3, RES-4 |

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

Copied from briefs/SIM-cases.md at commit 0b3d474, which mapped the 67 W5-D drafts (#263 to #435) and the POT drafts to owner-visible cases. Cases that existed only because of the daily digest (removed by D-097) are not carried; what the owner keeps from them is the last three rows. Drafts that tested only pacing-file storage, leases, manifests or daemon wiring have no owner-visible case.

| Draft | Case | Owner sees |
|---|---|---|
| #271 W5-D7 | A send cancelled before the modem bridge admits it | Nothing is sent and the text is not counted as possibly sent |
| #271 W5-D7 | A send cancelled after hand-off to the modem, then a late receipt | The text stays "may have been sent"; the late receipt neither resends nor flips it |
| #272 W5-D8 | A failed send to the owner's line | The local page shows the line failure |
| #280 W5-D14 | Local STOP while owner state is busy | STOP takes effect at once |
| #280 W5-D14 | STOP after an older RESUME code was issued | The older code no longer resumes |
| #280 W5-D14 | STOP during a RESUME code check | The system stays stopped |
| #304 W5-D22 | A strong code used, then a restart | The same code is refused after the restart |
| #304 W5-D22 | A code check whose state save fails | No unlock; the code is not spent; the owner gets the state-error reply |
| #305 W5-D23 | Wrong codes on the local page | Each is counted once; the lock and the challenge are texted once |
| #307 W5-D25 | A sign-in alert whose send fails | The alert is delivered once after the restart |
| #307 W5-D25 | A sign-in whose record save fails | The sign-in stands and is texted at once, once |
| #306 W5-D24 | Owner state unreadable at start | Nothing starts and nothing is written over the state |
| #306 W5-D24, #385 W5-D60 | STOP while owner state or accounting state is unreadable or missing | STOP still takes effect |
| #335 to #337 W5-D37 to D39 | The hourly allowance spent, then a restart, a crash, or a failed stamp save after a text goes out | The allowance is not refilled; the next update in the hour is held and goes once the hour passes |
| #335 W5-D37 | An aged request's priority turn, then a restart | The aged request still goes first |
| #335 W5-D37 | A pacing storage fault on any request path | The request is requeued, never sent uncounted or dropped |
| #335 W5-D37, #333 W5-D35 | Concurrent sends, and questions and updates together | Never more than one hourly allowance, shared across kinds |
| #335 W5-D37 | A blocked pacing save | STOP and urgent texts are not delayed by it, nor by any blocked storage |
| #336 W5-D38 | A pacing save that fails before a text goes out | The text is not sent and the error is returned |
| #287 W5-sid | A short request ID lent, then a restart before it is saved | Two open requests never share a short ID |
| #390 POT-P5 | A declined suggestion, then a reload | It is not offered again |
| W5-Dc r13 to r17 | A forget while texts are held | The held text of the forgotten subject is dropped; the hold is rebuilt from owner-text intents after a restart |
| SIM-erase | A forget | It reaches every derived view exactly once |
| digest drafts | A crash during an urgent send | The text is never sent twice; an uncertain send is reported as uncertain |
| digest drafts | A crash, then STATUS | STATUS shows the same open items as before the crash |
| digest drafts | A forgotten subject | It never appears in STATUS |

## 5. Queued rows with a brief

| Source | Behaviour | Requirements |
|---|---|---|
| GR-reissue-deadline ([brief](../../briefs/GR-reissue-deadline.md); its issue is closed) | A request re-issued after a restart keeps its original absolute deadline; a YES after the deadline is an expired decision; a passed deadline is refused with nothing opened, not renewed; a text send that outlasts the deadline closes the page request as expired | CH-10, OP-4 |
| EGRESS-rule-1 (#1321) | The route check reads the router's own rule, not a copy, so the check and the route cannot disagree | none named |

## 6. Security properties from the superseded decisions

| Source | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| D-065, D-071 | A restore never brings back forgotten data: when the forget log is missing (an older backup), rolled back to an earlier copy, or not anchored to the box's trusted counter, the restore holds until the owner says when they last forgot something, and each of those cases has its own wording | CAP-3 |
| D-065, D-071, D-076 | That question shows the real last-forget date among same-format decoys, plus "later than all of these" and "never". Decoys fall both before and after the real date, so the real date is usually not the latest shown; a picker that puts every decoy before it fails. Decoys sit at least 45 days apart, except that when room before the backup is short, decoys after the real date may sit closer, but never under 14 days apart; none falls after the backup | CAP-3 |
| D-078 | A signing key never leaves the clerk's custody; the clerk is the one point that mints per-request tokens, so any agent protocol plugs in there and nothing else holds a key | CRED-1, CRED-5 |
| D-103, #1106 (H-4) | A short owner-chosen secret (a mail or SIP password) can be guessed offline from any hash of it, so only the clerk holds it and no hash of it leaves custody | CRED-1 |

## 7. Harvested issues

Each issue below is closed as superseded once this file merges. Its text stays readable on GitHub through the link. Issues merged into a row in sections 1 and 5 (#2507, #1278, #2461, #2500, #1321) close with it.

These close with no case, because each is housekeeping of old-core code with no kernel equivalent: #2455 (cache a per-request redactor), #2484 (reuse a helper in workerroute.go), #2483 (list a fuzz target in the image manifest), #1874 and #2112 (egress ASSUMPTIONS edits) and #1237 (compute a plan lazily).

### Journal, replay and startup reconcile

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
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
| #1963 CHG-adoption-journal-later | Orphaned adoption bodies and proposals are collected; a body never runs ahead of the record it belongs to; the active set is rebuilt from the log when its bulk record is lost, never reset to the initial config; a confirm retried while STOP holds leaves no authorized intent behind; adoptions are visible from the moment the store exists; a proposal never lapses before replay finishes | none named |
| #1967 SM-adoption-journal-a follow-up (later) | C36 narrowing wording; replay confirm guard untested | none named |
| #1976 SM-adoption-journal-b follow-up (later) | Retry gate, skipped recheck, mutant coverage, revert wording | none named |
| #1975 SM-AQ later findings | Quality trigger retry gate, mutants, revert attribution (from PR #1974 reviews) | OP-7 |
| #1996 CHG-forget-revert-journal residue | A forged body cannot record a permanent revert; an owed revert refused for good stops retrying and tells the owner after a bounded number of tries; sequence numbers are never reused after a restart; an undo line names its cause; a flush STOP held says so | none named |
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
| #2474 SEC-recall-open-torn-cut | Recall.OpenFile does not cut a torn tail | none named |
| #2473 SEC-backs-latch-clear | A latched back-marks file stays latched until restart | CAP-3 |
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
| #1207 setup vault notes | Setup tells the owner what the vault holds and keeps it locked while setup runs (#1203 L5, L6) | CH-12 |
| #1206 setup vault opening | A stop between the renames that open the vault, a failed rename of the keys, or a crash that leaves a temporary file, never leaves a half-opened vault or a readable leftover copy of a key (#1203 L1 to L4) | none named |
| #1201 card vault wording | Each refusal of a card vault operation tells the owner, in their words, what happened and what step to take | CH-21 |
| #1200 card vault reset | A card vault reset interrupted by a crash leaves no temporary copy of the card behind after the next open (K21 residuals) | none named |
| #2041 failed trust wording | A failed trust change says "nothing was changed" only when nothing was; when vault entries stay, it says which | none named |
| #2303 CAP-11-plan-fu4 follow-up | Wire declared credential formats into the vault process redactor | CAP-11, CRED-7 |
| #1279 CRED-5f-mr-derived | Builder and replay grants follow stored keys | CRED-5 |
| #1310 CRED-5f-mr-grant l1 | Pin #1280's surviving mutant: wireModel without its checkAgentMachine call stays green | CRED-5 |
| #1401 CAP-11-broker-held-hardening | Per-worker placeholders required, placeholder scan, and a label-laundering control for broker-held plan routes (later; CRED-5, CRED-7, CAP-11) | CAP-11, CRED-5, CRED-7 |

### Egress proxy and plan route

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #1611 P2-2w-c4e3-s1-proxy | Pin that egress.DefaultTransport takes no proxy from the environment (DEV-2) | CRED-1, DEV-2 |
| #1873 egress | Test that a refresh without its own placeholder is refused before joining a flight | none named |
| #1872 egress | Overlapping refreshes keep one flight open (CRED-5t liveness) | none named |
| #1871 egress | A panic in the refresh leader pins its flight until restart | none named |

### Holders, keeper and checker (credential split)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #2515 SIM-split-wire later | A taken-over broker cannot fill every open-approval slot (1024 slots of 7-day holds) and so lock real owner answers out for a week: open approvals are bounded per kind. The approval queue rebuilt from a log that holds an Allowed decision equals the live queue | ADP-9 |
| #2506 SIM-split-wire part 4 follow-ups | Grid cell on act items, act bound, untested refusals | CH-10, CH-4 |
| #2502 SIM-split-wire part 3 follow-ups | A box started with the checker split never silently checks codes in the vault process; a verify setting without its pair is refused at start; a right enrol code used again in the same step tells the owner to wait for the next code, not that it was wrong | none named |
| #2498 SIM-split-wire | Enrolment confirms the pending seed in the vault process, not the checker | none named |
| #2496 SIM-split-wire | Approvals held past the checker's 15-minute TTL are refused at the holder | none named |
| #2454 SIM-split-wire | Keeper checks the holder socket's uid | none named |
| #2322 CRED-route-stop-mutants | Tests that kill the surviving route-stop mutants M5, M9, M10, M11 | none named |
| #2016 CRED-route-stop-followup | A route stop survives a restart, so a refused login is never retried without a sign-in; a stop whose cause cannot be swapped overrides a login-refused stop, so only a release lifts it; restart tests run on the real log, not a fake store | CRED-5, OP-11 |
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
| #2490 SR3-mail-k18g later | A reply body with a surrogate pair at the chunk edge is checked like any other; the egress budget a reply reserves is released as it streams, so a slow guest cannot hold about 40 MiB of it; no keep-alive deadline outlives its reply | none named |
| #2315 SR3-mail-k18f follow-up | Check request bodies by streaming tokens, not a map[string]any tree | CRED-8 |
| #2296 SR3-mail-k18g | Egress proxy body check memory and slot fairness (release findings from #2294) | CRED-8 |
| #1256 SR3-mail-k18d | Later points from PR #1245's reviews: vendor/third_party drift check, third_party tier, fuzz registries, malformed-reply status (later, recheck) | none named |
| #1244 SR3-mail-k18 later | A panic in go-imap's greeting leaves that IMAP connection open | none named |

### Updates and approvals (SR3)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #2310 SR3-6-f6-later | Pin retireClaims' held-copy race guard with a test | CH-12, UPD-8 |
| #2104 SR3-6-f5c notice text | Owner notices are worded in the second person, never the third ("the owner") | CH-21 |
| #2094 SR3-4f-r1-f1-f1 | Make activatortest's wholeness and default fit a real P2-1 adapter | UPD-1, UPD-1a |
| #1657 SR3-4f-r1-f2 l1 | Previous-version line keyed on inequality; Booted under the applier lock; untested in-flight guards (later) | CH-12, UPD-1 |

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

### Forget (W3-forget, DEL)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #965 W3-forget | Owner-facing forget command | none named |
| #966 W3-forget-b | Authenticated forget log replayed over backups | none named |
| #967 W3-forget-b1-5 | The forget log the vault keeps is the replay source on restore (it replaces the learn-dir file); copies at each destination are sealed (AEAD) from the one writer and written all-or-nothing, and forget entries replay in the order they were written | CAP-3 |
| #968 W3-forget-b1-6 | The restore entry checks the forget log safely before any data is restored, and creates its socket directory privately (0700, owner only) when it is missing | CAP-3 |
| #972 W3-forget-b2c-f1-w | A take-back that can never finish (no lineage) gets its own text with a step the owner can take, never "I keep trying"; take-backs restored from a backup get a count-only note; the retry line on STATUS says nothing is needed from the owner | CH-12 |
| #974 W3-forget-b2c-f1-r4 | When learning does not open after a restore, nothing is sent from the restored state, so a restored goal's batch is not sent before forget has been replayed | CAP-3 |
| #976 W3-forget-reach-r2 | An approved take-back whose done mark failed to save is not run again after a restart: the mark is kept somewhere that survives, or STATUS shows the take-back as unrecorded while it is held only in memory | CAP-3 |
| #978 W3-forget-reach-r4 | The "taken back" text goes only for take-backs the owner approved, never for ones that did nothing or were never asked | CH-12 |
| #979 W3-forget-reach-r5 | The taken-back notice is wired and tested end to end: a retry pass that finishes a take-back fires the notice through the same constructor production uses | none named |
| #795 DEL-1 | An accepted owner reply survives a crash: persist before 204, idempotent reply, guest retries what it holds | none named |
| #796 DEL-2 | Send outcomes for owner replies: retry known-unsent, flag uncertain, stable email intent | none named |
| #1133 P3-3-erase | An erase that fails part-way is never reported done on retry: bus Forget after a failed rewrite, journal Erase after a failed read, a torn seen line losing the next ID | CAP-3, CAP-4 |

### Updates and mail follow-ups (SR3)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #778 SR3-4f-r2 | The owner's retry control ships with W5b (release, tier A, UX on #597 R1 (6080675106); a W5b "Done" gate): the control calls Applier.Retry, and a held-owner-text test covers the applier's refused and unrecorded lines | none named |
| #780 SR3-4f-3-f1 | Follow up an open security Concern: a security Concern still unreverted after one day or N Recheck passes adds one digest line with a step for the owner | none named |
| #781 SR3-4f-r3 | Re-ask the owner about a refused or unrecorded security fix (release, tier A, UX on #597 R2 (6080675106)): a refused or unrecorded security fix gets a repeated digest line and an ask on the A7 channel, paced per GR9 | none named |
| #784 SR3-6-f6 | A narrowing (an attestor removed) retires every claim that relied on it, ordinary releases included, so an adopted release never reads "ready, installs at next quiet time" while staging refuses it; the policy binding covers the exact copy that is staged | OSS-9, UPD-5 |
| #787 SR3-mail-w2-r1 | Mail is reached only through its one adapter, never by a path prefix allowance; when the vault is locked at start, the mail account is re-checked on each call once unlocked; a refused sign-in names the step that failed (sign-in, unreachable) | CH-12 |
| #788 SR3-mail-w2-f1 | The log keeps mail message ids so an approved organize can run, while vault values and CH-19 patterns are redacted (which fields stay is a privacy decision, CRED-7); until then organize is asked every time. The owner hears distinct words for unbound, locked and unconnected; an undo report tells "could not reach the vault" apart from "changed since"; a forced ask gives its reason in the owner's voice | ADP-2, CH-19, CRED-7 |
| #791 SR3-5-f4 | "Changed since approval" is said only when something changed; an action with no pin, an unknown outcome after a restart and a failed move each have their own fixed words | CH-19 |
| #2300 SR3-4f-3-f1 finding | Resume commits a boot into an image being withdrawn | CH-19, OP-7, UPD-1 |

### Model routes, vault and egress (CRED-5, TRUST, S8-W1, W6)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #811 CRED-5f-mr | Model line for STATUS through modelroute: C2 grant, lock and reachability state, replacing agentosd's socket stat (#525 records) | none named |
| #812 CRED-5f-mr-busy | A probe that times out because the vault process is busy (an unlock's key derivation, say) is told apart from a dead process, or retried, before the owner is told to restart the box | OP-9 |
| #816 CRED-5t | Broker-held route failure triggers and fail-closed refresh test | none named |
| #817 CRED-5w | Owner pause and withdrawal notice for broker-held routes | none named |
| #818 CRED-5b | Build and test broker-held route failure, fallback and owner pause | CAP-11 |
| #1559 TRUST-anchor-sync-audit | Audit the Anchor and counter-creation paths for the same landed-but-not-synced gap | HW-8 |
| #1794 TRUST-stagefault-tests | Pin the stage fault after the .next file lands, test InjectStageFault restore and nesting, and fix the giveBack comment | HW-8 |
| #1796 S8-W1 plan route body check | Item/part field sets and two surviving mutants | ADP-10, CRED-5 |
| #2024 Provider worker route hold | Two provider workers together can still hold every route call | none named |
| #999 W6 | Recovery into the vault process and local UI | none named |
| #932 P2-2w c2 r1 | Setup on a vault whose enrollment is closed tells "never opened" apart from "sealed", and the page says the box cannot finish setup instead of "already set up" with a Continue that is then refused; "sealed by setup" apart from "never opened" lets finish accept a lost setup record | none named |

### Recall (RECALL)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #884 RECALL-canary-4 | A phone, order or tracking number removed only for its shape reads with a neutral marker ("[code removed]"), never "[credential removed]" | CRED-1 |
| #885 RECALL-canary-5 | A change to the credential scrubber or redactor is reviewed at tier A, enforced by the tier tool rather than by reviewers remembering | CRED-1 |
| #886 RECALL-canary-6 | Credential predicates written with an acronym run into a word (APIkey, SSHkey, PINcode, OTPsecret, 2FAcode, SEEDphrase) or as run-together lower-case words (sshkey, masterkey, accesstoken, wifipassword) still have their object scrubbed; the split is word-aware, so "PINned" is not a credential | CRED-1 |
| #1134 RECALL-EMB | Recall uses a local embedder (EmbeddingGemma 270M, truncated to 512 or 256 dimensions) and falls back to BM25 when the model is missing or corrupt, saying so on STATUS; a held-out query whose relevant item shares no keyword ranks it in the top 5; memory and p95 latency stay within the N95's limits; items are re-embedded when the model changes | CAP-3 |

### Grants and approvals (P3-4b, OSS-10, OP2, PE3, W5a)

| Issue | Behaviour to keep or failure to prevent | Requirements |
|---|---|---|
| #849 P3-4b-4e-earned | A reply rule is granted only once it is earned: the attention optimizer offered it for that account after a run of 20 unedited approvals (CAP-6), whatever origin asks for it | ADP-11, CAP-6 |
| #850 P3-4b-4e-composer | Reply rules match only on a composer machine that is fresh, sees only the thread's messages, and has no recall and no egress; without one, reply rules never match | ADP-11 |
| #851 P3-4b-3b | Open for Mark: does a failed probe pause grants on the probed machine? A fuzz crash is "noticed, not contained"; the probe case is undecided | none named |
| #852 P3-4b-3f | The socket probe runs where the log it reads is its own, so a busy machine raises no false High; open question for Mark: a dedicated probe machine (recommended), idle live machines, or per-effect attribution | none named |
| #957 OSS-10w2 r1 | A follow name that is a look-alike of "the agentOS project" (after case and accent folding, or by confusable skeleton) is refused, so a named follow never reads as switching back to the project; plain names still pass | CH-10 |
| #1680 OP2-later-d9 | Pin covers for implicit and late approvals, say why a re-ask comes, drop D-116's unreachable erased clause, fix the PR body's erased scope | OP-2 |
| #2185 OP2 | SendID fallback compares recipient lists with duplicates | OP-2 |
| #959 PE3 | Replay machine admission refusal interrupts, not fails | none named |
| #996 W5a-resume | Per-grant resume on the local page | none named |

## 8. Left open

- Kept by Mark's go: the STOP and RESUME defects (#2458, #2459, #2463, #2465, #2475, #2481, #2489, #2264, #2120, #1565, #1444); #2518 permission allow rules; hardware, image, modem and Wi-Fi items (#935, #936 and the M6 chain); CI flake fixes (#1917); Codex-lane and Codex-route rows (#2117, #2115, #2111, #2084, #1720, #1014, #1264).
- Kept with the Codex route, because #1014 S8-W1-tunnel continues: #1328 (the tunnel's peer check sees gVisor's shared host UID, so it must be restated before #1014's build), #1756 (field-aware placeholder resolve and measured header lists on the plan route), #1763 (correct the PKCE claim; stop the plan route on a refused refresh) and #2479 (egress denies CLI guests' provider cloud hosts; it pairs with #2417, which stays open).
- Kept for the spec PR, which maps them to the key, the clerk or the log: the owner hold and pacing rows, which live in broker/owner and the owner channel, not the old core. #983 (a forgotten reference re-offered by a source is never sent), #984 (provider security alerts, such as a new sign-in, a recovery change or added forwarding, reach the owner at once, outside pacing; CH-15), #986 (past the hold limit, agent then update texts are dropped before approval or broker texts, and agent texts get their own share of the hourly allowance), #987 with #2271, #2442 and #2451 (one held-text case: STATUS says texts are waiting, a released text carries a held or late marker with its date when held over a day, and urgent approval texts are not coalesced), #988 (a held text carries a forget reference, so a forget drops it before release; CAP-3), #2068 and #2211 (held install notice wording).
- Kept for the spec PR as trusted-host work rather than old-core hardening: #958 HOST-1f-r2 (vault lockout) and #827 P2-8b (vault re-encrypt), which also touch HW-8.
- Left for the spec PR, which owns SPEC.md, PLAN, BOARD, LANES and OPERATING: L1 spec-diff rows (except SIM-sd #761 and SIM-outer #1107, which fall with D-095), SIM-repo-2b (#775), the owner channel and UX rows, CRED-4 browser custody (#316), the CTRL-card, ROT-*, CAP-15 and PLAN-* rows, and the board itself (its rows leave as their issues close).
