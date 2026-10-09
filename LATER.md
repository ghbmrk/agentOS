# LATER: first-release critical path and backlog
Generated 2026-10-07 by the COST thread's audit; the coordinator updates it. Rows marked LATER are not started until the first release ships (DECISIONS D-048). Promote a row by moving it to "Release" with the acceptance test it now blocks.

## Summary
Non-merged rows audited: 129; the 67 stale rows it found were reconciled into BOARD.md on 2026-10-08 (DOC-3), and rows since merged were removed from the tables below. Row counts are not kept here, because every PR that touches a table made them stale; count the table rows (a line starting `| ` under each heading) when a number is needed.
No security-fix row (SR2-* or SR3-*) is classed Later. P2-1 (host image, PR #41) has no board row but blocks IMG-1, HOST-1a/1b/1c part 2 and W3-builder-ship.

## Release (needed for A1–A15 or an invariant)
| ID | Needed for | Note |
|---|---|---|
| SR3 | A4, A7, A12–A15 | Documentation intake for eight release findings; remediation stays open after intake merges |
| SR3-1 | A4, A6, A14 (CH-7, localui L25) | Lock during sign-in/refresh cannot mint a live token; stale sessions cannot RESUME |
| SR3-2 | A4, A13 (ADP-9, OP-3) | STOP-aged queues and concurrent dispatch obey current daily/per-record bounds |
| SR3-3 | A13, A14 (ADP-9, CH-3, CH-12) | Final approval shows and binds every authority-bearing grant field |
| SR3-4 | A7 (UPD-1, OP-4/5) | Interrupted update settlement converges after reopen; subsequent updates work |
| SR3-5 | A4, A13, A15 (ADP-2, OP-3, REV-2) | Mailbox epoch changes cannot redirect a guarded mutation or undo to another message |
| SR3-6 | A7, A14 (UPD-8) | Retiring interim trust invalidates pending automatic update authorization |
| SR3-7 | A4 (OP-8, ARC-7) | Meter-to-provider composition enforces one canonical, reserved request; source-only finding |
| SR3-8 | A12 (OSS-2) | Crash cuts cannot leave a completed clean-room job with unrecoverable output; source-only finding |
| S5 | A5, A13 | CRED-4 action protocol; live run blocked on network policy |
| S8-W1 | A14, CRED-5 | Blocks every worker-held route; credential invariant |
| S8-live | A3 (CAP-11) | Needs Mark's Claude and ChatGPT plans |
| S8-W1-tunnel | A3, A14 (CRED-5 W4) | CONNECT-only tunnel with broker-resolved host and SNI binding; precondition of any worker-held route; no CONNECT handler in `broker/egress` at 256b7cc (from S8-W1a, #543). Promote to a BOARD row with a brief when S8-W1 is scheduled |
| S8-W1-volume | A14 (CRED-5 W2) | Per-provider login volume (schema check, writable login file only) and its exclusion from snapshots, recall, journal and results; no code at 256b7cc (from S8-W1a, #543). Promote with S8-W1 |
| S8-codex-terms | A3, CRED-5 (unsure) | Decides Codex custody; a Claude plan route may already satisfy A3 |
| CRED-5f | A3 (CAP-9), CRED-5 | Plan route withdrawn with no API key granted must still route or tell the owner |
| CRED-5t | CRED-1 invariant | Unswappable refresh response must fail closed; stop retrying on account restriction |
| CRED-5w | CRED-5 | Owner can pause a broker-held route before a withdrawing release |
| S1 | A1 (G1) | Test kit ready; waits on Mark's hardware |
| S2 | A1, A3 | Modem SMS and voice; waits on Mark's modems |
| P2-4-hw | A8 | Real-TPM trusted-host run; risk 14 |
| P3-4b-1b | LOOP-9, LOOP-10 | Loop-side follow-ups to #464 before -3/-4 wire `Report`: close findings the tree comes to pass, finding-ID collision, crash resume, wording-scan coverage, config-probe fixes |
| P3-4b-2b | A11, CHG-2 | Harness follow-ups to #490: evidence check passes with no evidence record; raw held clause whose fields the visible test shares escapes the audit; leaking-adapter control runs on every valid seed |
| P3-4b-2 | A11 | Qualification harness for A11's loop 2 clause: harness-chosen seed, held-back variants, scripted rejected fixes |
| P3-4b-5 | LOOP-9 | Model-backed loop 2 fixer answering the §11 fix-candidate request through Loop 1's builder; needs W3-builder-ship |
| OP9-status | A11 (OP-9) | STATUS names every capability that is off or can't run; briefs/OP9-status.md, split into -a and -b |
| DIG-1 | A3 (CH-15), OP-9 | Daily digest sender reading every `Digest()` source; nothing sends a digest today; brief to be written |
| P3-4b-3 | LOOP-7 (D-067) | Off-the-shelf fuzz targets and in-guest socket probe; no longer in A11 (D-070), release because D-067 still governs LOOP-7 (D-070 supersedes it on A11 only) |
| P3-4b-4 | LOOP-7 (D-067) | Continuous canary rounds, published corpora, scripted tamper and exhaustion probes; same basis as P3-4b-3 |
| UPD-b | A1, A14 (UPD-3) | Update before accounts connect |
| CH-20w | A15 (CH-20) | Evidence delivery through the vault-held mail adapter |
| CRED-4b | A5, A13 | Credentialed browser executor; sessions only in the vault process |
| ADP-8 | A13 (ADP-8) | Mislabelled-draft check blocks adoption |
| ADP-5 | A13 | Desktop executor and kiosk-escape test; blocked on CRED-4b |
| OSS-6s | A12 | Publication sender, idempotent by day and batch |
| OSS-6j | A12 (OSS-6, DEP-2) | L3 on #330: the pull job is repository automation, not a service |
| OSS-6i | A12 (OSS-6) | L3 on #330: rotation is void if batches share a circuit |
| OSS-6p | A12 (OSS-6) | L3 on #330: OSS-6 values the sender needs |
| OSS-6a | A12 (OSS-6, OSS-7) | L3 on #330: silence vs ask-each-time |
| OSS-5t | A12 (OSS-5) | L3 on #330: embargoed report over Tor or not |
| OSS-6e | A12, clean-room invariant | Security ruling on #180: floor holds across restarts |
| OSS-10w | A12 (unsure) | Follow-fork wiring; OSS-1–13 are in A12's requirements |
| IMG-1 | A1 | CI scan for per-owner secrets in the image; blocked on P2-1 |
| P2-2w | A1, A14 (ARC-2) | Local UI process; sub-rows a, b merged, c and d open |
| P2-2w c | A1, A14 | Setup into agentosd; Security L6, L7 MUST |
| P2-2w d | A1, A3, A14 | Turns LocalUI on; unblocks approvals and CH-20p |
| SR2-3g | A5, A6 (security) | No host path in agent-visible tool errors |
| SR2-4i | A2 (RES-2) | Host image enables iocost; blocked on host image |
| CH-21 | A14 (CH-21) | Name, first-person voice, spoofed NAME refused |
| HOST-1a | A1 (HW-8) | Part 2 needs P2-1 image |
| HOST-1b | A1 (HW-8) | Part 2 needs P2-2w live page |
| HOST-1c | A1 (HW-8, ONB-7) | Part 2 needs P2-2 |
| HOST-1e | A1 | Host-untouched hash harness |
| PE7-bus | A11, A2 | Condition on the events-bus package; floor host; follows that package (D-067) |
| PE7-call | A11, A2 | Condition on the inbound-call package; follows that package (D-067) |
| W3 | A11 | Learning process; steps 3a, 3c open |
| W3-builder-ship | A11 | Builder defaults; P2-1 side queued |
| W3-forget | A14 (CAP-3) | Owner FORGET; split a, b |
| W3-forget-b | A14 (CAP-3) | Authenticated forget log over restores; Security C3 |
| W5 | A11, A15 | Owner channel for loops, digest, hint emitter |
| W5a-resume | A14 (security) | Per-grant resume needs a fresh bound code; Security R2 |
| W5b | A7, A11 | Loop 3 update checks as a scheduler source |
| W5c | A12 | Clean-room builder in the scheduler |
| W6 | A8 (REC-1–3) | Recovery into vault process and local UI |
| W7 | A10, A15 (CAP-4–6) | Compiled skills live; attention optimizer; blocked |

## Later (backlog; do not start before first release)
| ID | Why it can wait |
|---|---|
| P3-4c | LOOP-7 attacks generated by a model, and SPEC §15's later criterion "loop 2 finds a seeded vulnerability" (D-070); waits until builders have model access sanctioned for adversarial security work (D-067); the non-model half (an off-the-shelf fuzzer or canary hunt against a planted defect) may be promotable earlier through another lane (potency 3 on #408) |
| CRED-5f-mr-key | C2's "granted" reads `-grant` only, not whether the open vault holds that provider's key (cmd/agentosd ASSUMPTIONS M1); a grant without a key fails at the route and is logged; widen with plan routes (CAP-11) |
| CRED-5f-mr-cache | C2's probe is believed a minute (cmd/agentosd ASSUMPTIONS M3), so "the vault is locked" can stand up to a minute after an unlock; drop the cache on unlock or probe sooner after a locked answer (UX lens on #566) |
| CRED-5f-mr-bound | Pin the C2 probe's time bound: a silent-socket case on `context.Background()` returning under 3 s, and an agentosd fake that honours ctx, so the client `Timeout` and `modelProbeWait` cannot both regress unseen (Security on #566 point 2) |
| APPLY-dup | `broker/apply/ASSUMPTIONS.md` repeats rows A3–A7 (found on UPD-b); text only, no behaviour |
| FIRSTBOOT-text | `broker/firstboot` wording (L3 on #379, points 3–5): an unexpected `ScheduleFirstBoot` error still reads "updating to version N"; with several mirrors failing, STATUS names only the last mirror's failure; `Hold()` in `fell_back` says "when the update finishes" where `Status()` says it waits for a newer release. Text only; the gate stays held in each case |
| CR-dup-built | `broker/cleanroom` (L3 on #432, point 3): a crash between logging `built` and removing the queue entry logs `built` twice for one job; one artifact, no duplicate publication, may double-count the weekly hint summary |
| CR-quarantine-prune | `broker/cleanroom` (L3 on #432, point 4): quarantined artifact copies are never pruned; bounded at `maxRepairs`+1 copies (8 MiB each at most) per artifact ID |
| CR-power-cut | `broker/cleanroom` (L3 on #432, point 5): hardware power-cut qualification of the artifact store; no SPEC §15 acceptance test needs it, and simulated faults are recorded as no substitute (C14) |
| CR-list-skip | `broker/cleanroom` (L3 on #432, point 6): a manifest that becomes unreadable at runtime fails `list`, refusing intake until restart quarantines it; fails closed |
| CR-open-cost | `broker/cleanroom` (L3 on #432, potency note): open re-reads every artifact (at most 8 MiB each), so open time grows linearly with the store |
| P2-8b | Deferred re-encrypt after trusted-PC removal; slot removal already covers CRED-9 |
| P3-6d | Digest wording for deleted procedures; no A-test needs it |
| CH-20p | Page view of kept replies; A15 needs delivery, not this view |
| CH-20a | Attachments conflict with security C4; needs review; not in A15 |
| CH-20m | MORE command for redirected replies; convenience |
| P2-2a f1 | L3 SHOULD on page wording after a changed item |
| ADP-13 | Optional box mailbox; no A-test needs it |
| HOST-1d | Optional internal-disk opt-in (HW-8a); A1 requires disks untouched |
| PE3 | Potency follow-up on replay-interruption counting |
| W3-off-a | STATUS wording goes dynamic; polish |
| W3-implicit | Potency C2 outcome label; refinement of attention optimizer |
| W8 | Owner builds; no brief, no A-test names it |
| ADP-14-get | GET links with side effects reached by `navigate` on recipe sites; recipe gate covers state-changing methods first |
| ADP-14-undo-fail | A failed `UNDO` reply gives site, reference and deadline and opens a task; UNDO success path is enough for A13 |
| ADP-14-offer | After repeated approved submits on one unknown site, offer its private-derived draft for adoption; cuts approvals, not needed for A13 |
| ADP-14-cred6 | Recipes declare their site's CRED-6 screens, undeclared ones trigger ADP-7 repair; CRED-6 already applies without a recipe |
| ADP-14-origins | Which origins the credentialed context may reach on a site with no recipe; every state-changing request there is already held |
| ADP-16-acct2 | A second account signed in inside a suite executor's app; ADP-16 kiosk already limits to one account's adapters |
| W3-forget-b2b q | A queued item 2 run long after its YES also takes back work done since; the notice names only the count at the ask (#327 L3 L1) |
| W3-forget-b2b w | A failed owed `MarkTakeBack` write in one `resumeAgent` run lets a later run in the same open try again and text the owner again; fold into the not-saved release row (#327 L3 r5 #2) |
| W3-forget-b2b e | `Reach.TakeBack` returns early on an unfinished reset from the same time without a take-back mark, so a later boot could take back again; no known producer (#327 L3 r5 #3) |
| OSS-6e f1 | Security 319-1 (L3 asked for this line; lands before #319 merges): a missing or unreadable `boot_id` fails open, so each restart can count one day of the 20h floor again |
| W3-forget-b2 f1 | L3 on #321: a forget after a proposal reached the owner requeues the rebuild, which may ask again; rare, owner can decline |
| W3-forget-b2 f2 | L3 on #321: a self-cancelled job still calls propose/Build with a cancelled ctx |
| W3-forget-b2 f3 | L3 on #321: no mutation test covers the post-build disjunct |
| P2-2w d f3 | L3 F3 on #322: LocalUI tracks localui.sock, not the page process; a readiness signal would stop page-asked changes waiting while the page is down; liveness only, nothing approves |
| P2-2w d f3b | L3 F3 on #322 delta: gate.go `NoPage*` reasons say "which is not running"; agent-facing, never texted to the owner (the journal redacts them) |
| P2-2w d f4 | L3 N1 on #322: OSS-10 is missing from the REQ marker in `pagewording_test.go` |
| P2-2w c1 f2 | A crash between the enrollment seal and deleting `owner-totp-pending` leaves that copy of the channel seed in the vault (and backups); unreadable once sealed. Fix: delete a leftover pending entry when a sealed vault opens |
| P2-2w c1 f3 | No negative test for a peer uid on the `/enroll` routes; the `verify.sock` SO_PEERCRED listener is unchanged and already tested |
| P2-2w c1 f4 | L3 L1 on #320: `ReEnroll` does not delete the `owner-totp-setup-open` vault entry |
| P2-2w c2 f2 | Security lens 367-1 on #367 (9bef9df): the seal's pending-seed check and the vault enroll's confirmed-mark delete each stop a restarted pairing alone, and only removing both fails a test; add one vault test per guard when P2-2w c4 touches enroll.go, and read f1 as "either guard" |
| P2-2w c1 f5 | L3 L2 on #320: no test covers a setup-open entry of the wrong kind |
| P2-2w c2 f1 | L3 re-review on #367: the confirm-mark deletion in the vault's enroll and `setEnrolled(false)` in `localsrv` enroll are defence in depth, not load-bearing; the seal's pending-seed check alone gates a restarted pairing |
| P2-2w c2 r1 f1 | L3 point 1 on #465: on a sealed vault with an empty setup record, finish answers `not enrolled`, so the page would say "Try again" rather than the cannot-finish wording; unreachable (the codes step offers no Continue there); map it to `enrollment unavailable` when `localsrv/setup.go` is next touched |
| P2-2w c2 r1 f2 | L3 point 2 on #465: the comment on `gen` in `localui/setup.go` says a confirmation before a restart never counts after it; no longer true after a seal whose record was lost; reword when the file is next touched |
| P2-2w c2 r1 f3 | L3 point 3 on #465: two overlapping enroll calls can let the later one clear a confirmation made for the newer seed; finish then refuses and the owner confirms again; the vault still gates the seal |
| P2-2w c3 f1 | Change the home Wi-Fi after setup: `agentos-netjoin` is served only in setup mode (Security L8.7, [note](reviews/security/2026-10-08-p2-2w-l6-l8.md)); a later change needs its own owner authentication on the page (a fresh code) and a non-setup op; until then a box that moves networks uses Ethernet or a reset |
| P2-2w c3 f2 | SAE-only (WPA3-only) home networks: `agentos-home` is fixed to `key-mgmt=wpa-psk` (Security L8.4; L3 B3 on #422), which joins WPA2 and transition networks only; SAE needs the network's type from c4's scan and refuses 64-hex keys |
| P2-2w c3 f3 | Home networks that do not broadcast their name: `agentos-home` is fixed to `hidden=no` (Security L8.4); `hidden=yes` would make the box probe for the home SSID everywhere |
| P2-2w c3 f4 | A home network on the access point's subnet (`10.42.0.0/24`, L26 `IPAddressAllow`) breaks routing; CH-9 stays safe through L5's device binding (L3 on #422) |
| SR2-3g f6 | `guesterr.New` takes any untyped string constant, a host-path constant included; needs deliberate misuse (L3 on #324). Same kind, from Security on #398: `guesterr.Guest` checks shape, not provenance, so a host value that happens to be ID-shaped shows if a caller mislabels it `Guest`, and an embedded nil `*Guest` panics in `Newf` |
| SR2-3g f7 | L3 R1 on #324: the `guesterr` import sits in the stdlib import group in `question_test.go`; style only |
| SR2-3k f1 | The ID pattern `^[A-Za-z0-9._-]{1,64}$` is written out in `guesterr`, `guest/mcp.go`, `question/tool.go` and `recalltool/tools.go`; one exported pattern would keep them from drifting (later 2, L3 on #398) |
| SR2-3k f2 | An unknown tool named by a non-ID value reads `no tool "(not shown)"`, which looks like a tool's name; unquoted wording would read better (later 3, L3 on #398) |
| SR2-3j f1 | `annotate`'s `GuestReason = Reason` fallback takes a plain string; typing it `guesterr.Literal` would let the compiler hold the rule GR30 states (lens on #396) |
| OSS-10w f1 | UX on #323: the alert wording "Switch back there" reads oddly after a switch back to the project |
| OSS-10w-r | WF1 after a project root-key rotation: switching back compares against the image's shipped root keys and so fails closed once the project rotates them; a chain walk from the shipped root would admit it. Meanwhile the owner's only route back is a named follow (beside U13 limit (b)). No release has rotated root keys; a new image ships the new root |
| W3-forget-b2b f1 | Security 327-1: race between `worked()` and `takeBack(approved=false)` in `agentBackWithoutAsking`; re-check under `r.run` |
| W3-forget-b2c l1 | UX: the recall-off owed take-back text names no owner step, because STATUS has no line when recall is Off (`LateExecutor.Status`); a config only a dev box has; recall Off still has no STATUS line |
| OP9-status-a l1 | L3 L1 on #525: the `C1_vm_open_fails` and `C1_guest_plane_fails` subtests set the same state (`agentOff(agentNoMachines)`), so neither exercises its own path (S11); a split of `main` wiring would let them run end to end |
| OP9-status-a l2 | L3 L2 on #525: with the guest plane failing and no worker image set, STATUS gives both "Agent and worker tools: off" and "Worker tools: not set up" (opposite fixes, against OP-9's "exactly one"); clear `workersOff` in `agentOff(agentNoMachines)` or skip the C10 line while C1 names worker tools |
| OP9-status-a l3 | Security 3 on #525: `ownerWorded` runs only in tests; fine while every line is a constant, but if one is ever formatted, call `capLines.check` at start or fail the test that enumerates producers |
| OP9-status-a l4 | UX 4 on #525: a STATUS in the first minute, before `agentos-egress` is up, says "restart the box" (cached up to a minute), which does not help; fixed in effect by CRED-5f's modelroute state |
| OP9-status-a l5 | UX 5 on #525: C11 stands on every box until W5b, so a daily digest would repeat "Update checks: not running; nothing to do"; the DIG-1 brief says how lines with no owner step are paced, decided by Mark together with Q1 |
| OP9-status-a l6 | UX 6 on #525: "Routing: learning cannot change how work is routed here" is the least plain line; say "Learning cannot change which model does which work" |
| DOC-3 f1 | L3 on #356: the SHAs on rows inferred as merged name the last commit touching the package, not its merge; relabel as "last touched" or cite the PR |
| DOC-3 f2 | L3 on #356: D-041 (license) has date `Pending`, not ISO; set it when the license is chosen |
| DOC-2 f1 | L3 on #357: doclint does not check DECISIONS cells ≤300 characters or that `decisions/D-NNN.md` links resolve (D-056) |
| CRED-5 f5 | L3 point 5 on #328: restore "only" in the broker-held use set so it is closed on its own; state precedence between unconfirmed broker-held and worker-held when terms are silent on proxies but require the provider's sign-in flow |
| CRED-5 f6 | L3 point 6 on #328: D-061 was numbered at merge time; if another PR also claims D-061, the coordinator renumbers whichever merges second |
| CRED-4b f1 | L3 on #300 (#9): the browser gate passes the raw `cfg.Origins` to the driver, not the canonical keys (`gate.go:99`) |
| CRED-4b f2 | L3 on #300 (re-review #7): `exec.CommandContext` kills only the driver's group leader on ctx cancel; set `cmd.Cancel` to kill the process group (`gate.go:100`) |
| CRED-4b f3 | L3 on #300 (re-review #6): no test isolates the Lstat and O_NOFOLLOW symlink layers |
| CRED-4b f4 | L3 on #300 (K6): images in output files are not inspected |
| CRED-4b f5 | L3 on #300 (1960aed re-review #3): the label rule misses `accessTOKEN:` and suffixed labels (`accessTokenValue:`, `access_token_value:`); add to K11's part-2 corpus |
| CRED-4b f6 | L3 on #300 (e000ecc re-review): keep both `myApiKey=<hex>` and `myApiKey: <hex>` in the part-2 corpus |
| CRED-4b f7 | L3 on #300 (f135e43 re-review): the label rule redacts prose such as `See the secret 2024-holiday-party-photos album`; fails closed, noted next to K12 |
| CRED-4b f8 | L3 on #300 (1960aed re-review #4): camelCase false positives (`hotKey 2024-10-08-release-notes`, `useToken 2024-…`, `?sortKey=created_at_2024_desc`); fail closed, part-2 negative corpus |
| CRED-4b f9 | L3 on #300 (e000ecc re-review): an initialism or capitalised word before a label word is redacted (`USBKey 2024-10-08-firmware-notes`, `PGPKey: 2024-…`, `MyKey: 2024-…`); fail closed, part-2 negative corpus |
| OSS-10w2 f4 | L3 on #370 (23bc810): the follow page's reserved-name check folds case only, so look-alikes (Cyrillic А in "the АgentOS project again") pass; the name is the owner's own and the card shows the fingerprint. Fold look-alikes as CH-10 does |
| OSS-10w2 f5 | L3 on #370 (23bc810): localui's `reservedName` and `followPrint` duplicate `grants.ReservedFollowName` and `grants.FollowPrint`; move both into localapi so page and card cannot drift |
| CRED-4b f10 | L3 on #300 (f135e43 re-review): the label rule's value charset misses passwords with other punctuation (`password: Abc123@xyz789#Qq`) |
| CH-21a f1 | `change` `TestForgetGoalRewritesALaterAdoptionsUndo` failed once in a full `go test ./...` run (setup: candidates rejected) and passed on four reruns and alone; look for a load-dependent timing in its setup
| P2-2w d2a-1 | `localsrv.status` reads the whole `Line()` (five modem-link locks) for `.Note`; a note-only accessor would show the D1 split in the types (#378 L3) |
| P2-2w d2a-2 | `pageLine` takes five separate locks, so one page can mix states; display only, fixed on reload (#378 L3) |
| P2-2w d2a-3 | `plural` lives in both `localui/line.go` and modemlink's recovery text; wording can drift (#378 L3) |
| broker/owner review_test.go IDs | L3 on #386: `TestRestartHandsOpenRequestsToReissue` seeds the restart record with hard-coded IDs `Z9`, `Y9`, `X9`, which `newIDLocked` can issue, so a request opened earlier in the test can collide with one (0 of 600 runs failed; assertions tolerate it today); use IDs outside the generator's range (e.g. `Z1`, `Y1`, `X1`) when a package next touches review_test.go |
| W3-forget-b3 rr1 | L3 on #425: `retry` and `finishOwed` log a forget with a zero `Since` though the time is known, so the forget log loses the task's time; restore reads `Since` only for agent entries |
| W3-forget-b3 rr2 | L3 on #425: fold `forget-owed.json` (W3-forget-b3) and the owed take-backs (W3-forget-b2c) into one store or one start-up step; rename `forget_owed_test.go`/`forgetowed_test.go` then |
| W3-forget-b3 rr3 | L3 on #425: `tellLater` and `retry` run on `context.WithoutCancel`, so their shutdown branch never runs; behaviour is right (exit leaves it owed), the comment misleads |
| W3-forget-b3 rr4 | L3 on #425: `TestAGarbageOwedFileFailsSafe` does not assert the rewritten owed file is valid JSON or that a later forget is told |
| HK-1 f1 | Lens screen on #401: the sandbox-unavailable message in `tools/depaudit.py` names neither the PID namespace nor the `/proc` mount it now needs; the probe already fails loudly |
| HK-1 f2 | Lens screen on #401: violations carried from faulted attempts are not de-duplicated, so the same leak seen twice is listed twice; the outcome is unchanged |
| HK-1 f3 | Lens screen on #401: `_scratch_dir` drops `TemporaryDirectory`'s chmod-and-retry cleanup of read-only entries; removal still raises rather than passing |
| W5a-resume-pace | A page resume ask waits for the gate's CH-15 batch before it shows under Approvals; the page says it shows shortly |
| W5a-resume-dedupe | Two concurrent asks for one pause can file two requests; approving one resumes and the other then fails at apply, so nothing widens twice |
| W3-forget-b f1 | L3 on #317: a brief that stores its own state (`**State:**`) can drift from BOARD, which is authoritative; drop the line from new briefs and have doclint flag it |
| W3-forget-b3 f4 | L3 on #425: a failed save after a told done text leaves it owed, so the next start tells it again; a repeat over a lost text |
| W3-forget-b4 l1 | L3 on #528: no test pins that `openOwedFile` removes a stale `forget-owed.json.bad` before the hard link; dropping the `os.Remove` passes every test (the link then fails with EEXIST and the newer bad file is not kept aside, though the owner is still told) |
| W3-forget-b4-promise | UX on #528: `Execute` can leave the owner with `forgetNotSaved` ("I'll text you when it's done") while no owed entry has held (ASSUMPTIONS F11: failing disk plus a crash); a softer promise while `owedSaved` is false, or holding that text until the entry is on disk, would remove it; it changes owner wording, so it belongs to a later owner-text package with a test of the `TestHeldOwnerTextsNameOnlyStepsThatWork` kind |
| W3-forget-b4-aside | Potency on #528: `openOwedFile` removes an older `forget-owed.json.bad` before linking the new one, so a second unreadable file destroys the first, and the aside is never read back (F10's "text each recoverable goal from the .bad file" stays open); when that recovery is built, keep a numbered or dated aside instead |
| W3-forget-b3 f6 | L3 on #425: `forget-owed.json` is uncapped; cap it if forgets can be owed in bulk |
| W3-forget-b3 f7 | L3 on #425: a restored backup's owed file is replayed like the live one, so its texts may be told again |
| DOC-4 f1 | L3 on #400: a no-PR record must still write `head <sha>` for a `main` commit and invent a package (`POTENCY`); accept `PR none · package none · main <sha>` in the Record check |
| DOC-4 f2 | L3 on #400: the Record check skips lens files without a `YYYY-MM-DD-` name (e.g. `reviews/ux/pr500.md`); require dated names for non-README files in lens directories |
| DOC-4 f3 | L3 on #400: the Record check accepts the line anywhere in the file, not only under the title as OPERATING §4 step 3 says; harmless today |
| DOC-4 f4 | L3 on #400: U15 sits between U10 and U13 in `broker/update/ASSUMPTIONS.md`; cosmetic reorder |
| DOC-4 f5 | Lens screen on #400: the Mark-requested SR3 and deep-potency reviews are indexed only by filename, beside per-PR records; keep a one-line "Requested reviews" pointer list (regex part is DOC-4 f1) |
| DOC-4 f6 | Lens screen on #400: OPERATING §4 step 1 could give the run index in one command, `grep -H -e '^Record:' -e '^Verdict' reviews/<lens>/*.md` |
| DOC-4 f7 | Lens screen on #400: `RECORD_DIRS` is hard-coded, so a new lens directory goes unchecked, and `records()` globs the disk, so an untracked scratch record fails a local run |
| DOC-4 f8 | Lens screen on #400: the `head` regex in the Record check accepts lowercase hex only, while its message says "hex"; say "lowercase hex" or match case-insensitively |
| CH-21c f2 | CH-21c: recovery owner texts still open with "AgentOS: " (`recovery/owner.go`), a signature CH-21 says owner texts do not carry; drop it with CH-21e, which owns how broker text is told from agent text |
| CH-21c f3 | CH-21c: third person the voice regex cannot see stays in swept packages ("your box" in `recovery/choice.go`, "AgentOS project" is fine); a wording sweep with the UX lens, no new check; includes mixed voice such as the card recovery sheet ("restores your box … I cannot print this again", L3 on #462) |
| CH-21c f4 | L3 on #462: `grants/resume.go` `pausedBy` shows the owner "Paused by Loop 2", naming an internal part (CH-12); predates #462 |
| CH-21c f5 | UX lens on #462: the vault fallback "I refused that. Try again." (`localui/vault.go`) gives no reason; the reason was missing before #462 too |
| OSS-10w2 f6 | UX on #402: the follow-refused text "Not asked: I refused this request." gives no next step (CH-12); it predates #402 |
| W5a-resume f1 | L3 on #381: no committed test covers restart; a legacy pause-less resume replaying and `Pause`/`PausedBy` rebuilt from the journal were shown only by a scratch test. The next package that touches grants adds it |
| W5a-resume f2 | UX on #381: the Approvals line shows the raw pause intent ID (e.g. `loop2/pause/3fa9…`); keep it in Detail for the binding, but show the pause time or put the ID on a muted line |
| SR2-3j f2 | Security on #396 delta: the guest text for a void approval, "a wrong code was given too many times", is passive and does not say whose code |
| SR2-3n f1 | L3 point 2 on #466: no test bounds a guest that holds its stderr pipe open after runsc exits 0; only the context-deadline path is exercised. Add a fake-runsc mode that leaves `sleep 30 >&4 &` behind and assert Exec returns within `ExecWaitDelay` with the guest's output |
| W3-forget-b1 f1 | L3 on #409: a forget log long enough to need 100+ copies or segments has no tested path; F4's notices assume one log file per destination (broker/recovery/ASSUMPTIONS.md F4) |
| W3-forget-b1 f2 | L3 on #409: forgets made before the counter's anchor (a box with no TPM, or provisioned without Box.Counter) are only as fresh as the newest copy found (broker/recovery/ASSUMPTIONS.md F3) |
| OSS-6s-a f1 | L3 on #411: `pubsend.New` reads the ledger with an unbounded `os.ReadFile` before `validate`; the directory is owner-only, so this is hardening; cap the read at about `MaxWaiting`×2×`FrameSize` |
| OSS-6s-a f2 | Potency on #411: P10 lowers `MaxPayload` to 261,116 bytes (m = 4) and nothing records that the planned producers fit (clean-room artifacts C13 K2, OSS-8 attestations); add one line to P10 or OSS-6m with their expected sizes |
| OSS-6s-a f3 | UX on #411: in Release, a signed item over `SignerOverhead` is counted in the "could not be signed" error; harmless while the caller is a broker timer, so give it its own reason when W6 lands |
| OSS-6s-a f4 | Security on #411 (re-sign): a PR's Findings line should name the LATER rows its delta removes (the `OSS-6s-a age bound` row was struck outside the brief's scope) |
| W5a-resume f3 | UX on #381: a gate refusal other than "pause changed" shows the "isn't answering" text, which names the wrong cause; reload still works as the next step |
| W5a-resume f4 | UX on #381: the paused-grant card heading is the bare grant ID; lead with what the grant does (the `What` line) and keep the ID second |
| W5a-resume f5 | Security record on #381 (point 1 in its record, unlabeled in the comment): `localsrv.askResume` checks the token inline instead of through `s.authed`; equivalent today, but a later check added to `authed` would miss it; fold it in when the file is next touched |
| W3-forget-b1 f3 | Security on #409 L1: destination forget-log copies are plaintext (goal IDs, forget times, take-back flags readable by the destination); consider AEAD under its own HKDF label |
| W3-forget-b1 f4 | Security on #409 L2: `readRestoredForgets` trusts `forget-log.json` without authentication at every start; low risk, only agentosd's uid can write it |
| W3-forget-b1 f5 | Security on #409 L3: the test "copy holds its key" looks for the key's hex but JSON stores `[]byte` as base64, and the copy has no key field, so the assertion is vacuous |
| W3-forget-b1 f6 | UX on #409 U4 and P4: the taken-back text reaches 161 chars at 100+ things undone; and the BOARD row should say "not live until b1-5/6/7" |
| CRED-5f l1 | Combined lens on #420: a withdrawn route's decline says "not granted" (403 `no_route`); CAP-9 wants the reason. The owner already learns it from the withdrawal notice, so only the agent-facing text is vague |
| CRED-5f l2 | Combined lens on #420 (L3 later point): `CredentialRejected`'s 24 h re-notice compares wall-clock times, so a clock step back can delay it; the new withdrawal notice is once per withdrawal and is unaffected |
| CRED-5f l3 | Combined lens on #420: if CRED-5w's owner pause reuses `Config.Withdrawn`, the owner gets a withdrawal notice for their own pause; give the pause its own reason |
| SR3-5 u2 | UX on #424 point 2: `ErrValidity`'s text ends "resolve it again", an instruction for the agent or gate; word it for the owner before mail evidence reaches an owner surface |
| SR3-5 p1 | Potency on #424 point 1: undo skips flag changes recorded under an older UID validity even when the Message-ID matches, so a provider rebuild makes a digest's label changes un-undoable; the watcher's identity digest (M12) could re-identify the message |
| W3-forget-b2c l1 | UX on #427: with no agent, "when it runs again" means the next boot (the agent machine opens only at boot); STATUS's agent line should name that step |
| W3-forget-b2c l2 | UX on #427: an owed take-back is journaled `succeeded` with evidence `owed: …`; once the digest renders journal outcomes it must not read as done |
| SR3-2 l1 | UX/Potency on #428 (L3 later point): an authorized intent that never dispatches (held, no executor, fenced) holds its bound place with no age-out; note it in GR31 and let STATUS show it |
| SR3-2 l2 | Security on #428, point 2: GR7 ("under a bound of 1 the second is asked") overstates, since concurrent `Authorize` calls are not seq-checked and both can be authorized, the second being refused at the dispatch recheck. Safe. Next time GR7 changes, add "or, if both are authorized at once, refused at the recheck" |
| P2-2a f3 l1 | UX on #423, point 2: an owner who never answers is asked again at every check; after a few lapses the ask could move to the daily digest only (UPD-5) |
| P2-2a f3 l2 | Potency on #423, point 1: the lapse record is in memory only; persist it with proposals (C9, potency PM4). No release is stranded meanwhile, since Loop 3 re-asks after a restart |
| SR3-1 f3 | UX on #431: a RESUME refused by a lock race shows "RESUME failed to record. Still stopped."; map `ErrUnauthorized` on /resume to the unlock page, as Approvals and Paused do (CH-11, CH-12). Also L3: the refresh-path check `locks != ses.locks` at `localsrv.go:285` is untested and redundant with `LocalResume`'s commit-point check; remove it or comment it as belt and braces. #431's PR body wrongly says reverting the localsrv read also fails the refresh test |
| SR3-4 l1 | L3 on #434: a pre-PR rollback point without `ToManifest`, cut after `staged.json` was removed, gets stuck in CommitRelease (a nil exposure while the applier is unwired) |
| SR3-4 l4 | Delta L3 on #434, A: update the Revisit column of `broker/apply/ASSUMPTIONS.md` A9, and fix `abandonLocked`'s doc comment ("stays pending" is false on the `ErrPolicyMoved` path: Pending is cleared in memory, and only Tick's Resume or New's reset on load persists it) |
| SR3-4 l5 | Delta L3 on #434, B: pin the Pending reset in `New()` (`apply.go` near line 241) with a restart test; a mutation that removes it survives |
| SR3-4 l6 | UX on #434: name the ID the owner sent (`UNDO <short ID>`), or both, in the refusal text instead of only the release version. The signed UX and Potency records for #434 keep IDs A9, C25 and U16 (head 215deae); they were renumbered A10, C27 and U17 on merge |
| SR3-6 l1 | Potency on #430, W5b wiring: a pending security fix dropped by a policy change and scheduled again by Loop 3 should keep its first-scheduled time for A7's 24-hour "no free moment" ask, so a policy change does not reset the clock |
| SR3-7 l1 | L3 on #429: nested keys still last-win; an `n` check in `anthropic.go` is unreachable |
| SR3-8 l5 | UX on #432: repeated "lost its output N times; not built again" points at failing storage; if a box-health line ever reads disk faults, this log is one input |
| W3-forget-b3 rr8 | UX on #425, point 1 (CAP-3, F3): a crash after the owner's YES and before the tombstone saves ends silently; reconcile marks the intent not applied and the owed entry is dropped untold. The owed file holds the date, so "Your task from <date> was not forgotten. Send FORGET to try again." would close it. Pre-existing, narrow window |
| W3-forget-b3 rr9 | UX on #425, point 2: several owed texts after one restart go as separate texts; if forgets are ever owed in bulk, send one text listing the dates |
| W3-forget-b3r l1 | L3 on #481: repeated POSTs for one goal submit repeated forget requests, as repeated texted `FORGET n` do; consider one open request per goal |
| SEC-record-format | Security records: #443 puts `Verdict` on line 1 above the title while other security records put the title first; pick one and add a doclint rule |
| SR3-8 l1 | L3 re-review on #432, point 1: once `CR-quarantine-prune` is on main, add to it that any pruning of `.quarantine` must keep the per-artifact loss count (e.g. a count file), since C14's `maxRepairs` bound is counted from the copies; fold this line into that row |
| SR3-8 l2 | L3 re-review on #432, point 2: a job stopped by the repair bound is logged `failed: no result within the allowed attempts`; only the log line says its output was lost repeatedly. Text only |
| SR3-8 l3 | L3 re-review on #432, point 3: no test pins the `<id>-<12 hex>` name check in `Store.losses`; a bare prefix match passes every test. Unreachable today (fixed-length broker-written IDs) |
| W3-forget-b1-4 l1 | L3 on #436: `broker/change` TestRouterCandidateAdoptsThroughPipeline flakes (~2/10k; random split key); fix is a seeded Rand, proposed on #436 |
| W3-forget-b1-4 l2 | #436: decoy dates may fall before box setup or enrolment |
| W3-forget-b1-4 l3 | #436: "Never" wording for owners whose forgets predate the log |
| W3-forget-b1-4 l4 | Security on #436: the derived decoy key is not wiped from memory |
| W3-forget-b1-4 l5 | #436 (ASSUMPTIONS Q1): leftover decoy variance across different stale backups |
| W3-forget-b1-4 l6 | UX on #436: a shorter "replies" line in the confirmation text |
| W3-forget-b1-4 l7 | Potency on #436 (considered, not proposed): an accept-and-re-forget flow |
| W3-forget-b1-4 l9 | UX on #436 (point 3): reword the forget-log-missing question ("Since this backup on <date>, …") once W3-forget-b1-6 has the missing case carry an authentic copy (coordinator, 2026-10-09) |
| OP9-status l2 | L3 on #416: give held-back fields values distinct from the finding's free text |
| P3-4b-1 l1 | L3 on #464 (agreed with builder): LOOP-3's "unmeasured" state resets on every daemon restart; the brief keeps restart behavior unchanged (scheduler.go:153) |
| P3-4b-1 l3 | Security 5 on #464: `loopKeys` lists exact paths no tree file or reader uses yet; when a reader of `config/loops.json` or `config/loop2.json` lands it must read exactly those keys, with a test tying the list to the reader |
| P3-4b-1 l5 | UX on #464: text the owner when a reported finding's fix is adopted, as a passive finding's clearing is texted (secure.go:409-410), so the owner who was texted "Paused grant Y" learns it is safe to resume; P3-4b-1b item 1 texts the cleared close once, and this line is the same text for an adopted fix, so use one wording for both |
| P3-4b-1 l6 | UX on #464: "I cannot build one yet" does not say whether anything will ever fix the finding; say "no repair is set up on this box yet; an update may bring one" when OP9-status writes its owner lines |
| P3-4b-1 l7 | UX on #464: LOOP-0 line "check myself against known problems and repair what I can, and check for updates" says "check" twice and "repair" is true only once a fixer is wired; reword when P3-4b-5 lands ("check myself against known problems, repair what I can, and look for updates") |
| P3-4b-1 l8 | UX on #464: a partial line followed by a wait line repeats the prefix ("Loop 2: partial (…). Loop 2: 1 finding waits…"); join them under one "Loop 2:" when STATUS wording is next touched |
| P3-4b-1b l1 | Security 2 on #493: the clear check (`LinkedHold`) and the close in `Pass` are not atomic; impact is bounded (the pause and cases stay) and a re-report reopens the finding |
| P3-4b-1b l2 | L3 on #493: a crash between the owner send and the `Told` save re-sends the owner text (at least once, S21) |
| P3-4b-1b l3 | UX 2 on #493: no cleared text for a finding that was capped but not paused; take it with P3-4b-1 l5 (same text) |
| P3-4b-1b l4 | Potency 4 on #493 (A11): when the K-S1 row makes plain config probes live, its brief should recheck that the A11 config seeds still qualify on a box with live plain probes, and take S22's lift if not |
| P3-4b-5 l1 | #493 item on P3-4b-5: a reported finding that cannot link is re-linked every pass (S21); it costs a case add, never a fixer call, and S31 removed the permanent case, so the fix retry bound (loops S48) does not cover it |
| P3-4b-5 l2 | UX later on #575: the new loop 2 wait lines are not in the wording or GSM-7 scan, and `FixHold` is recomputed only on `Pass`, so STATUS can show a stale hold between passes |
| P3-4b-5 l3 | Security later on #575: a builder machine that will not start (`ErrMachineUp`) counts toward the fix cap and nothing resets it; `FixPreempted` is not counted; the loops S48 cap and the "apart from Loop 1" share wording hold for tokens only (the builder slot is shared) |
| SR3-1 f1 | Builder on SR3-1: page deny (`LocalAnswer`), follow and ask-resume check the lock count at the token check only, not where they commit; deny only narrows and the other two only open a request that needs a code, so the race gains no authority. Also (Security re-sign on #444, R3): adopt-SIM checks the lock count after the code, not where `AdoptSIM` writes the roles file; closing that gap would take a lock-count argument on `AdoptSIM`, as `LocalResume` has, and it gains nothing, because a strong code lifts locks |
| SR3-1 f2 | Builder on SR3-1: a sign-in overlapped by a lock still returns a token, dead on first use; answering with a refusal instead would save the page one round trip |
| W3-forget-b1-7 a | A held box serves no local page (localui.sock), so the page shows nothing while a restore is held; the owner learns of it by text only (broker/cmd/agentosd ASSUMPTIONS H1) |
| W3-forget-b1-7 b | A held release from the inbox whose confirmation Send fails is only logged before the hold is released; retry with bounded backoff first (#487 L3 point 2) |
| W3-forget-b1-7 c | opening() builds the question text under the lock but sends it outside, so a stale question can follow a released reply on "message" (#487 L3 point 3) |
| W3-forget-b1-6 l8 | L3 delta on #519, point C: if Mark's ruling on b1-6 open question 1 rewords `PendingNotice(PendingUnanchored)` (the anchor fallback makes "Restoring on your original PC still works" false there), the brief must state the CH-12 bound (GSM-7, at most three segments), or `heldNotice` silently falls back to `heldFallback` |
| P3-4b-2 l1 | #490: the invalid-seed control assumes seed 0's first clause is padding; derive the padding from the seed when the catalog changes |
| P3-4b-2 l2 | #490: the assurance/loop2 assumptions sit in the README, not ASSUMPTIONS.md (OPERATING §5); move them when the README is next touched |
| P3-4b-2 l3 | Security 3 on #490 (H-4): leaks of single array elements and non-canonical JSON escapes (`\/`, `\u0063`) go undetected; verbatim and canonical only |
| P3-4b-2 l4 | UX 1 on #490: assurance/README.md says a seeded defect is "found"; say "reported" when next touched (LOOP-3 item 8) |
| P3-4b-2 l5 | UX 2 on #490: `run.py` sets `GOTOOLCHAIN=local`, so an older local Go stops with a go.mod error; add a README line naming the toolchain or `GOTOOLCHAIN=auto` |
| P3-4b-2 l6 | Potency 2 on #490: no seed in `routing/` or `skills/`; add a routing seed when the catalog is next extended |
| P3-4b-2 l7 | Potency 3 on #490: `--all` and `--pick` each rebuild and rerun both controls; one invocation that records a pick would halve the CI step |
| P3-1-rand | `broker/change`: no test asserts that `change.New` draws a fresh 32-byte split key from crypto/rand when `Config.Rand` is nil, or that two fresh pipelines get different keys. Raised by L3 (#491 comment 6073134807) and Security |
| P3-1-envkey | `broker/change/env_test.go`: `newEnv`'s pinned key is a single `bytes.Reader`, so a second fresh-state pipeline opened with the same cfg would hit EOF. No test does this today (Potency on #491) |
| P3-4b-2b-held | Fix-input audit (Security #500 1): a held array/object value leaked alone in non-canonical layout passes the audit; H-4's wording needs updating |
| P3-4b-2b-ctrl | A11 leaking-adapter control (Security #500 2): accepts any audit hit, not only a `held/` hit |
| P3-4b-4a corpora | Only PromptInject (10 items) is vendored: the larger published injection sets on Hugging Face are unreachable from the build environment (403); vendor one when a session can fetch it |
| P3-4b-4a shape | Vendor the next injection set for shape (obfuscated, multilingual, long indirect), not size; the 10 PromptInject items are near-equivalent English wrappers (Potency 1 on #515) |
| P3-4b-4a rule-less | Open question: rule-less probe findings get no §11 fix request (S23); the pause plus the probe's next clean run is the exit (UX 4, Potency 5 on #515) |
| P3-4b-4a canary-trust | L3 on #515: a clean canary round inherits A5's trust in the surfaces the target hands back; a compromised guest could curate a copied `sweep` dump. Record an S-row when a guest-sweep target is registered for rounds |
| SR2-3q f1 | Security 4a on #463 (fail-open drift): `notRun` reads urpc's `urpc method %q failed` text to tell a lost ExecuteAsync reply from a pre-start error; if a runsc upgrade rewords it, that reply reads as NotStarted ("retry it") and CI stays green because the fixture copies the text. When the runsc pin next changes, add a check against the format string at the pinned tag |
| SR2-3q f2 | L3 on #463 point 1 (V33 gaps; UX lens, same item): a non-UTF-8 `argv[0]` or an unusual PATH dir still reads as a failure that advises a retry, though the command can never run; classify it as NoProgram when the text is next touched |
| SR2-3q f3 | L3 on #463 point 1: re-read the runsc error prefixes (`loading container failed:`, `parsing process spec:`, `executing processes for container:`) against the new tag on the next pin bump (V33/V20) |
| SR2-3q f4 | L3 on #463 point 2: `fakerunsc.sh` has no case for the raw (unwrapped) urpc send failure, which classifies as NotStarted; add one so a later runsc that wraps send errors fails a test |
| SR2-3q f5 | UX lens on #463: `ErrExecFailed`'s text says "after the command started" where the start is unknown; the advice is right, only the claim overstates, so reword it the next time the text is touched |
| W3-forget-b1-7 d | L3 re-review of #487, point 1: a request `sockets.serve` reads just as the server stops can lose the race for the connection mutex; `handle` still runs the handler with a cancelled ctx, so its effect happens with no reply. Skip the request when `ctx.Err() != nil` |
| W3-forget-b1-7 e | UX 2 and Potency 1 on #487 (CH-12, C3): the held box texts once per start and then only answers; send a reminder after a day |
| W3-forget-b1-7 f | UX 3 on #487 (CH-2, CH-11): STOP and STATUS get the held question back, which does not say the agent is stopped; prefix "Your agent is stopped." |
| W3-forget-b1-7 g | UX 4 on #487 (wording): "restore this backup again to answer again" says "again" twice |
| W3-forget-b1-7 h | UX 5 on #487 (lens README): the CH-12 held-text check only matches phrasings in `heldSteps`; say so in the reviews/ux/README.md row |
| SR2-3n f2 | UX 1 on #466 (CAP-8): when the guest's stderr is still held open past `ExecWaitDelay`, the read deadline cuts it and the result says `truncated: false`; set the flag when the copy ends on the deadline (reads best with SR2-3n f1, which is on #466's branch only; this line stands alone) |
| SR2-3n f3 | Security 4a on #466: on a normal result, anything runsc wrote to its own stderr is discarded rather than logged; nothing leaks, only diagnostics are lost |
| W3-forget-b3r l2 | L3 accept on #481, point 1: the `forget.go` comment at :224 cites CH-21 for the unlock rule; the cite is CH-3 (CH-21 is "Name and voice"). Fix it when a build touches that file |
| W3-forget-b3r l3 | L3 accept on #481, point 2: the BOARD `W3-forget-b3` row says "in review (#425)" although #425 is merged; the coordinator corrects it |
| DEP-2-join | depaudit `_inner` snapshots the trace after `join(10)`/`join(2)` without checking `is_alive()`; a live reader should make the attempt `error` (fail-closed). strace has exited by then, so a truncated trace is unlikely (L3 on #437 point 4) |
| DEP-2-otattr | depaudit: `open_tree_attr` (syscall 467) needs Linux 6.15+; on an older kernel it returns ENOSYS, so only the `mount_setattr` half of `control-kept-read-only` bites there. `setpriv`'s CAP_SYS_ADMIN drop still covers both (Security re-sign on #437, L1) |
| DEP-2-nestns | depaudit: no test covers D8's claim that a nested user namespace cannot clear the read-only flag because copied mounts are locked (MNT_LOCK_READONLY) (Security re-sign on #437, L2) |
| DEP-4-prop | depaudit: mount propagation in the sandbox is private only by util-linux `unshare -m`'s default; pass `--propagation private` in `_unshare_flags()` (or `mount --make-rprivate /` in `_inner`) and state it in ASSUMPTIONS D10, so no mount can arrive under a kept path after the DEP-4a check (L3 on #552 point 2; Security 4a on #552 point 1: one `MS_PRIVATE` in `_set_read_only`'s propagation field) |
| DEP-4-topo | depaudit: judge each `rw` mountinfo entry by whether a visible child entry covers it (parent-id topology) instead of `statvfs` + ENOENT, removing the hidden-entry rule's dependence on path lookup (D10 fallback; L3 on #552 point 3) |
| DEP-4-ctl | depaudit: the in-scenario half of `control-kept-read-only` leaves `dirname(sys.executable)` out of `ro_kept` and does not `realpath` `DEPAUDIT_KEEP_RO`, so it covers less than `_inner`'s check; only the control's evidence is weaker (Security 4a on #552 point 2) |
| DEP-4-strace1 | depaudit: `sandbox_available()` and `_inner` look strace up on different PATHs (`_inner` after masking `/home`, `/root`, `/tmp`), so the probe can vet a different binary than the run uses; silent only for aarch64 `_ABSENT` names. Resolve strace once and pass the absolute path to both (Security 4a on #552 point 3) |
| DEP-4-compat | depaudit: no control shows a compat-ABI call is traced (a 64-bit process calling `connect` via `int 0x80`, i386 `socketcall` or numbers); DEP-4b proves strace knows each name, not that it catches every ABI entry (Security 4a on #552 point 4; predates DEP-4) |
| DEP-4-erofs | depaudit: the first half of `test_a_submount_of_a_kept_path_is_read_only` accepts `outcome == "error"` for any cause, so it does not pin `mount_setattr` (dropping `AT_RECURSIVE` is caught only by the control half); pin the EROFS branch (lens Potency on #552 point 4) |
| DEP-3 l1 | depaudit: the scenario can hard-link an unmapped-owner file into `tmp/`, so the lchown back to 0 raises and the verdict becomes `error` (fails closed, but a target can DoS its own verdict; `fs.protected_hardlinks=1` limits it); skip `st_nlink > 1`/foreign-owner entries or report EPERM as a finding (L3 on #562 point 2) |
| DEP-3 l2 | depaudit: trace lines that do not parse are skipped; fail closed on them (a second layer behind the DEP-3 uid boundary) (L3 on #562 point 3, builder finding on #562) |
| DEP-3 l3 | depaudit: no `IdMapTest` case for a subordinate count of 0, so `_subordinate`'s `>= 1` guard is uncovered (newuidmap refuses it anyway) (L3 on #562 point 4) |
| DEP-3 l4 | depaudit: `writes` paths keep files owned by the scenario's subordinate id, persisting across targets that share it; not a regression (all shared the runner uid before DEP-3) (Security 4a on #562 point 7) |
| DEP-3 l5 | depaudit: the runner's first subordinate range may be shared with rootless containers on the same host (ASSUMPTIONS D13) (Security 4a on #562 point 8) |
| DEP-3 l6 | depaudit: a chown back that fails partway leaves files owned by the subordinate id; error path only, verdict already fails closed (Security 4a on #562 point 9) |
| DEP-3 l8 | depaudit: the probe-failure FAIL line still prints `TRACED` for every probe failure (a newuidmap that refuses the range too); print it only when the stderr tail contains `invalid system call` (lens on #562 UX 4, narrowed by DEP-6d; L3 on #568 point 3) |
| DEP-3 l9 | depaudit: the probe-failure FAIL line has no `tools/ASSUMPTIONS.md D13` pointer, though a newuidmap or newgidmap that rejects the range is the D13 case; only the no-range cause has it (lens on #562 UX 5, narrowed by DEP-6e; L3 on #568 point 4) |
| DEP-3 l10 | depaudit: `control-evidence-channels` tries the three channels the brief names, not the whole `ptrace_may_access` gate: add `/proc/1/mem`, `process_vm_writev` and `pidfd_getfd` on PID 1 (lens on #562 Potency 6) |
| DEP-3 l11 | depaudit: `_evidence_fds()` falls back to `range(64)` once `/proc/1/fd` is closed, so the control never shows the tried fds include the trace pipe; add a positive run (caps back) that can open them (lens on #562 Potency 7) |
| DEP-3 l12 | depaudit: `test_the_evidence_channels_are_closed_by_uid_alone` skips silently without the sandbox; check in the `dependency-audit` log that it ran (lens on #562 Potency 8) |
| DEP-6 l1 | process: #568 edited LATER.md and BOARD's DEP-3 row, outside the brief's declared scope (BOARD DEP-6a–e only), on the coordinator's instruction; briefs should list the records a package must touch (L3 on #568 point 5) |
| DEP-6 l2 | tools: brief-local IDs (DEP-6a…) cannot carry `REQ:` markers because `trace.py` rejects IDs SPEC does not bold, and package IDs share the `DEP-n` namespace with SPEC DEP-1–4; add a `LOCAL:` marker that trace.py checks against `briefs/*.md` without counting it (L3 on #568 point 6) |
| DEP-7 l1 | briefs/DEP-7.md: the DEP-7e rationale names `_map_text` for the uncaught `TypeError` under the `or` → `and` mutant; it is `_unshare_flags` (`"--map-groups=%d:%d:%d" % gid_map[1]`, reached from `sandbox_available()`), checked building DEP-7; correct the brief text (L3 on #567 delta, builder check on DEP-7) |
| DEP-7 l2 | tests/test_depaudit.py: `_evidence_channels`' fallback for a non-strace parent (`… not strace: its stderr and signals were not tried`) has no behavioural test; add one with a mocked `getppid`/comm (L3 on #577, comment 6078709076, point 1) |
| DEP-7 l3 | tests/test_depaudit.py: `HandBackTest`'s module scan reads `c.args[1]`, so a `_chown_tree(path, uid=…)` keyword call raises IndexError; check `keywords` too (L3 on #577, comment 6078709076, point 2) |
| DEP-7 l4 | tests/test_depaudit.py: `assert_both_connects_logged` checks `events == 2`, which assumes the control makes no other call in TRACED; revisit if TRACED grows (L3 on #577, comment 6078709076, point 3) |
| DEP-7 l5 | tools/ASSUMPTIONS.md D9 (DEP-7b): in the uid-alone case the stderr open is refused first by `/proc/<strace>/fd`'s 0500 directory DAC (`proc_fd_permission`), not `ptrace_may_access`, which refuses only in the uid-0 cap-drop case; reword D9 to name the gate that holds (Security 4a on #577, comment 6078712147, point 1) |
| DEP-7 l6 | tools/depaudit.py `_subordinate`: `isdigit()` accepts non-ASCII digits, so `'²'` crashes with a ValueError traceback (fails closed, not cleanly); folded into DEP-8, whose DEP-8c strict parse (ASCII digits only, any other line refuses the range) on #576 covers it (Security 4a on #577, comment 6078712147, point 3) |
| DEP-7 l7 | tests/test_depaudit.py: `test_the_control_runs_them_on_its_strace_parent` greps source for `_tracer_channels(` and `os.getppid()`, which a comment satisfies; replace it with an `ast` check like 7g's, or drop it since the CI mutant covers it (UX/Potency on #577, comment 6078726537, point 1) |
| DEP-7 l8 | tests/test_depaudit.py: the message in `test_inner_hands_back_only_through_the_helper` ("_inner calls _hand_back only under a condition") says the opposite of its assertion; correct it (UX/Potency on #577, comment 6078726537, point 2) |
| DEP-7 l9 | process: LATER.md edited outside the brief's declared scope on a second PR (DEP-6 l1 on #568, then DEP-7 on #577); either briefs list the records a package must touch (as DEP-6 l1 proposes) or CI gets a scope check in the next package that touches this area (UX/Potency on #577, comment 6078726537, point 3) |
| DEP-7 l10 | tools/depaudit.py: the control FAIL lines for DEP-7b–d carry no remedy; add a pointer such as "AS_SCENARIO must setresuid and set PR_SET_NO_NEW_PRIVS; see tools/ASSUMPTIONS D9" (UX/Potency on #577, comment 6078726537, point 4) |
| DEP-6 l3 | depaudit: `_tail` keeps ESC and other C0 control characters, so ANSI sequences could rewrite a terminal line; only trusted host binaries write that stderr today: `re.sub(r"[\x00-\x1f\x7f]", "?", …)` (Security 4a on #568 point 3) |
| DEP-6 l4 | depaudit: no test drives a line over 500 characters through `_tail`, so dropping the DEP-6d cap survives (Security 4a on #568 point 4) |
| DEP-6 l5 | depaudit: the pre-5.12 FAIL line does not print `os.uname().release` and does not say a seccomp filter answering ENOSYS gives the same line (lens on #568 UX 1) |
| DEP-6 l6 | depaudit: the DEP-6e rw-mount remedy does not say where the keep entry lives (the target's `keep` in the targets file) or what "bind it read-only" means for an operator outside the sandbox (lens on #568 UX 2) |
| DEP-6 l7 | depaudit: the `mount_setattr` refusal prints `str(OSError)`, which adds `[Errno 1]` to text already naming EPERM; print `e.strerror` (lens on #568 UX 3) |
| DEP-6 l8 | depaudit: the missing-binary remedy hard-codes `apt-get install`, right only on Debian and Ubuntu hosts (lens on #568 UX 4) |
| DEP-6 l9 | depaudit: per-target `detail` opens with `sandbox exit 1, no single result line` before the actionable line, reading like a harness bug; predates DEP-6 (lens on #568 UX 5) |
| DEP-6 l10 | depaudit: no real-strace test on x86_64 shows strace skips an unknown `?`-prefixed name and exits 0 (D12), which the aarch64 branch rests on; run `strace -e trace=?nosuchcall,connect true` (exit 0) and without `?` (nonzero) (lens on #568 Potency 6) |
| DEP-6 l11 | depaudit: `test_a_missing_subordinate_range_is_named_with_its_remedy` skips silently on a host without `uidmap`; a CI grep for the test name would catch an image that loses it (lens on #568 Potency 7) |
| DEP-6 l12 | depaudit: the stderr → `detail` link for the `mount_setattr` refusal has no test of its own; `SubmountTest` covers the same path for the rw message, so none is needed unless that path changes (lens on #568 Potency 8) |
| DEP-6 l13 | ci: assurance.yml adds the fixed range 100000-165535 when the runner has none; acceptable on an ephemeral single-tenant runner, where 100000 is `useradd`'s default `SUB_UID_MIN`, but it shares ids if that step is copied to a shared host (builder finding; Security re-sign on #568, later) |
| DEP-6 l14 | depaudit: `test_the_kept_read_only_control_uses_it` pins `_control`'s `kept_rw_mounts` call by source text only: a mutant passing `[]` for `ro_kept` survives, and nothing shows a kept rw mount reaches `wrong`; drive `_control`'s mount half with a patched `kept_rw_mounts` result or a planted rw submount under `DEPAUDIT_KEEP_RO` (L3 delta on #568 point 1; Security re-sign on #568 point 3) |
| W3-forget-b3r-lockedtext | UX on #522: the locked text ("Your session is locked ... Unlock it with a code first.", on the page and as `forgetPageLocked`) names a step with no path to it; the Second line page says "I am locked ... Unlock me" with a link to `/unlock/vault`, and the owner's own word is "locked", not "session". Reuse that wording and link, paired with a test of the `TestHeldOwnerTextsNameOnlyStepsThatWork` kind in the next package that touches owner page texts |
| W3-forget-b3r-askedtask | UX on #522: the reply to "Ask to forget" does not name which task was asked, and the list comes back unchanged with the same button, so a second press files a second request and a second text to the owner (a texted `FORGET n` repeated does the same); the effect is a duplicate approval, not data loss. Name the label in the reply, or mark a task as asked until the request resolves; it changes owner wording, so it belongs to a later owner-text package (Security 4a on #522, point 2, says the same: harmless, since each request needs a code; a later page package could show "already asked" for a goal with a Pending forget) |
| W3-forget-b3r-deeper | Potency on #522: the page lists `recent(forgetList)`, five tasks, as the brief requires, so an older task still cannot be forgotten from the page or by text (R2 says "older tasks"); lifting it means a deeper `recent(n)` and a paged list, with the ask check (P2) and the texted `FORGET n` list kept equal. Security cost: a longer label list on shared Wi-Fi after sign-in |
| W3-forget-b3r-label | Potency on #522: a task the owner did not text shows only "(a task, <time>)" (security C2), so for tasks from other channels the page cannot say what it would forget and the owner picks by time alone; any richer label is a security-lens change (agentosd P4); a UX-side proposal is a fixed label by origin (for example "(a voice task, <time>)"), if the task records its channel |
| W3-forget-b3r | L3 on #522: `localapi.ForgetTask.Date` is sent but the template never shows it; the label already carries the time, so the field is unused. Either drop it or show it (Security 4a on #522, point 1, says the same) |
| W3-forget-b3r-scope | L3 on #522 (brief-gap, process): the b3r brief's Scope omitted the `localapi` and `daemon` wiring, which any new page op needs; future briefs for a page op should list `broker/localapi/` and `broker/daemon/daemon.go` PageSocket wiring |
| P2-1 watchdog | L3 on #41 (UPD-1): a boot that hangs with no kernel panic and no failed unit never reaches a reboot; a hardware watchdog (`RuntimeWatchdogSec=` on the N95's iTCO timer) closes it. Panics, failed units and emergency or rescue mode already reboot |
| P2-1 unblessed | Fourth L3 on #41 (UPD-1): two unblessed `+0` entries make the fallback reboot between them forever, since each counts the other as an earlier release. Fix in the update package (refuse to stage on an unblessed boot) or count only blessed or tries-left entries. An initrd failure on a blessed or single-release `+0` entry also reboot-loops (image/ASSUMPTIONS.md I4) |
| P3-4b-3 l2 | Security 4 on #523: `ErrPeer` on a guest socket is journaled under that machine's ID, though the peer was another host process; coalesced, harmless; note the attribution in B19's row |
| P3-4b-3 l4 | Security 6 on #523 (LOOP-7): the broker-side probe check is per code, not per frame; give each fixed frame a distinct code or a broker-known frame token in the refusal note when LOOP-7 next touches `sockprobe` |
| P3-4b-3 l5 | Potency 5 on #523: `Resolve`'s replay gate is tautological for probes (the source builds `Replay` from the open finding); add a probe digest or round ID to the evidence if another caller appears |
| P3-4b-3 l6 | Potency 6 on #523: a probe finding for a machine never probed again (retired, renamed) stays open; add a staleness line to the digest when the source is wired |
| H6 | #561: `KeyError`/`AttributeError` raised instead of `ValueError`; column naming; `trace.py` A10 regex; the PR's Findings line said "None" |
| CI-SOAK-f1 | #563: no exactly-at-cap test |
| H8 | #564: the `devA != devB` check can't fail; only the 12-case fixture is guarded; replace before-variance with a 20k-env measurement |
| P3-4b-3a l1 | #560: stale `run-*` dirs; `FuzzMCP` 108-byte path test; 17 vs 16 binaries |
| P3-4b-3a l2 | #560: `eachInput`'s total time is outside the 1 m cap (about 3 min); exit 0 when `-test.run` matched nothing counts as pass; `eachInput` exit 0 without PASS |
| P3-4b-3a l3 | #560: a hang behind a FAIL goes unnamed; a slow corpus gives a sticky `noInput` false positive; a fuzz exit without "Failing input written to" only reaches `Logf` |
| P3-4b-3c l1 | #558: canary-clear after STOP; 3 UX nits; the once-per-name dedupe (`said` map) is untested |
| P3-4b-3c l2 | #558: a `runProbe` batch with a same-key clear and a paused finding can drop "stays paused"; weak pins (untexted open findings, key without `Check`); 3 surviving filter mutations |
| P3-4b-3c l3 | #558: S38 wording (STOP is also appended when paused; the Spec-basis column says only LOOP-9); S38's "owner can redefine" has no setting yet; pin the S39 wording |
| P3-4b-3 l7 | Potency 7 on #523 (P3-4b-4): the probe sends four fixed frames per socket and tests no connection limits, rapid reconnects or half-open frames; promoting good fuzz inputs to seeds is a later choice |
| P3-4b-3 l8 | UX 4 on #523: a fuzz finding whose corpus file is removed can never resolve, yet STATUS says it is rechecked; add a line to `broker/loop7/ASSUMPTIONS.md` when the source is wired |
| P3-4b-3 l9 | UX 5 on #523: a probe finding's ID derives from its `Detail`, so a different failure set next round is a second High text for one machine; cap or fold per subject when the probe text is reworded |
| P1-4-flake l1 | L3 1 on #547: the `ci.yml` comment and loop7 F8 say "about what 20s ran" (measured: 600000x took 6-20 s per target), and loop7 F6 still says "runs 20 s per CI run"; reword when the counts change (P1-4-flake-counts) |
| P1-4-flake l2 | L3 2 on #547: the fuzz deadline race is not specific to Go 1.26 (`stop` against `fuzzCtx.Err()` is long-standing); reword "Go 1.26's coordinator" in ci.yml and the brief. The "toolchain with the coordinator fixed" condition stays right |
| P1-4-flake l3 | L3 3 on #547: a count-bound fuzz run is capped only by `go test`'s default 10 m `-timeout`; an explicit per-step `-timeout` is the fix, and P1-4-flake-counts covers it, so this line closes with that row |
| P1-4-flake l4 | L3 4 and Security 4a 3 on #547 (pre-existing, since #391): a runsc crash at the deadline reaches callers as `TimedOut` with no output, not `ErrExecFailed`; the failure is visible only in `exec.log` |
| P1-4-flake l5 | Potency 3 on #547 classed the soak row (P1-4-flake-soak) `later`; it rides P1-4-flake-counts in one package (coordinator, 2026-10-09), so the "don't start later rows" audit reads clean (#580 L3 8) |
| P1-4-flake-crashed l1 | #580 L3 6: `panic_test.go` and V32/V34 cite RES-4 (storage reserve, per-machine quota), which links to them only through `exec.log`'s rotation bound; re-cite these tests the next time they are touched |
| P1-4-flake-crashed l2 | [#591 L3](https://github.com/ghbmrk/agentOS/pull/591#issuecomment-6079765306): the brief's `go test ./vm/gvisor -race -count=50` exceeds `go test`'s default 10 m `-timeout` (the package takes about 20 s a pass, so about 17 min), on main too; name `-timeout 60m` wherever that command is prescribed |
| P1-4-flake-crashed l3 | [#591 UX/Potency L-a](https://github.com/ghbmrk/agentOS/pull/591#issuecomment-6079780946): if stray runsc stderr lines on a normal exec turn out common at a pinned-runsc bump (P1-4-flake-runsc-recheck), give "finished, output withheld" a sentinel of its own rather than `ErrExecFailed` |
| P1-4-flake-crashed l4 | [#591 UX/Potency L-b](https://github.com/ghbmrk/agentOS/pull/591#issuecomment-6079780946): add `ctx.Err()` and whether the pid was written (started) to `logExec`'s header line, in the next package that touches `logExec` |
| W5-Da l1 | M11 on #555: `Finish` accepts `TransportAccepted` without an evidence reference; require one when the sender exists |
| W5-Da l2 | M3 on #555: the `Attempts >=` check in `Begin` repeats the `MaxAttempts` bound enforced in `Finish`; keep one |
| W5-Da l3 | #555: `Evidence` is an unauthenticated opaque string, and Forget keeps association hashes in the dedupe state; settle both in the retention policy |
| W5-Da l4 | #555: `change.FileStore.Load` treats a missing file as empty state, which resets Seq and the Latest ledger; a deleted queue file restarts the sequence |
| W5-Db l1 | L3 9 on #565: W5-Da-r1 to r4 stay `queued (folded into …)`; a `folded` board state, or removing folded rows, would keep BOARD queries from double-counting them |
| W5-Db l2 | L3 delta on #565: DC-4 says `capLines.add` puts a STATUS line under the `capLineTexts` wording test, but `capLineTexts()` (`capoff.go`) is a hand-kept list; W5-Dc appends its new constants there, and the brief should say so if edited again |
| W5-Db l3 | L3 delta on #565: W5-Dc covers only CH-15's "always sent" clause (pacing and quiet hours are W5-Dc-r1), but a `REQ: CH-15` marker shows CH-15 covered in TRACE.md; W5-Dc's PR states the partial coverage on its trace table |
| W5-Db l6 | L3 on #573: one marker in `digestqueue/resolve_test.go` reads `OP-1 (W5-Db DB-6), OP-1`, a harmless duplicate; tidy it when the file is next touched |
| W5-Db l7 | Lens on #573: `proven` turns a NotSent into Unknown when the ctx has ended, even with proof such as `not-queued` (the brief mandates it; errs safe); a shutdown during an outage makes a retryable batch unknown; revisit if the unknown line shows up often in the soak |
| W5-Db l8 | Lens potency on #573: the mutant where `proven` keeps evidence on a valid `OutcomeUnknown` survives; add `{OutcomeUnknown, "id-1"}` to the Send table and assert the stored `Evidence` is the item ID |
| W5-Db l9 | Lens on #573: `CodeRecipient` is unreachable in production today (`Link` always sets `LineOwner`; `at.Modem.Send` never returns `ErrNumber`); `TestSendReceiptRecipientIsNotSent` pins the defensive path only |
| W3-forget-b2c-f3 l1 | L3 point 3 on #553: with f3's early append the owed entry still has `Logged` false, so a crash during `retry` makes `finishOwed` append the same goal again at restart; the replay is idempotent (`forgotten.has`), the cost is a duplicate log entry, and the restart's done text gets the caveat tail (`forgetBackups`) though the early entry exists (understates; UX/Potency 1 on #559); the f3 builder records it in ASSUMPTIONS.md |
| W3-forget-b2c-f1 l1 | L3 delta on #553: the f1 brief still calls its lint "CH-12-lint" (F1-5, Sources); it should say UX-182-3-lint; reword when f1 next touches its brief |
| W3-forget-b2c-f3 l3 | UX/Potency 3 on #559: F3-3 hand-builds the restored log line and takes only `goal` and `at` from the fake, so nothing pins that the real appender's output for `logForget(goal, time.Time{}, false)` parses back through `readRestoredForgets`; add the round-trip with the real vault-written log in b1-5, where `forgetLog` stops being nil |
| W3-forget-b2c-f3 l4 | UX/Potency 4 on #559: no single test runs `retry` to a finished forget and then replays a restored backup; F3-1 and F3-3 each pin one half. Add the end-to-end case when this path is next touched |
| W3-forget-b2c-f3 l5 | Security 4a L1 on #559 (pre-existing, ASSUMPTIONS R1): on the done path the tombstone-to-append window spans `agentBackWithoutAsking` (a network take-back), not one write; a crash there plus a restore before the next start loses the forget. Append `agent=false` right after the tombstone and let the take-back's `agent=true` entry follow (replay is idempotent) |
| P3-4b-4b l1 | Security 4a 5 on #548: M3 ("only the test guest runs these scripts") is not enforced; add a test that fails when non-`testdata` broker code imports `machprobe` |
| P3-4b-4b l2 | Security 4a 6 and L3 threat check on #548: `TamperProbe` passes host paths (the broker's state layout) to the guest as argv; send only the `Guest` paths and `/proc/*/root` forms once 4c picks the real targets |
| P3-4b-4b l3 | Security 4a 7 on #548: `ExhaustProbe` has no destroy step; a production `Press` that creates a machine each round must destroy it, or preempted machines and pressure files pile up. Note it in the 4c brief |
| P3-4b-4d l1 | L3 4 on #556: every published PromptInject item has a space or newline, so through the plane the label check only ever exercises `labelClass`'s syntax rule and the configured-label rule is never decisive; add a single-token-item control if such a corpus is vendored |
| P3-4b-4d l2 | UX 1 on #556: check names such as "alert patterns" and "label check" read oddly in `findingText`'s "my <check>"; fold into P3-4b-3c's finding-text test |
| P3-4b-4d l3 | Security 2 on #556: the 30 s route deadline bounds only the guest run; add `cmd.WaitDelay` and ctx bounds on the gate and mailbox steps (a killed `runsc exec` client may leave /guest running); carry into P3-4b-4c's production `Relay` |
| P3-4b-4d l4 | Potency on #556: the archive control's discriminating power is unproven (mutants of `AlertWording`/`isAlert` fail at the clean run, not at the control); add a mutant the control alone kills |
| P3-4b-4d l5 | Potency on #556: the label route's stall under a permissive `labelClass` is bounded at 30 s but its cause (imapsmtp SetFlags) is undiagnosed |
| P3-4b-4d l6 | L3 on #556: a production `Relay` should report a route timeout as its own error class, not as a generic route failure; P3-4b-4c |
| P3-4b-4d l7 | L3 on #556: no test pins the `ok` check in the rig's `requested()` (relaxing it survives, since every replayed want is non-empty); add a guest that omits the key if a test needs it |
| P3-4b-4d l8 | L3 on #556: one over-long vendored corpus item fails every code-filter run (S45); P3-4b-4c decides whether to exclude it at vendoring or report it as its own finding |
| P3-4b-4b l4 | L3 5 and UX 2 on #548: the `cpu` finding reads "found no cpu limit" when the finding is "machine weight >= broker weight" (suggested: "an agent machine can take as much CPU as I can"); "I answered slower than my target" and "I stopped an agent machine slower than my target" give no consequence; one wording pass |
| P3-4b-4b l5 | L3 6 on #548: S34 should say a journal line means "unchanged after attempt", not "refused", since entries rest on the guest having tried |
| P3-4b-4b l6 | Security 4a and L3 deltas on #548: each round leaves one more `.agentos-tamper-<nonce>` marker file in a directory target that stays writable; bounded by rounds x targets while a High finding is open; cleanup is the owner's remediation |
| P3-4b-4b l7 | L3 delta on #548: `loops.tamperNonce` (regexp) in `machine.go` is used only by tests; move it to the test file or use it to check `newTamperNonce`'s output |
| P3-4b-4b l8 | Security 4a delta 1 on #548 (predates the fix; covered by release row P3-4b-4c-fresh): a probe guest that skips its scripted writes still closes an open tamper finding; if the probe image is ever shared with agent code, closing must need a broker-side write check (a canary the broker plants and verifies through the same mount) |
| SR3-5-f1 l1 | Delta L3 on #571 (comment 6078264771): a pin is never cleared for an intent that is denied or never dispatched; pins live in memory, so a restart drops them |

## Reuse candidates
| ID | Component | Why |
|---|---|---|
| CRED-4b, S5 | Playwright (Chromium over CDP) | Drives pages inside the sandbox; the narrow action protocol wraps it |
| ADP-5 | cage (Wayland kiosk compositor) | Single-app kiosk with no shell or file manager; add file-dialog confinement |
| HOST-1d | cryptsetup / LUKS2 | Vault-keyed disk encryption without custom crypto |
| SR2-4i | systemd resource control (IOWeight=, CPUWeight=) | Sets io.weight and cpu.weight per slice; add iocost QoS on the image |
| UPD-b | systemd-sysupdate (S7 stack) | First-boot update-before-trust already fits the chosen image stack |
