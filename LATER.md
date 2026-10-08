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
| S8-codex-terms | A3, CRED-5 (unsure) | Decides Codex custody; a Claude plan route may already satisfy A3 |
| CRED-5f | A3 (CAP-9), CRED-5 | Plan route withdrawn with no API key granted must still route or tell the owner |
| CRED-5t | CRED-1 invariant | Unswappable refresh response must fail closed; stop retrying on account restriction |
| CRED-5w | CRED-5 | Owner can pause a broker-held route before a withdrawing release |
| S1 | A1 (G1) | Test kit ready; waits on Mark's hardware |
| S2 | A1, A3 | Modem SMS and voice; waits on Mark's modems |
| P2-4-hw | A8 | Real-TPM trusted-host run; risk 14 |
| P3-4b-1 | A11 (LOOP-9, LOOP-10, LOOP-3) | Loop 2, given a seeded failing security test as a finding, contains it, adds a minimized regression and qualifies a fix; weakening fixes rejected (D-070) |
| P3-4b-2 | A11 | Qualification harness for A11's loop 2 clause: harness-chosen seed, held-back variants, scripted rejected fixes |
| P3-4b-5 | LOOP-9 | Model-backed loop 2 fixer answering the §11 fix-candidate request through Loop 1's builder; needs W3-builder-ship |
| OP9-status | A11 (OP-9) | STATUS names every capability that is off or can't run; owner row, brief to be written |
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
| APPLY-dup | `broker/apply/ASSUMPTIONS.md` repeats rows A3–A7 (found on UPD-b); text only, no behaviour |
| FIRSTBOOT-text | `broker/firstboot` wording (L3 on #379, points 3–5): an unexpected `ScheduleFirstBoot` error still reads "updating to version N"; with several mirrors failing, STATUS names only the last mirror's failure; `Hold()` in `fell_back` says "when the update finishes" where `Status()` says it waits for a newer release. Text only; the gate stays held in each case |
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
| HK-1 f1 | Lens screen on #401: the sandbox-unavailable message in `tools/depaudit.py` names neither the PID namespace nor the `/proc` mount it now needs; the probe already fails loudly |
| HK-1 f2 | Lens screen on #401: violations carried from faulted attempts are not de-duplicated, so the same leak seen twice is listed twice; the outcome is unchanged |
| HK-1 f3 | Lens screen on #401: `_scratch_dir` drops `TemporaryDirectory`'s chmod-and-retry cleanup of read-only entries; removal still raises rather than passing |
| W5a-resume-pace | A page resume ask waits for the gate's CH-15 batch before it shows under Approvals; the page says it shows shortly |
| W5a-resume-dedupe | Two concurrent asks for one pause can file two requests; approving one resumes and the other then fails at apply, so nothing widens twice |
| W3-forget-b f1 | L3 on #317: a brief that stores its own state (`**State:**`) can drift from BOARD, which is authoritative; drop the line from new briefs and have doclint flag it |
| DOC-4 f1 | L3 on #400: a no-PR record must still write `head <sha>` for a `main` commit and invent a package (`POTENCY`); accept `PR none · package none · main <sha>` in the Record check |
| DOC-4 f2 | L3 on #400: the Record check skips lens files without a `YYYY-MM-DD-` name (e.g. `reviews/ux/pr500.md`); require dated names for non-README files in lens directories |
| DOC-4 f3 | L3 on #400: the Record check accepts the line anywhere in the file, not only under the title as OPERATING §4 step 3 says; harmless today |
| DOC-4 f4 | L3 on #400: U15 sits between U10 and U13 in `broker/update/ASSUMPTIONS.md`; cosmetic reorder |
| DOC-4 f5 | Lens screen on #400: the Mark-requested SR3 and deep-potency reviews are indexed only by filename, beside per-PR records; keep a one-line "Requested reviews" pointer list (regex part is DOC-4 f1) |
| DOC-4 f6 | Lens screen on #400: OPERATING §4 step 1 could give the run index in one command, `grep -H -e '^Record:' -e '^Verdict' reviews/<lens>/*.md` |
| DOC-4 f7 | Lens screen on #400: `RECORD_DIRS` is hard-coded, so a new lens directory goes unchecked, and `records()` globs the disk, so an untracked scratch record fails a local run |
| DOC-4 f8 | Lens screen on #400: the `head` regex in the Record check accepts lowercase hex only, while its message says "hex"; say "lowercase hex" or match case-insensitively |
| CH-21c f1 | L3 on #402: `localui/vault.go:598` "The box refused that. Try again." is third person; localui is on the CH-21c `pending` list, so its sweep takes it |
| OSS-10w2 f6 | UX on #402: the follow-refused text "Not asked: I refused this request." gives no next step (CH-12); it predates #402 |
| W5a-resume f1 | L3 on #381: no committed test covers restart; a legacy pause-less resume replaying and `Pause`/`PausedBy` rebuilt from the journal were shown only by a scratch test. The next package that touches grants adds it |
| W5a-resume f2 | UX on #381: the Approvals line shows the raw pause intent ID (e.g. `loop2/pause/3fa9…`); keep it in Detail for the binding, but show the pause time or put the ID on a muted line |
| SR2-3j f2 | Security on #396 delta: the guest text for a void approval, "a wrong code was given too many times", is passive and does not say whose code |
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

## Reuse candidates
| ID | Component | Why |
|---|---|---|
| CRED-4b, S5 | Playwright (Chromium over CDP) | Drives pages inside the sandbox; the narrow action protocol wraps it |
| ADP-5 | cage (Wayland kiosk compositor) | Single-app kiosk with no shell or file manager; add file-dialog confinement |
| HOST-1d | cryptsetup / LUKS2 | Vault-keyed disk encryption without custom crypto |
| SR2-4i | systemd resource control (IOWeight=, CPUWeight=) | Sets io.weight and cpu.weight per slice; add iocost QoS on the image |
| UPD-b | systemd-sysupdate (S7 stack) | First-boot update-before-trust already fits the chosen image stack |
