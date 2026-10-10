# CONV-3: open PR triage

Snapshot 2026-10-09T15:20Z, base `main`. Query: `list_pull_requests state=open` (GitHub MCP), 195 PRs, each listed once.
Classes follow `briefs/CONV-3.md`. Nothing is closed by this package (Q3 answered, D-090).

## Counts

| Class | PRs |
|---|---|
| merge-ready | 3 |
| finish | 95 |
| parts bin | 86 |
| superseded | 5 |
| stale | 6 |
| total | 195 |

## Close list (Q3, D-090)

The brief posts this list as Q3 in `docs/MARK-QUEUE.md`. Q3 was asked and answered ("Yes", D-090) before this PR, and the queue keeps only open questions, so the list is recorded here and in D-090 instead.

- superseded (5): #193, #195, #198, #219, #236
- stale (6): #175, #191, #192, #194, #197, #231

Nine are already closed (D-087). #175 and #231 close after this PR's L3 accepts, branches kept (BOARD rows P2-1 and CH-21e cite them).

## Method

- **Idle** is age of the last commit on the PR head (committer date), not `updated_at`, which bot activity resets. Stale needs idle of at least 48h (D-086). The number of PRs past the line rises every hour; `crosses 48h in Nh` marks those within 6h.
- **parts bin**: any draft CODEX-1 lists as accepted-source or held, plus the W5-D stack. Never stale or superseded.
- **superseded**: the same row or change is merged on main under another PR (named). Checked by row ID against main history, by BOARD row, and by the identifiers the PR adds. Main's history was rewritten, so a reverse apply of the diff does not show it.
- **merge-ready**: non-draft, CI green, merges clean into main, L3 `accept` at the current head. Green without a verdict at head is `finish` (L3 owed).
- **stale**: not the above, idle at least 48h.
- **owning row** comes from matching BOARD row IDs against PR title and branch; `—` means no row claims it. Two stale PRs own a BOARD row: #175 (P2-1, back to `queued`, cites #175) and #231 (CH-21e cites #231). CONV-3-4 changes those two rows.

## Table

| PR | Title | Class | Owning row | Reason |
|---|---|---|---|---|
| #175 | P2-1: device image (supersedes #41): per-drive IDs, host clock untouched, closed device po | stale | P2-1 | idle 48h or more (last commit 2026-10-05). Not superseded: its initrd per-drive ID check (power off on refusal) and `DevicePolicy=closed` on every service (HW-8, D-044, I12) are not under `image/` on main; #41 is the older image it rebuilds. Branch kept as the only copy |
| #191 | H2 Point agents at uncovered IDs and queued packages | stale | — | idle 48h (D-086 limit 48h by last commit); conflicts with main |
| #192 | H3 Reject a trace table that cites an unmarked requirement | stale | — | idle 48h (D-086 limit 48h by last commit); conflicts with main |
| #193 | P2-2a f1 Tell the owner when a page approval changed underneath it | superseded | P2-2a f1, P2-2a | P2-2a f1 is on main (f2 #363 and f3 #423 followed) |
| #194 | P3-6d Say when a skill replaces a step-by-step procedure | stale | P3-6d | idle 48h (D-086 limit 48h by last commit) |
| #195 | OSS-6s Publish each day as one constant-size body | superseded | OSS-6s | OSS-6s-a merged as #411 (OSS-6s split, #325) |
| #196 | Hand back an oversized tool result as a stand-in the machine can read | finish | — | CI unknown, no L3 verdict, conflicts with main, crosses 48h in 0h |
| #197 | P2-8b Removing a trusted PC owes Refresh until the card is scanned | stale | P2-8b | idle 48h (D-086 limit 48h by last commit) |
| #198 | SR2-3h Keep runsc diagnostics out of the guest | superseded | SR2-3h | SR2-3h merged as #362 |
| #199 | Shorten JSON tool results without dropping a field | finish | — | CI green, no L3 verdict, crosses 48h in 0h |
| #200 | Measure the code-word check without withholding any text | finish | — | CI unknown, no L3 verdict, conflicts with main, crosses 48h in 0h |
| #201 | Stop a legal request id from looking like an unknown page answer | finish | — | CI unknown, no L3 verdict, conflicts with main, crosses 48h in 0h |
| #202 | Keep a question-store path out of the guest error | finish | — | CI green, no L3 verdict, crosses 48h in 0h |
| #203 | Keep an inbox-store path out of a failed delivery | finish | — | CI green, no L3 verdict, crosses 48h in 0h |
| #204 | Keep the publication floor across a restart on the same boot | finish | OSS-6e | CI unknown, no L3 verdict, conflicts with main, crosses 48h in 1h |
| #205 | Remove known token shapes from text a model can read | finish | — | CI green, no L3 verdict, crosses 48h in 1h |
| #206 | Pin that a guest machine cannot dial | finish | — | CI green, no L3 verdict, crosses 48h in 1h |
| #207 | Strip a host path from a tool error before the guest reads it | finish | — | CI unknown, no L3 verdict, conflicts with main, crosses 48h in 1h |
| #208 | Block adoption of a read or draft that sends in the demo | finish | — | CI green, no L3 verdict, crosses 48h in 1h |
| #209 | Keep a host path out of a failed recall reset's evidence | finish | — | CI red, no L3 verdict, crosses 48h in 1h |
| #210 | Keep a host path out of a failed change save | finish | — | CI green, no L3 verdict, crosses 48h in 1h |
| #211 | Accept only the closed browser action protocol | finish | — | CI green, no L3 verdict, crosses 48h in 1h |
| #212 | Keep a host path out of a failed activation's evidence | finish | — | CI green, no L3 verdict, crosses 48h in 1h |
| #213 | Keep a host path out of a failed update install's evidence | finish | — | CI unknown, no L3 verdict, conflicts with main, crosses 48h in 2h |
| #214 | Keep a host path out of a failed grant's evidence | finish | — | CI green, no L3 verdict, crosses 48h in 2h |
| #215 | Keep a vault path out of the text about a failed forget | finish | — | CI red, no L3 verdict, crosses 48h in 2h |
| #216 | Keep a host path out of a skill's stop reason | finish | — | CI green, no L3 verdict, crosses 48h in 2h |
| #217 | S8-W1: worker-held login invisible to tool subprocesses | finish | S8-W1 | draft, crosses 48h in 1h |
| #218 | CRED-4b: broker browser executor on S5 fixtures | finish | CRED-4b | draft, crosses 48h in 2h |
| #219 | UPD-b: first-boot stable update before AI/accounts (UPD-3) | superseded | UPD-b | UPD-b merged as #379 |
| #220 | RES-5: per-pool plan admission + concurrency cap | finish | — | draft, crosses 48h in 1h |
| #221 | CAP-11/12: provider-agent declaration + resources tool | finish | — | draft, crosses 48h in 2h |
| #222 | ONB-9: plan pool lines on STATUS + Wi-Fi page | finish | — | draft, crosses 48h in 2h |
| #223 | OP-9: STATUS/digest names every dead capability | finish | — | draft, crosses 48h in 1h |
| #224 | UPD-9: security fix never held in silence | finish | — | draft, crosses 48h in 1h |
| #225 | HOST-1e: host-untouched QEMU acceptance harness | finish | HOST-1e | draft, crosses 48h in 1h |
| #226 | TR3: tests-only markers for soft gaps | finish | — | draft, crosses 48h in 1h |
| #227 | ADP-6: adapter candidates must enter through section 11 | finish | — | draft, crosses 48h in 2h |
| #228 | CH-20m: MORE pages non-redirected kept replies only | finish | CH-20m | draft, crosses 48h in 2h |
| #229 | HOST-1e-ci: CI job for host-untouched harness | finish | HOST-1e | draft, crosses 48h in 2h |
| #230 | W3-off-a: dynamic spare-time STATUS note | finish | W3-off-a, W3-off | draft, crosses 48h in 2h |
| #231 | CH-21: box name rules, NAME parse, withhold helper | stale | CH-21, CH-21e | idle 48h or more (last commit 2026-10-07 17:58Z, 45h at the snapshot). Its voice work is on main (CH-21a #372, CH-21c #462), but `withholdAgent`, `AskForCode` and `ReplyGrammar` (CH-21e) are not; CH-21e cites this branch |
| #232 | BAK-1h: rune limit and single-script backup destination names | finish | — | draft, crosses 48h in 2h |
| #233 | HOST-1b-o1: open clock state once with O_NOFOLLOW | finish | HOST-1b | draft, crosses 48h in 2h |
| #234 | PC1: hold adapter_gap changed_api/layout until ARC-6(d) | finish | — | draft, crosses 48h in 3h |
| #235 | S8-codex-terms: broker-held Codex custody allowed | finish | S8-codex-terms | draft, crosses 48h in 2h |
| #236 | CH-21: third-person self-reference detector (voice) | superseded | CH-21 | CH-21 third-person detector is on main (voice_test.go, #372) |
| #237 | HOST-1b-o2: cap how far a plain sync can raise the floor | finish | HOST-1b | draft, crosses 48h in 2h |
| #238 | HOST-1b-c2: unverified-clock code wording (K15/C2) | finish | HOST-1b | draft, crosses 48h in 2h |
| #239 | W5c-ps2: clean-room spare-meter Max share | finish | W5c | draft, crosses 48h in 2h |
| #240 | BAK-1i: empty key ID log entries read as old-card | finish | — | draft, crosses 48h in 2h |
| #241 | OSS-6-w5: count publication days only on a verified clock | finish | OSS-6 | draft, crosses 48h in 3h |
| #242 | HOST-1b-t8: phone-attested time for codes and waits (T8–T10) | finish | HOST-1b | draft, crosses 48h in 3h |
| #243 | BAK-1-w1: AcceptUpload checks stream hash against BackupSum receipt | finish | BAK-1 | draft, crosses 48h in 3h |
| #244 | HOST-1c-r2: answer Windows recovery-key prompts from the guide | finish | HOST-1c | draft, crosses 48h in 3h |
| #245 | BAK-1-pb2: start backup after key change when a destination exists | finish | BAK-1 | draft, crosses 48h in 3h |
| #246 | BAK-1-stale: only-copy notice returns when a backup is over a month old | finish | BAK-1 | draft, crosses 48h in 3h |
| #247 | OSS-10-wf1: empty follow name only when root matches the image root | finish | — | draft, crosses 48h in 3h |
| #248 | TIM-1-flush: Flush owner texts before a planned restart or update | finish | — | draft, crosses 48h in 3h |
| #249 | BAK-1-setup: defaults line carries the no-backup only-copy clause | finish | BAK-1 | draft, crosses 48h in 3h |
| #250 | W5a-fx-gate: only AddSecurityCase creates loop2 fixtures | finish | W5a | draft, crosses 48h in 3h |
| #251 | SR2-4i-pids: pool cap from the effective pids cap up the tree | finish | SR2-4i | draft, crosses 48h in 3h |
| #252 | W5-sl: second-line digest lines daily for 7 days, then weekly | finish | — | draft, crosses 48h in 3h |
| #253 | P2-3w-stop: the owner's exact STOP skips the inbound limit and goes first | finish | P2-3w | draft, crosses 48h in 3h |
| #254 | P2-3w-r2: SendFirst puts a STOP or STATUS reply ahead of the outbound queue | finish | P2-3w | draft, conflicts with main, crosses 48h in 3h |
| #255 | CI-SOAK: remove runner umask and filesystem assumptions from regressions | parts bin | CI-SOAK | CODEX-1 held or accepted-source draft; kept as a parts bin (already fully on main) |
| #256 | H4: prepare bounded context with planned-file and worktree freshness checks | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #257 | H5: distinguish named test execution from requirement marker claims | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #258 | H6: collect matched A10 outcomes without conflating resource units | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #259 | S5-R: preserve a failing refused-navigation recovery qualification probe | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #261 | INT-A: freeze actual service contracts and synthetic recovery oracles | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #262 | S8-W1: inventory every credential-bearing tool surface before qualification | parts bin | S8-W1 | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #263 | W5-D1: specify crash-safe digest snapshots and acknowledgment | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #264 | W7-A: specify verified feedback and assembled learning benefit experiments | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #265 | H7: independently audit offline review exports against pinned Git objects | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #266 | W5-D2: persist bounded digest batches with source acknowledgment and unknown-send recovery | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #267 | W5-D3: recover durable digest source acknowledgments before fresh collection | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #268 | W5-D4: persist nonconsuming pipeline digest generations and exact event acknowledgments | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #269 | W5-D5: connect production pipeline receipts to durable digest collection | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #270 | W5-D6: persist nonconsuming question digest prefixes and exact acknowledgments | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #271 | W5-D7: expose cancellable bridge sends with handoff evidence | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #272 | W5-D8: preserve disclosure and line-failure provenance in cancellable notices | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #273 | H8: stabilize test-only pipeline split entropy for cascade fixtures | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #274 | W5-D9: join guarded complete-text digest sends to durable transport outcomes | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #275 | P4-3-status: agentos-release status with expiry and threshold warnings | finish | P4-3 | draft, conflicts with main, crosses 48h in 4h |
| #276 | W5-D10: test assembled digest recovery at twelve durable crash cuts | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #277 | W5-D11: fuzz rehashed source receipts without consuming later notifications | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #278 | W5-D12: distinguish nested context capability refusal from line failure | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #279 | W5-D13: persist bounded owner guard notes with exact nonconsuming receipts | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #280 | W5-D14: make local STOP immediate and invalidate older RESUME work | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #281 | P3-3b-scrub: an erase also removes quoted decision reasons and quality notes | finish | P3-3b | draft, crosses 48h in 4h |
| #282 | W5-D15: capture typed owner guard notes with independent failure status | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #283 | HOST-1d part 1: internal-disk opt-in offer and consent | finish | HOST-1d | draft, crosses 48h in 4h |
| #284 | W5-D16: bind typed owner-note receipts to durable multi-source collection | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #285 | W5-D17: persist ordered idempotent owner-note ingestion receipts | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #286 | W5-D18: refuse timestamps outside durable UTC year bounds | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #287 | W5-sid: adoption IDs from the owner channel's allocator (change C11) | finish | — | draft, conflicts with main, crosses 48h in 4h |
| #288 | HOST-1a part 2: bsg and NVMe controller nodes root-only | finish | HOST-1a | draft, crosses 48h in 4h |
| #289 | ADP-13 part 1: the box's mailbox address choices | finish | ADP-13 | draft, crosses 48h in 4h |
| #290 | ADP-13 part 2: forward receipts only with an aligned DMARC pass | finish | ADP-13 | draft, conflicts with main, crosses 48h in 4h |
| #291 | P4-4-measure: attestation hardware and versions from measurement only (attest A9) | finish | P4-4 | draft, crosses 48h in 4h |
| #292 | P2-rev3-sweep: boot sweep unstages staged copies a restart left behind (RV11) | finish | P2-rev3 | draft, crosses 48h in 4h |
| #293 | UPD-a-held: a planned update waits for effects in their undo window (UX-76-2) | finish | UPD-a | draft, conflicts with main, crosses 48h in 4h |
| #301 | W5-D19: bind claimed digest producers to private source checkpoints | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #302 | W5-D20: atomically retain guard notes with owner-state transactions | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #303 | W5-D21: refuse incompatible digest producers and expose capture errors | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #304 | W5-D22: delegate code-state writes and atomic guard events to outbox | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #305 | W5-D23: route delegated handler events without duplicate capture | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #306 | W5-D24: compose transactional owner channel with recovery-only startup | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #307 | W5-D25: sanitize transactional recovery errors and held-code replies | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #308 | W5-D26: verify transactional owner-to-queue recovery across file cuts | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #309 | W5-D27: contain digest dispatch and serialize quiescent invalidation | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #310 | W5-D28: exercise actual owner STOP across durable digest dispatch | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #311 | W5-D29: persist clock-gated daily heartbeat source and exact receipts | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #312 | W5-D30: revalidate digest source eligibility before transport call | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #313 | W5-D31: reject zero and cancelled heartbeat clock observations | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #314 | W5-D32: compose contained daily collection and dispatch recovery | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #331 | W5-D33: assemble transactional daily host and bounded runner | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #332 | W5-D34: retire accepted daily history within explicit calendar retention | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #333 | W5-D35: share notification pacing and recheck policy before transport | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #334 | W5-D36: verify assembled host policy and actual bridge recovery | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #335 | W5-D37: persist the shared notification allowance before handoff | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #336 | W5-D38: contain dispatch when shared accounting needs recovery | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #337 | W5-D39: verify five-store bridge and common budget recovery | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #338 | W5-D40: require provisioned pacing state without resetting allowance | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #345 | SUB-2: audit identity and preserve adopted substrate contracts | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #346 | SUB-3 L1: propose peer substrates while preserving current-main contracts | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #347 | W5-D41: expose overdue pacing storage without blocking health | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #348 | W5-D42: bind provisioned daily host to one shared accounting policy | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #349 | W5-D43: bound accounting file reads before Gate decoding | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #350 | W5-D44: hold cooperating pacing-store lease across Gate lifetime | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #351 | W5-D45: propagate accounting retirement to Gate and host health | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #352 | W5-D46: own one leased accounting Gate and drain scoped users before release | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #353 | W5-D47: own blocked accounting startup and preserve independent held controls | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #354 | W5-D48: bound cooperating accounting startup admission across paths | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #359 | W5-D49: decode bounded pinned pacing settings into strict startup | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #360 | W5-D50: anchor leased pacing I/O to its held directory | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #361 | W5-D51: bound leased accounting lookup and refuse symbolic ancestors | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #368 | W5-D52: prove shared approval/question/host drain and independent STOP | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #369 | W5-D53: capture complete pinned notification/runtime reconciliation | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #371 | W5-D54: explicitly recover only pinned duplicate accounting temporary | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #373 | W5-D55: share owner admission between startup and explicit recovery | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #374 | W5-D56: admit manifest reading inside one owned startup worker | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #375 | W5-D57: prevent implicit Git transport during offline reconciliation | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #376 | W5-D58: join daemon workers and settlements before journal close | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #382 | W5-D59: report fixed journal-close outcome after daemon shutdown | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #385 | W5-D60: use actual provisioned shared Gate in opt-in daemon | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #387 | POT: stage implementation drafts and dependencies from the deep potency review | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #388 | POT-P6: isolate routing evidence by task class | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #390 | POT-P5: earn bounded approval suggestions per recurring template | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #395 | W5-D61: assemble one trusted owner for provisioned daemon and daily host | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #397 | W5-D62: inspect bounded accounting residue without mutation | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #399 | POT-P3: grade replays from broker-observed effects (activation blocked) | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #403 | SPEC: local devices as capabilities (§10B) and home-network boundary (DEV-2) | finish | — | CI green, L3 accept (older head) |
| #404 | W5-D63: enforce opt-in protected ancestor ownership and write modes | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #405 | UX3: deep UX review with evidence and twelve remediation briefs | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #410 | W5-D64: carry pinned protected policy through one owned startup | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #413 | W5-D65: retain final accounting lease cleanup result | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #414 | W5-D66: retain uncertain constructor unwind in startup admission | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #417 | UX4: onboarding review — preserve intent, handoffs and first value | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #418 | OSS-6 spec-diff: pull job, circuit isolation, ask-each-time prompts, embargoed report tran | merge-ready | OSS-6 | CI green, L3 accept at current head, merges clean |
| #419 | Records: BOARD state refresh 2026-10-08 | finish | — | CI unknown, no L3 verdict, conflicts with main |
| #421 | CRED-5f/5t/5w: L1 spec-diff, broker-held route failure, fallback and owner pause | finish | CRED-5f | CI green, L3 fix-list (older head) |
| #426 | CRED-5t: fail-closed credential exchange and route stop in egress | finish | CRED-5t | CI unknown, no L3 verdict, conflicts with main |
| #435 | W5-D67: carry pinned manifest policy through explicit recovery | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #447 | ARCH1: secure cross-silo architecture with simple text/call outcomes | parts bin | — | CODEX-1 held or accepted-source draft; kept as a parts bin |
| #449 | S9: local neural embedder for recall (spike harness and baselines; model comparison blocke | finish | — | draft, conflicts with main |
| #451 | S10: personal-agent protocols spike — PACT not adoptable as specified, PAP unpublished | finish | — | CI unknown, no L3 verdict, conflicts with main |
| #453 | P2-2w c3 r2: spec diff, host network secrets outside ARC-1 | finish | P2-2w c3 r2, P2-2w c3 | CI green, L3 fix-list at head |
| #457 | CH-21d: first-person voice in agentosd, agentos-egress, agentos-localui | finish | CH-21d | CI unknown, no L3 verdict, conflicts with main |
| #467 | CH-21b: NAME command and box-name check (setup half split to CH-21f) | finish | CH-21b | CI unknown, no L3 verdict, conflicts with main |
| #469 | FIRSTBOOT-text: first-boot gate wording (L3 on #379, points 3-5) | finish | — | CI unknown, no L3 verdict, conflicts with main |
| #470 | DOC-5: LATER records sweep (docs and tooling rows) | finish | — | CI unknown, no L3 verdict, conflicts with main |
| #471 | OSS-6s-a-f: cap the pubsend ledger read; record producer sizes against MaxPayload | finish | OSS-6s-a, OSS-6s | CI green, no L3 verdict |
| #473 | W3-forget-f: re-check work under run in TakeBack; loop1 forget follow-ups | finish | W3-forget | CI unknown, no L3 verdict, conflicts with main |
| #476 | OSS-10w-r: switch back across a project root-key rotation | finish | OSS-10w | CI unknown, no L3 verdict, conflicts with main |
| #480 | L1 spec-diff: D-079/D-080 MORE paging, held multi-message tasks, withheld results | finish | — | CI green, no L3 verdict |
| #482 | Records: combined lens pass for #453 (ARC-1 host network secrets) | finish | — | CI green, no L3 verdict |
| #485 | L1 spec-diff: D-081/D-082 phone contract and bounded guarantee claims | finish | — | CI green, no L3 verdict |
| #505 | CRED-5: combined lens record for #421 at b6954ae | finish | — | CI green, no L3 verdict |
| #611 | SR3-4f-2-r1: Loop 3 offers a dropped release again | merge-ready | SR3-4f-2-r1, SR3 | CI green, L3 accept at current head, merges clean |
| #614 | SR3-4f-3: security withdraw after Install; refused revert sets a Concern; permanent drop r | finish | SR3 | CI pending, L3 fix-list (older head) |
| #615 | Records: carry the non-blocking review points of #602–#610 | finish | — | CI green, no L3 verdict |
| #616 | SR3-5-f2: pin delete-remote intents; never expire the judgement of an intent in use | finish | SR3-5-f2, SR3-5 | CI green, L3 accept (older head) |
| #617 | W5-Dc-r1a: owner pacer (quiet hours and unsolicited-text pacing, CH-15) | finish | W5-Dc | CI pending, L3 fix-list (older head) |
| #618 | Records: brief the P3-4b-4c follow-ups (nofollow, canary-uid, bounds, dedupe) and P3-4b-4e | merge-ready | P3-4b-4c, P3-4b-4e | CI green, L3 accept at current head, merges clean |
| #619 | W5-Dc-r9: dead digest batches give way to today's digest | finish | W5-Dc-r9, W5-Dc | CI pending, L3 accept (older head) |
| #620 | SR3-6f-4: a narrowing retires every claim it touches | finish | SR3 | CI green, no L3 verdict |
| #621 | P3-4b-3r-env-r1: childEnvCheck tracks Env per command and catches the shapes it passed | finish | P3-4b-3r-env-r1, P3-4b-3r-env | CI green, no L3 verdict |
| #622 | W5-Dc-r12: digest replays the tombstone at open (forget double fault, CAP-3) | finish | W5-Dc-r12, W5-Dc | CI pending, no L3 verdict |
| #623 | P3-4b-3r-confine-r5: F16's defences fail a test when reverted; input reads and run output  | finish | P3-4b-3r-confine-r5, P3-4b-3r-confine | CI pending, no L3 verdict |
| #624 | RECALL-canary-1: remove evenly grouped recovery codes of any alphabet (CRED-1) | finish | — | CI pending, no L3 verdict |
| #625 | P3-4b-3h-r2 (+3h-r1): a hang closes on a producer loops holds; a late hang is a stall | finish | P3-4b-3h-r2, P3-4b-3h | CI pending, no L3 verdict |
| #626 | P3-4b-3r-confine-r6: emptying the fuzz leaf kills on a failed freeze, within 1.5 s | finish | P3-4b-3r-confine | CI pending, no L3 verdict |
| #627 | CONV-1: convergence rules (D-086), Mark queue, CONV-0..6 briefs | finish | CONV-1, CONV-0 | CI unknown, no L3 verdict |
