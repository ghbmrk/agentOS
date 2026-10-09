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
| DEP-2 | [depaudit evidence out of the tracee's reach](briefs/DEP-2.md) | HK-1 | merged (1355d27; #437) |
| DEP-3 | [depaudit evidence out of the tracee's uid](briefs/DEP-3.md): run the scenario under a uid distinct from `_inner` and strace with an exact uid_map, plus a control that drains `/proc/1/fd`, ptrace-attaches and writes a partial line after a connect, and expects `violation` even without the capability drop (release, tier A, A9; L3 on #437 point 2, Security on #437 point 3 and re-sign 3 N1, tools/ASSUMPTIONS.md D9) | DEP-2, DEP-4 | merged 82817bb (#562) |
| DEP-4 | [depaudit fails closed on its own preconditions](briefs/DEP-4.md): kept paths read-only recursively, checked from mountinfo; reject an strace that cannot name a `TRACED` syscall (DEP-5 folded in) (release, tier A, DEP-2b, A9; L3 on #437 point 3, Security on #437 point 2, tools/ASSUMPTIONS.md D10) | DEP-2 | merged (958fa35; #552) |
| DEP-5 | depaudit fails closed on an strace that cannot name a `TRACED` syscall: folded into [DEP-4](briefs/DEP-4.md) as DEP-4b (one tier-A review cycle for two small fail-closed checks in the same files) | DEP-2 | dropped (folded into DEP-4) |
| DEP-6a | [depaudit](briefs/DEP-6.md): test `TRACED` per architecture as `_traced(machine)` for `aarch64` and `x86_64`; the current test derives both sides from `_ABSENT`, so the aarch64 `?` branch never runs on CI (release, tier A, DEP-4b; lens on #552 Potency 2) | DEP-4, DEP-3 | building (#568) |
| DEP-6b | [depaudit](briefs/DEP-6.md): `control-kept-read-only` reads mountinfo independently of `writable_mounts`/`_reaches_rw` (another parse, or `statvfs` per mount point), so a bug there cannot blind both the check and its control (release, tier A, DEP-4a; lens on #552 Potency 3) | DEP-4, DEP-3 | building (#568) |
| DEP-6c | [depaudit](briefs/DEP-6.md): probe `mount_setattr` once in `sandbox_available()` so a kernel before 5.12 exits 2 up front naming the need, not `error` per target with a traceback (release, tier A, DEP-4a; lens on #552 UX 5) | DEP-4, DEP-3 | building (#568) |
| DEP-6d | [depaudit](briefs/DEP-6.md): keep the probe's stderr tail when `sandbox_available()` fails and print it on the exit-2 FAIL line, so the rejected strace name or failing `unshare`/`setpriv` shows (release, tier A, DEP-4b; lens on #552 UX 6). Also covers a missing subuid/subgid range: `sandbox_available()` swallows `_id_maps()`'s OSError before the probe starts, so there is no stderr; keep that text and print it on the FAIL line (lens on #562 UX 1) | DEP-4, DEP-3 | building (#568) |
| DEP-6e | [depaudit](briefs/DEP-6.md): the rw-mount sandbox error gives a next step (bind it read-only, or drop the keep entry; D10) (release, tier A, DEP-4a; lens on #552 UX 7). Also: the exit-2 sandbox-unavailable line names the failing need and its remedy per cause (`apt-get install uidmap`; `usermod --add-subuids/--add-subgids`, as in `assurance.yml`) (lens on #562 UX 2) | DEP-4, DEP-3 | building (#568) |
| DEP-3-r1 | [depaudit](briefs/DEP-7.md): test `test_the_evidence_channels_are_closed_by_uid_alone` asserts 2 connect events, not only the violation targets, so a lost second connect fails a named assertion (L3 on #562 point 1) (release, tier A, A9) | DEP-3, DEP-6 | queued (after DEP-6) |
| DEP-3-r2 | [depaudit](briefs/DEP-7.md): `control-evidence-channels` also tries to reopen strace's stderr (`/proc/<strace>/fd/2`, O_RDONLY) to drain fault lines (Security 4a on #562 point 1) (release, tier A, A9) | DEP-3, DEP-6 | queued (after DEP-6) |
| DEP-3-r3 | [depaudit](briefs/DEP-7.md): `control-evidence-channels` also signals the tracer (`kill`/`SIGSTOP` of strace and `_inner`) and expects refusal (Security 4a on #562 point 2) (release, tier A, A9) | DEP-3, DEP-6 | queued (after DEP-6) |
| DEP-3-r4 | [depaudit](briefs/DEP-7.md): `control-distinct-uid` asserts `NoNewPrivs:\t1` in `/proc/self/status`, so removing `PR_SET_NO_NEW_PRIVS` fails a control (Security 4a on #562 point 3) (release, tier A, A9) | DEP-3, DEP-6 | queued (after DEP-6) |
| DEP-3-r5 | [depaudit](briefs/DEP-7.md): `IdMapTest` case: a subuid range with no subgid range makes the sandbox unavailable by design, not by `None` formatting (Security 4a on #562 point 4) (release, tier A, A9) | DEP-3, DEP-6 | queued (after DEP-6) |
| DEP-3-r6 | [depaudit](briefs/DEP-7.md): unit test: EACCES on a writable fs (stubbed `statvfs`) is not a read-only refusal in `_refused_read_only` (Security 4a on #562 point 5) (release, tier A, A9) | DEP-3, DEP-6 | queued (after DEP-6) |
| DEP-3-r7 | [depaudit](briefs/DEP-7.md): test pins reap-before-chown-back: `_end_namespace` runs (and reaps) before the lchown to 0 (Security 4a on #562 point 6) (release, tier A, A9) | DEP-3, DEP-6 | queued (after DEP-6) |
| DEP-6-r1 | depaudit: `_subordinate`/`_id_maps` treat a range whose start is below 100000 (or `SUB_UID_MIN`/`SUB_GID_MIN`), or that overlaps any uid in `/etc/passwd` or gid in `/etc/group` (the runner's own included), as no usable range, so `sandbox_available()` fails with the DEP-6e remedy instead of mapping the scenario onto root or a login user (release, tier A, DEP-3a, D13; Security re-sign on #568 point 2; brief to write) | DEP-4, DEP-3 | queued (needs brief) |
| CODEX-1 | [Intake of Codex drafts for implementation](briefs/CODEX-1.md) | — | in review (C; records only) |
| CI-SOAK-f1 | [Fixtures independent of umask and tmpfs](briefs/CI-SOAK-f1.md) | — | merged (8c49dc5; #563) |
| H8 | [Deterministic split entropy for change fixtures](briefs/H8.md) | — | merged (9358360; #564) |
| H6 | [A10 trial collector](briefs/H6.md) | — | merged (464736c; #561) |

## Security and architecture review (2026-10-08)

Primary lane; remediation is unclaimed. [Review record](reviews/security/2026-10-08-architecture-review.md).

| ID | Package | Needs | State |
|---|---|---|---|
| SR3-1 | [Bind local sign-in to the authenticated lock generation](briefs/SR3-1.md) | P2-2w a, P2-2w b | merged (#431 a52a678) |
| SR3-2 | [Enforce pre-allowance rate limits at dispatch](briefs/SR3-2.md) | P2-grants, P2-gr8 | merged (#428 75a97c7) |
| SR3-3 | [Show and bind the complete pre-allowance rule at approval](briefs/SR3-3.md) | P2-grants, P2-2a | merged (#433 3bd595e) |
| SR3-4 | [Make update finalization durable and idempotent](briefs/SR3-4.md) | UPD-a, P4-3, P3-1 | in review (#434) |
| SR3-5 | [Preserve IMAP message identity through mutations and undo](briefs/SR3-5.md) | P2-6m | merged (#424 e43ae52) |
| SR3-6 | [Invalidate verified updates when attestation policy narrows](briefs/SR3-6.md) | P4-3, P3-1 | in review (#430) |
| SR3-7 | [Use one validated request for model reservation and routing](briefs/SR3-7.md) | P2-7, P1-7 | merged (#429 afb8077) |
| SR3-8 | [Commit clean-room output durably before recording completion](briefs/SR3-8.md) | P4-2 | merged (#432 6ec0328) |
| SR3-2-f1 | [mail](briefs/SR3-mail-f.md): Mail `DailyLimit` counts at authorization, not at dispatch (the F2 shape): move it to dispatch-time durable counting through `journal.Engine.InUse`, so a queue older than 24 h or one lost on restart cannot run past 200. Also add this row to the Needs of the row that wires unattended mail (release, tier A, anchor AT4; Security on #428, point 1, [note](reviews/security/2026-10-08-pr428.md)) | SR3-2 | queued (release; before mail is wired) |
| SR3-2-f2 | [grants](briefs/SR3-2-f.md): The ask names the queued intents that hold places under the bound, so the owner can see why they are asked (release, UX on #428) | SR3-2 | queued (release) |
| SR3-2-f3 | [grants](briefs/SR3-2-f.md): An erased intent keeps counting toward `PerDay` but loses its record key, so it stops counting toward `PerRecord`: count it against every record, or keep the record key among the fields erasure keeps (CAP-3, A12). Predates #428, owner-triggered; Security signed it `later`, filed as release because the path is tier A (release, tier A, Security on #428, point 3, [note](reviews/security/2026-10-08-pr428.md)) | SR3-2 | queued (release) |
| SR3-4-f1 | A staged image that fails a Recheck security evaluation still boots at the next restart, because revert is refused until the adoption settles; abandon it in the slot. For a non-protected staged image Recheck also sets no Concern, so the failure is silent (release, tier A, L3 on #434; brief to write) | SR3-4 | queued (needs brief) |
| SR3-4-f2 | Resume can wedge for good: CommitRelease and ConfirmStaged are durable, the applier's save is cut, the next boot runs the old root, StageFailed refuses the confirmed adoption, Applying stays set and Tick blocks every later update. Must land before W5b (release, tier A, Security 4a on #434, S1; brief to write) | SR3-4 | queued (needs brief; before W5b) |
| SR3-4-f3 | Narrow the refusal of the owner's UNDO and of Recheck reverts from "adopted" to Applying (the handover window), and have the applier drop the pending release. Today a release waiting days for a free moment cannot be cancelled or reverted before it installs (release, tier A, Potency on #434, A7 and C25, renumbered A10 and C27 on merge; ordered before W5b; brief to write) | SR3-4 | queued (needs brief; before W5b) |
| SR3-4-f4 | An adoption abandoned as "not handed" stays Staged if nothing reschedules it, and the owner's UNDO is refused for it (release, tier A, Security 4a on #434, S2; brief to write) | SR3-4 | queued (needs brief) |
| SR3-4-f5 | If the Installed save keeps failing, a bad image can be retried without a fallback being recorded, which weakens rollback safety on `broker/apply` (release, tier A, L3 on #434; brief to write) | SR3-4 | queued (needs brief) |
| SR3-6-f1 | W5b wiring condition: each `Store.Check` rewrites `attestor_policy` from its own `Options.Attestors`, so a `NoteAttestors` narrowing lasts only until the next Loop 3 check with a static list. Loop 3's list and the `NoteAttestors` list must come from one owner-setting source, with a test. Also commit the fail-closed attestor read-error test (release, tier A, Security 4a on #430, S1 and point 2, Potency later 1; brief to write) | SR3-6 | queued (needs brief) |
| SR3-6-f2 | U16: anchor the adoption state in the TPM NV, so deleting the store directory cannot revive interim (release, tier A, L3 on #430; bound to P2-4b; brief to write) | SR3-6, P2-4b | queued (needs brief) |
| SR3-6-f3 | Apply drop paths leave the adoption Staged, and a narrowing between Install and reboot is not caught; wire `NoteAttestors` (release, tier A, L3 on #430 and Security 4a points 3-5; with SR3-4; brief to write) | SR3-6, SR3-4 | queued (needs brief) |
| SR3-7-f1 | [route](briefs/SR3-7-f1.md): `route.failover` retries on 500/502/503/504/529, but the meter sees only the served route's usage; if a provider bills 5xx attempts, one call can spend attempts times the limit against one reservation. Predates #429 and is unmeasured. First read the provider documentation on 5xx billing; if any is billed, meter every attempt or stop failover after a timeout-class status (release, tier A, Security 4a on #429, [note](reviews/security/2026-10-08-pr429.md) point 1) | SR3-7 | queued (release) |
| SR3-8-f1 | [cleanroom](briefs/SR3-8-f.md): `openStore` and `New` quarantine on the manifest's own `m.ID` instead of the directory name, and nothing validates the ID: with store write access a tampered manifest can quarantine the wrong artifact or rename a directory from outside into the store. Quarantine by directory name and require `m.ID` to equal it (release, tier A, Security 4a on #432, S1, PR #452) | SR3-8 | queued (release) |
| SR3-8-f2 | [cleanroom](briefs/SR3-8-f.md): The durability tests check the fault-hook trace, not the syscalls, so mutants that drop `syncDir` or `f.Sync` survive: pin the syscalls (release, tier A, Security on #432, S2) | SR3-8 | queued (release) |
| SR3-5-f1 | [mail](briefs/SR3-mail-f.md): Execute and Reconcile re-plan an organize by Message-ID and never check the result against what the gate approved, so a same-ID alert that replaced the approved message is hidden without the change-account ask: carry the gate's Ref (or alert bit) in the intent and return NotApplied on a mismatch or an unescalated hidden alert; also refuse a flag-only undo whose `Change.Validity` is 0. Before mail is wired (release, tier A, Security 4a on #424, S1-S2, [note](reviews/security/2026-10-09-pr424.md)) | SR3-5 | queued (release; before mail is wired) |
| SR3-mail-w | Wire unattended mail organize in agentosd (mail `Config` with the journal's `InUse` hook, the dispatch recheck, the digest's UNDO); brief to write. Placeholder so the ordering has a row to attach to (release, tier A; L3 on #571 point 6) | SR3-2-f1, SR3-5-f1 | queued (release; needs brief) |

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
| S8-W1 | [Image fix for worker-held custody](briefs/S8-W1.md) | S8, #186 | queued (blocked: needs a supervised session with prompts on, D-064; the design hand-off is a bwrap prefix for agentos-toolsh, managed-settings denies and a containment test) |
| S8-W1a | [Inventory credential-bearing tool surfaces](briefs/S8-W1a.md) | S8 | building (C; from #262; feeds S8-W1) |
| S8-live | [S8 live part](briefs/S8-live.md) | see brief | queued |
| S8-codex-terms | [Read OpenAI's current terms on a proxy holding ChatGPT-managed…](briefs/S8-codex-terms.md) | openai.com reachable | in review (decided: broker-held, unconfirmed route, #328; [note](spikes/S8-provider-workers/CODEX-TERMS.md)) |
| CRED-5f | [CRED-5 fallback when no API key is granted](briefs/CRED-5f.md) | #328 | merged (#420) |
| CRED-5f-mr | [Model line for STATUS through `modelroute`: C2 grant, lock and reachability state, replacing agentosd's socket stat (#525 records)](briefs/CRED-5f.md#added-scope-model-line-for-status-release-from-525) | CRED-5f | in review (tier A: `modelroute`, `cmd`) |
| CRED-5f-mr-busy | C2: a probe that times out while the vault process is busy (an unlock's key derivation, say) reads "not reachable ... restart the box", like a dead process; tell a slow answer apart from none, or retry before naming a restart (release, tier A, OP-9; UX lens on #566; brief to be written) | CRED-5f-mr | queued (release) |
| CRED-5f-mr-page | C2: `modelLocked` says "the local page" where other owner texts say "my Wi-Fi page"; settle one name for the box's page across owner lines, within `ownerWorded` (no apostrophes) (release, tier B, OP-9; UX lens on #566; brief to be written) | CRED-5f-mr | queued (release) |
| CRED-5f-mr-grant | Grants a real box can get: agentosd serves the local page's API-key step (`localui.AgentosdSetup.ConnectAPIKey` answers `errNotServed` today) and the vault process's model grants follow stored keys, not only `-grant` flags read at start (egress K8); until then every box reads "no AI plan or key connected", and `modelNoGrant` returns to naming the page (`TestModelNoGrantNamesAServedStep`) (release, tier A, A11, ONB-3, CRED-5; Potency on #566; brief to be written) | CRED-5f-mr | queued (release) |
| CRED-5f-mr-trailers | `modelroute.Forward` scrubs broker-only headers incompletely: `dropOurs` deletes the canonical key, so a non-canonical map key (`h["agentos-state"]`) survives, and request trailers are never scrubbed, so a declared `Agentos-*` trailer reaches the vault process; delete by the original key and run `dropOurs` on `pr.Out.Trailer`, with a raw-wire test. Not reachable from the wire today (release, tier A, ARC-6, CRED-1; L3 point 1 and Security point 1 on #566; brief to be written) | — | queued (release) |
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
| P1-4-flake | [`TestRunscPanicAtTheDeadlineAnswersNoOutput` raced runsc's exit at its deadline; a trace written before a kill answered output](briefs/P1-4-flake.md) | P1-4 | merged (#547; c0eb06e) |
| P1-4-flake-fuzz | [CI's time-bounded fuzz step failed at its deadline (#537): Go 1.26's fuzz coordinator race; bound by count](briefs/P1-4-flake.md) | P3-4b-3 | merged (#547; c0eb06e) |
| P1-4-flake-soak | `soak.yml` fuzzes for a duration (`-fuzztime "$FUZZTIME"`), so it can hit the same Go 1.26 coordinator race at its deadline (P1-4-flake-fuzz); fix by a toolchain carrying the upstream fix or a count bound sized to the soak (brief to be written) | P1-4-flake-fuzz | queued |
| P1-4-flake-counts | Per-target CI fuzz counts with a wall-clock cap: 600000x matches 20s only for `modemlink:FuzzInbound`; `sockets:FuzzFrames` gets about a third of its budget. Take counts from CI's exec/s (log them), and add a `timeout` per `go test` so a count-bound hang is loud (#547 Security 4a 1, Potency 1-2; release; brief to be written) | P1-4-flake-fuzz | queued (release) |
| P1-4-flake-crashed | Simplify gvisor `crashed` to `err != nil && len(runscErr) > 0`: closes the gap where runsc is killed by something else (cgroup OOM) after a trace, exits -1 with `ctx.Err() == nil`, and leaves no `exec.log` entry (CAP-8, RES-4; #547 Security 4a 2; release; tier A; brief to be written) | P1-4-flake | queued (release) |
| P1-4-flake-runsc-recheck | At the next pinned-runsc bump, re-check that runsc writes nothing to stderr during a normal exec; otherwise a deadline would lose partial output (V20, V34; #547 UX 1; release; rides the bump) | P1-4-flake | queued (release) |
| P1-6 | [Canary harness](briefs/P1-6.md) | Cloud only | merged |
| P1-5 | [Owner channel on a modem simulator](briefs/P1-5.md) | P1-2 | merged |
| P1-7 | [OpenClaw as first guest](briefs/P1-7.md) | P1-3, P1-4, P1-5, P1-6 | merged (847ea23; broker/guest) |

## Phase 2: real hardware, cloud parts first

| ID | Package | Needs | State |
|---|---|---|---|
| P2-1 | [Device image](briefs/P2-1.md) | P1-7, S7 | in review (#41) |
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
| P3-4b-1 | [Loop 2 repairs an injected finding: contain, minimized regression, fix qualified against linked cases; LOOP-10 rejections; LOOP-3 unmeasured](briefs/P3-4b.md#p3-4b-1-product-side) | P3-4 | merged (1d4446b; #464) |
| P3-4b-1b | [Loop 2 loop-side follow-ups to #464: close reported findings the tree comes to pass, finding-ID collision, crash resume, wording scan, config-probe fixes](briefs/P3-4b.md#p3-4b-1b-loop-side-follow-ups-to-464) | P3-4b-1 | merged (2ba9e87; #493) |
| P3-4b-2 | [A11 loop 2 qualification harness: seed catalog, held-back variants, harness-chosen seed](briefs/P3-4b.md#p3-4b-2-a11-qualification-harness) | P3-4b-1 | merged (336e29b; #490) |
| P3-4b-2b | [A11 harness follow-ups to #490: evidence check fails on a missing evidence record; fix-input audit catches a raw held clause whose fields the visible test shares; leaking-adapter control on every valid seed](briefs/P3-4b.md#p3-4b-2b-harness-follow-ups-to-490) | P3-4b-2 | merged (682486e; #500) |
| P3-4b-5 | [Model-backed loop 2 fixer: answers the §11 fix-candidate request through Loop 1's builder, wired in the daemon](briefs/P3-4b.md#p3-4b-5-model-backed-loop-2-fixer) | P3-4b-1, W3-builder-ship | queued (tier A) |
| OP9-status | [OP-9: STATUS names every capability that is off or can't run; split into -a and -b](briefs/OP9-status.md) | P3-2, P3-4 | queued |
| OP9-status-a | [OP-9 capability-line registry for STATUS and the digest; lines for every silent off case; A11 learning-cause test](briefs/OP9-status.md#op9-status-a-registry-and-the-silent-cases) | P3-2, P3-4 | merged (#525, 38c5f1c) |
| OP9-status-b | [OP-9 fix clauses on existing off lines; loop 2 wording; owner choices and the LOOP-3 loop-shares line](briefs/OP9-status.md#op9-status-b-fix-clauses-loop-lines-and-owner-choices) | OP9-status-a, P3-4b-1b, P3-4b-5 | queued (tier A; scope extended by #525 records: worker tools named under H1/H2 lines, plainLine keeps apostrophes; also, from the #532 L3 (comment 6074799003): `capState.recallWired` (broker `capoff.go`) is called only from tests, so C7's "Memory across tasks: off" line can never show in production; wire it) |
| DIG-1 | [Daily digest sender (CH-15) reading every Digest() source, OP-9 lines included (brief to be written)](briefs/OP9-status.md#split) | W5, OP9-status-a, W5-Db | queued (tier A declared; needs its own brief) |
| P3-4b-3 | [LOOP-7 off-the-shelf: socket and action-protocol fuzz targets, in-guest socket probe](briefs/P3-4b.md#p3-4b-3-loop-7-fuzzing-and-socket-probes) | P3-4b-1b | merged (#523, 58a6994) |
| P3-4b-4a | [LOOP-7 off-the-shelf: probe findings through `Report`, continuous canary rounds, published injection corpora](briefs/P3-4b.md#p3-4b-4-loop-7-canary-rounds-corpora-tamper-and-exhaustion-probes) | P3-4b-1b | merged (#515, afd66a7) |
| P3-4b-4b | [LOOP-7 off-the-shelf: tamper and exhaustion probes, and corpus replay through a real guest channel (both need the in-machine rig). Owed check (second occurrence, Security #515 f4 after #523 f5): move `broker/loops`, `broker/probecmd` and `broker/corpus` to tier A in `tools/risk_tier.py` (`TIER_A_BROKER`) with `test_risk_tier.py` pins. Corpus replay split to P3-4b-4d (size)](briefs/P3-4b.md#p3-4b-4-loop-7-canary-rounds-corpora-tamper-and-exhaustion-probes) | P3-4b-4a | merged (#548; 8a31dc9) |
| P3-4b-4d | [LOOP-7 off-the-shelf: corpus replay through a real guest channel (split from P3-4b-4b for size): published injection items delivered as untrusted input over the guest plane (mail adapter, MCP) in a gVisor machine, checked broker-side by the closed checks; needs the e2e guest-plane rig. Owner note (#548 Potency 5): the 4d split leaves corpus replay through a real guest unverified; nothing runs on a box or pauses grants until 4c and 3b](briefs/P3-4b.md#p3-4b-4-loop-7-canary-rounds-corpora-tamper-and-exhaustion-probes) | P3-4b-4b | merged (#556; 9c5a390) |
| P3-4b-4c | [LOOP-7 probes wired in `agentosd`: canary rounds and corpus replay on the box through P3-4b-3a's runner, once the drive carries the harness and corpora (loops S28); acceptance: a probe ran on the box and its run is visible in STATUS (#515 Potency 2). Also from #515 records: corpus closure keyed on item plus check (L3 release); `items.json` embedded or digest-pinned at load (Security 3); `canary.py` minimal environment and keeping hits from a target that also errored (Security 5); canary registry labels and containment (UX 3). The #548 release rows P3-4b-4c-fresh, -restore, -env, -attrib, -limits and -step add the probe-round hardening (comments 6075866370, 6075894827, 6075903379). The minimal-env Go check and process-group kill moved to P3-4b-3a; the UX wording and `TestFindingTextsNameNoIdentifiersAndNeverAlarmWithoutAStep` moved to P3-4b-3c. From P3-4b-4d (release): wired on the box, the guest-plane replay's reply route must text a sink line, never the owner's; replay goes through the daemon's `evidence.reply` path (its clip, the guest-chosen Summary), not straight to Notify, and the code-filter control reruns against that production `OwnerReply`; the box runs `PlaneChecks` plus the in-process commitment check, so the commitment filter is not dropped; `Relay` takes ctx and each route gets a timeout; the label and archive routes, like the reply route, run only against a rig mailbox and rig gate, never the owner's account. Split 2026-10-09: the CI-testable work is P3-4b-4c-corpus, -canary, -tamper and -exhaust; this row keeps the box wiring (machine probes, canary on the box if decided, the P3-4b-4d plane items above) and the box acceptance, after two decisions (canary on the box; the probe machine, from P3-4b-3f)](briefs/P3-4b-4c.md#p3-4b-4c-box-wiring-and-box-acceptance) | P3-4b-4c-corpus, P3-4b-4c-canary, P3-4b-4c-tamper, P3-4b-4c-exhaust, P3-4b-3f | queued (owner decision; acceptance on the box) |
| P3-4b-4c-fresh | [Probe rounds use a fresh machine from the signed image each round, plus a positive control (a broker-made writable target that must change; `memory.current`, `pids.current` and `cpu.stat` must rise during the hold), so a guest that does nothing cannot close open tamper or slow findings (LOOP-7, LOOP-9; #548 Security 4a 2, comment 6075894827; release; tier A)](briefs/P3-4b-4c.md#p3-4b-4c-tamper) | P3-4b-4b | queued (release; checks built in P3-4b-4c-tamper and P3-4b-4c-exhaust; the fresh-machine wiring is box row P3-4b-4c's, so this row closes with it) |
| P3-4b-4c-restore | [A positive tamper write must not overwrite or pollute the real target: restore a broker copy, or write only a fresh sibling file (LOOP-7; #548 Security 4a 3, comment 6075894827, and L3 3, comment 6075903379; release; tier A)](briefs/P3-4b-4c.md#p3-4b-4c-tamper) | P3-4b-4b | queued (release; built in P3-4b-4c-tamper) |
| P3-4b-4c-env | [Widen the env-inheritance check owed by 4c to cover `os.StartProcess`/`ProcAttr` and `syscall.ForkExec` as well as `exec.Cmd`, and update the Security README row (widens the minimal-env Go check that moved to P3-4b-3a; applies to 3a's runner and to `machprobe`; #548 Security 4a 4, comment 6075894827; third shape; release; tier A)](briefs/P3-4b-3r.md#p3-4b-3r-env) | P3-4b-4b | queued (release; built in P3-4b-3r-env) |
| P3-4b-4c-attrib | [Concurrent broker writes (checkpoints) during a tamper round must not give false High tamper findings: take targets the broker does not write during a round, pause checkpoints for the round, or attribute the change by the nonce (LOOP-7; #548 L3 2, comment 6075903379; release; tier A)](briefs/P3-4b-4c.md#p3-4b-4c-tamper) | P3-4b-4b | queued (release; built in P3-4b-4c-tamper) |
| P3-4b-4c-limits | [`ExhaustProbe` counts any positive `memory.max`/`pids.max` as limited, so it detects an unset limit, not an unenforced one (S36): compare against the configured per-class limit or box total minus broker reserve, and name the claim that way in LOOP-7 coverage; the 1 s response target is a stand-in (S35) until SPEC freezes a figure (RES-1, LOOP-7; #548 Potency 2-3, comment 6075866370, and L3 4, comment 6075903379; release; tier A)](briefs/P3-4b-4c.md#p3-4b-4c-exhaust) | P3-4b-4b | queued (release; built in P3-4b-4c-exhaust) |
| P3-4b-4c-step | [The High tamper and "no limit" finding texts carry no step and read as alarms with `Contain` unset (S37); add a step and, until P3-4b-3b decides containment, say it was only noticed, not paused. Adds step and not-paused wording and a clause to the already-owed `TestFindingTextsNameNoIdentifiersAndNeverAlarmWithoutAStep` test, which P3-4b-3c now owns (third source; LOOP-9; #548 UX 1, comment 6075866370; release)](briefs/P3-4b-4c.md#p3-4b-4c-exhaust) | P3-4b-4b | queued (release; built in P3-4b-4c-exhaust) |
| P3-4b-4c-corpus | [Corpus replay wired in `agentosd` (in-process closed checks), corpus embedded in the signed binary or digest-pinned (#515 Security 3), corpus closure keyed on item plus check (#515 L3); CI-testable, split from P3-4b-4c](briefs/P3-4b-4c.md#p3-4b-4c-corpus) | P3-4b-4d | queued (release; tier A declared) |
| P3-4b-4c-canary | [Canary harness: minimal target environment (#515 Security 2), keep hits from a target that also errored (#515 Security 5), registry names and containment (#515 UX 3); CI-testable, split from P3-4b-4c](briefs/P3-4b-4c.md#p3-4b-4c-canary) | P3-4b-4a | queued (release; tier A declared) |
| P3-4b-4c-tamper | [Tamper probe hardening: positive control and fresh machine check, sibling-only writes, broker writes quiesced for the round; carries rows -fresh (tamper half), -restore, -attrib; CI-testable, split from P3-4b-4c](briefs/P3-4b-4c.md#p3-4b-4c-tamper) | P3-4b-4b | queued (release; tier A declared) |
| P3-4b-4c-exhaust | [Exhaustion probe hardening: counters must rise during the hold, limits judged against the configured budget, finding texts; carries rows -fresh (exhaustion half), -limits, -step; CI-testable, split from P3-4b-4c](briefs/P3-4b-4c.md#p3-4b-4c-exhaust) | P3-4b-4c-tamper | queued (release; tier A declared) |
| P3-4b-4e | [LOOP-7 off-the-shelf: the commitment filter replayed through a guest (release finding from P3-4b-4d): the guest composes the replayed text as an ADP-11 auto-reply, so the probe needs an earned pre-allowance and a verified thread starter in the replay rig; add it to `corpus.PlaneChecks`](briefs/P3-4b.md#p3-4b-4-loop-7-canary-rounds-corpora-tamper-and-exhaustion-probes) | P3-4b-4d | queued (tier A declared) |
| P3-4b-3a | [LOOP-7 child-process runner and fuzz source in `agentosd`: one reviewed exec path (`escapeOK` or a runner outside the daemon), minimal child environment, process-group kill, fuzz binaries in the image, `loop7.Source` wired with `Probe` nil, tier A for `loops`, `loop7`, `probecmd`, `corpus` (#523 L3, Potency 1; #515 Security 1, 2, 4)](briefs/P3-4b-3a.md) | P3-4b-3 | merged (99a6e27; #560) |
| P3-4b-3b | Owner decision: does a probe failure pause grants on the probed machine? DECISIONS says a fuzz crash is "noticed, not contained"; the probe case is open (#523 Potency 2) (brief to be written) | P3-4b-3 | queued (owner decision) |
| P3-4b-3c | [Owner text for LOOP-7 findings: a "Cleared" text for every texted finding, plain words with no Go identifiers, urgent only when the text names a step, the real recheck cadence; takes rows 3d and 3e and 4c's UX items and lens check (#523 UX 1–3, #515 UX 1–2)](briefs/P3-4b-3c.md) | P3-4b-3 | merged (55229ef; #558) |
| P3-4b-3d | No Go identifiers in owner text; every urgent alert names a step (#523 UX 2) | P3-4b-3a | dropped (merged into P3-4b-3c) |
| P3-4b-3e | Correct the "I recheck it every round" wait wording (#523 UX 3) | P3-4b-3a | dropped (merged into P3-4b-3c) |
| P3-4b-3f | [Socket probe wired on a machine whose journal is the probe's own, so `Journaled` raises no false High on a busy machine; takes row 3g. Open question for Mark: dedicated probe machine (recommended), idle live machines, or per-effect attribution (#523 Potency 1, 3; L3 point 2)](briefs/P3-4b-3f.md). Also F11 from #560: `Config.Want` net-free plus a match test | P3-4b-3a, P3-4b-3c | queued (owner decision) |
| P3-4b-3g | Live-agent intents in `Journaled` (#523 L3 release point 2) | P3-4b-3a | dropped (merged into P3-4b-3f) |
| P3-4b-3h | [Detect a fuzzed input that hangs a worker: Go stops at `-test.fuzztime`, prints PASS, exits 0 and stores no input, so loop7 sees a clean step; flag a step whose exec count never moves past its baseline (Security re-sign and delta L3 on #560; loop7 F12, F13). Also: nothing closes a fuzz overrun (hang) finding today; the open finding suppresses the S39 "Cleared" message for later crash fixes in the same target, and the owner text says "crash" for a hang. The brief must define the closing evidence: close it, recorded as not a replay, after a new release completes the step within its bound. Correct F13's "If wrong" text, F13's and the `loop7.go` code comment's citation of "P3-4b-3c's rules" (merged 3c has no close rule for it), and F10, which makes the same 3c claim (from #560 and #558)](briefs/P3-4b-3r.md#p3-4b-3r-fuzz) | P3-4b-3a | building (P3-4b-3r-fuzz) |
| P3-4b-3h-r1 | Detect a fuzzed input that hangs a worker after the step's exec count has moved past its baseline: the stall rule (loop7 F12) sees only a count that never moved, so a later hang ends in a clean step; for example, compare the last two progress lines' counts (release, tier A; P3-4b-3r-fuzz) | P3-4b-3h | queued (release; needs brief) |
| P3-4b-3h-r2 | A hang finding's closing evidence (a good step's progress lines, `hang.json`) and `Resolve`'s PASS lines are the child's own output, which a fuzz child that runs code can forge; rest the closure on output the child cannot write (loop7 F13, F3; loops S32). Once P3-4b-3r-confine (#588) runs children as an unprivileged user that owns the state directory, a child can reach `hang.json` and the progress lines: hold the producer digest in loops' own state on the open record at `Report`, have `CloseTarget` compare `c.Binary` against it, and drop `hang.json`. Also: `run` returns combined stdout and stderr, so the progress lines are line-anchored with the last count winning, not only the engine's own (L3 on #586 point 2) (release, tier A; P3-4b-3r-fuzz) | P3-4b-3r-confine | queued (release; needs brief) |
| P3-4b-3a-r1 | [Audit and pin the fuzz and `agentosd` child processes that start with a minimal `Env` (`envExempt` children) so none inherits more than intended (release, from #560)](briefs/P3-4b-3r.md#p3-4b-3r-env) | P3-4b-3a | queued (release; built in P3-4b-3r-env) |
| P3-4b-3a-r2 | [The `chronyc` child env carries `AGENTOS_OWNER`: drop it (release, from #560)](briefs/P3-4b-3r.md#p3-4b-3r-env) | P3-4b-3a | queued (release; built in P3-4b-3r-env) |
| P3-4b-3a-r3 | [Fuzz children run as root with capabilities inside `agentosd`'s netns and cgroup with no `memory.max`: confine them (drop caps, own cgroup with `memory.max`, no net) (release, from #560)](briefs/P3-4b-3r.md#p3-4b-3r-confine) | P3-4b-3a | queued (release; built in P3-4b-3r-confine) |
| P3-4b-3a-r4 | [The fuzz cache is unbounded: bound it (release, from #560)](briefs/P3-4b-3r.md#p3-4b-3r-confine) | P3-4b-3a | queued (release; built in P3-4b-3r-confine) |
| P3-4b-3a-r5 | [Add a fuzz-status digest line (release, from #560)](briefs/P3-4b-3r.md#p3-4b-3r-pass) | P3-4b-3a | queued (release; built in P3-4b-3r-pass) |
| P3-4b-3a-r6 | [`secure.go:1307`: fix the wording and add a finding-text check (release, from #560)](briefs/P3-4b-3r.md#p3-4b-3r-fuzz) | P3-4b-3a | building (P3-4b-3r-fuzz) |
| P3-4b-3a-r7 | [ARC-2: guest-bridge `main.go:76` uses `append(os.Environ())`; pass an explicit env (release, from #560)](briefs/P3-4b-3r.md#p3-4b-3r-env) | P3-4b-3a | queued (release; built in P3-4b-3r-env) |
| P3-4b-3c-r1 | [`Pass`'s close loop ignores `failed` (release, from #558)](briefs/P3-4b-3r.md#p3-4b-3r-pass) | P3-4b-3c | queued (release; built in P3-4b-3r-pass) |
| P3-4b-3c-r2 | [`Pass` sends "Cleared" only for paused findings (release, from #558)](briefs/P3-4b-3r.md#p3-4b-3r-pass) | P3-4b-3c | queued (release; built in P3-4b-3r-pass) |
| P3-4b-3r-env | [No broker child inherits the daemon environment: explicit env for chronyc, runsc and the audio tools, no `os.Environ()` in an `Env`, check widened to `os.StartProcess` and `syscall.ForkExec`; carries 3a-r1, r2, r7 and 4c-env](briefs/P3-4b-3r.md#p3-4b-3r-env) | P3-4b-3a | queued (release; tier A declared) |
| P3-4b-3r-confine | [Fuzz children confined: own cgroup leaf with `memory.max` and `pids.max`, empty network namespace, unprivileged user, bounded fuzz cache; carries 3a-r3, r4](briefs/P3-4b-3r.md#p3-4b-3r-confine) | P3-4b-3a | queued (release; tier A declared) |
| P3-4b-3r-fuzz | [A stalled fuzz step is a finding, a hang finding closes on a new release binary that completes a good step, hang owner text, F10/F12/F13 and the "3c's rules" comments corrected; carries 3h and 3a-r6 (`secure.go:1307`)](briefs/P3-4b-3r.md#p3-4b-3r-fuzz) | P3-4b-3a, P3-4b-3c | queued (release; tier A declared) |
| P3-4b-3r-pass | [`Pass` keeps findings of a failed check open, texts "Cleared" for every texted finding, and STATUS says when fuzzing makes no progress; carries 3c-r1, 3c-r2 and 3a-r5](briefs/P3-4b-3r.md#p3-4b-3r-pass) | P3-4b-3a, P3-4b-3c | queued (release; tier A declared) |
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

Gaps found by comparing the build plan (§3) and spec v0.12 with this board, TRACE.md (31 of 144 IDs uncovered at a0feaa7) and the open PRs. **Unblocked** rows can start now in the cloud. Rows are in suggested order. P2-1 (plan P2 item 1) has a draft PR, #41, but no row of its own; IMG-1 adds its missing checks. Not listed: hardware-only IDs (HW-3 to HW-7, the N95 halves of HW-4 and A2), OSS-12 (Mark chooses the license), LOOP-7 (off-the-shelf testing is P3-4b-3 and P3-4b-4, outside A11 since D-070; finding a seeded vulnerability is later, P3-4c), CRED-2 (a scope statement, not testable), and CAP-7 (guest behavior, which the spec says is not infrastructure).

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
| IMG-2 | [Reproducible initrd, blocking two-runner check](briefs/IMG-2.md) | P2-1 | queued |
| IMG-3 | [Forced-fail fallback boot in CI](briefs/IMG-3.md) | P2-1, update package | queued |
| IMG-4 | [Broker cgroups check and agentosd.service hardening](briefs/IMG-4.md) | P2-1, P2-2 | queued |
| UX-41-2 | [Health result in STATUS and the digest](briefs/UX-41-2.md) | P2-1, W5 | queued |
| SR2-1 | [Approval texts show only canonical recipients](briefs/SR2-1.md) | — | merged (#144) |
| P2-2a | [Local-page approvals](briefs/P2-2a.md) | P2-2 | merged (6239bd4; #178 part 2) |
| P2-2w | [Local UI process and owner socket](briefs/P2-2w.md) | P2-2a | building (in sub-rows a, b, d, c (P3-2 thread)) |
| P2-2a f1 | [Page result after a changed item](briefs/P2-2a-f1.md) | P2-2a | merged (#329) |
| P2-2a f2 | [Page result for a changed release adoption](briefs/P2-2a-f2.md) | P2-2a f1 | in review (#363) |
| P2-2a f3 | [Re-offer an awaiting-owner release the pipeline dropped](briefs/P2-2a-f3.md) | P2-2a f2 | in review (#423) |
| P2-2a-f4 | After a release decision STATUS still says "Update N has been waiting for your approval" when no request is open (after the owner's NO or "not chosen"); a release is dropped on dispatch failure; a declined release is asked again after a restart. Fix in Loop 3 STATUS (release, tier A, L3 on #423 and UX on #423 point 1, UPD-5 and CH-12; brief to write) | P2-2a f3 | queued (needs brief) |
| P2-2w a | [`localui.sock` in agentosd](briefs/P2-2w-a.md) | P2-2a | merged (b00db30; #184) |
| P2-2w b | [`agentos-localui` command under its own uid](briefs/P2-2w-b.md) | P2-2w a | merged (0302131; #189) |
| P2-2w d | [LocalUI on (part 1)](briefs/P2-2w-d.md) | P2-2w b | merged (#322; split 2026-10-08; part 2 is d2) |
| P2-2w d2 | [Home page shows `Link.OwnerLineNote` and `Link.LastOutage`](briefs/P2-2w-d2.md) | P2-2w d | building (split into d2a, d2b) |
| P2-2w d2a | [Home page shows the owner line's note, last outage and counts](briefs/P2-2w-d2a.md) | P2-2w d | in review (#378) |
| P2-2w d2b | [Page control to confirm a SIM swap and set up the owner number](briefs/P2-2w-d2b.md) | P2-2w d2a | in review (#444) |
| P2-1-roles | Host image: agentosd can write the modem roles directory so an adopted SIM takes effect on a real box (until then adopting changes nothing; Potency on #444, release), and `/var/lib/agentos/modem` is not writable by `agentos-modem`, because `recordOwnerSIM` follows a symlink at `roles.json` (Security S1 on #444, release; fold into the P2-1 image) | P2-1 (#41), P2-2w d2b | queued (release; brief to write) |
| P2-2w-d2b-s2 | Two test gaps from #444 Security 4a (S2, release): no test pins clearing `adopted` after a SIM or state change (mutant M7), and none pins that the bridge sends no serial while the line is ok (mutant M12). Pin both; skip if #444 gains them before it merges. Also pin SR3-1 on adopt-SIM: a lock between the token check and the code must drop the session and adopt nothing (#444 M14: disabling adoptSIM's `locks != ses.locks` branch passes the localsrv tests; Security re-sign R1) | P2-2w d2b | queued (release; tier A; brief to write) |
| P2-2w c | [Setup moves into agentosd](briefs/P2-2w-c.md) | P2-2w b | building (split into c1-c3, each under one session) |
| P2-2w c1 | [Code seed made in the vault process and handed out once](briefs/P2-2w-c1.md) | P2-2w b | merged (#320) |
| P2-2w c2 | [Pairing and finish in agentosd](briefs/P2-2w-c2.md) | P2-2w c1 | in review |
| P2-2w c3 | [`agentos-netjoin`](briefs/P2-2w-c3.md) | P2-2w c2 | queued (#422 merged the re-brief only; `agentos-netjoin` is not built) |
| P2-2w c4 | Setup's remaining hooks in agentosd (the networks list, box number, host trust, texts, providers, real progress; joining a network is c3; `Online` must tell the owner when a saved home network never came online, since c3 may answer `saved`) and `agentos-localui` given `AgentosdSetup` (release finding on P2-2w c2; localui L28) | P2-2w c2 | queued |
| P2-2w c2 r1 | [Setup on a vault whose enrollment is closed](briefs/P2-2w-c2-r1.md): the vault answers "never opened" apart from "sealed", and the page says the box cannot finish setup instead of "already set up" with a Continue that finish refuses (release finding, L3 on #367; localui L28). Also: if the seal succeeds but the setup record is lost and the owner resets setup before retrying, every finish is refused; the vault answering "sealed by setup" apart from "never opened" lets agentosd accept the former at finish (release, L3 re-review on #367) | P2-2w c2 | in review (#465) (A) |
| P2-2w c3 r1 | D-Bus busconfig policy for `agentos-netjoin`: its uid may send only `Settings.AddConnection2`, `Settings.GetConnectionByUuid`, `Settings.Connection.Update2` and the property reads in L8.4, so a compromised helper can no longer `GetSecrets` or `Delete` (it can still rewrite the access point); one policy file and a parse test, foldable into c3 (release, L3 security on #422; [note](reviews/security/2026-10-08-p2-2w-l6-l8.md)) | P2-2w c3 | queued |
| P2-2w c3 r2 | L1 spec diff: host network secrets (the access point's and the home Wi-Fi password) are held by the host network stack, outside ARC-1, and stay subject to CRED-1 and CRED-8. ARC-1 read literally cannot be met: the supplicant must hold the PSK or its PMK (release, spec-gap, L3 security on #422) | — | queued (L1 spec diff) |
| P2-2w c3 r3 | P2-1: NetworkManager's connection store must not leave the home PSK in plaintext on the drive (CRED-8 says a lost drive is ciphertext; CRED-1 counts passwords). Choose one: the store on an encrypted volume, or in-memory connections (`AddConnection2` in-memory) re-added by agentosd through the helper after each vault unlock, which also settles r2 and amends L8.7 (release, L3 security on #422; [note](reviews/security/2026-10-08-p2-2w-l6-l8.md) L8.6) | P2-1 (#41), P2-2w c3 | queued (blocked on P2-1) |
| P2-2w c3 r4 | P2-1/IMG-1 facts c3 rests on: a Wi-Fi station device beside the always-on access point (one radio in AP+station mode, or a second adapter), made at boot; no seat or console session on the image (NetworkManager's `allow_active=yes`); NetworkManager with `auth-polkit=true`; polkit that reads JS rules (0.106 or later). Without the station device the helper only ever answers `saved` (release, L3 security on #422; [note](reviews/security/2026-10-08-p2-2w-l6-l8.md)) | P2-1 (#41), P2-2w c3 | queued (blocked on P2-1) |
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
| SR2-3n | [No runsc crash trace reaches the guest, and the guest cannot pick the logged part](briefs/SR2-3n.md) | SR2-3m | in review |
| SR2-3o | [Malformed-request refusals keep a field-level hint for the guest](briefs/SR2-3o.md) | SR2-3j | dropped (#461: unreachable behind guest/mcp.go:263 and grants/gate.go:915) |
| SR2-3p | [A command that cannot start is not told to retry](briefs/SR2-3p.md) | SR2-3j | in review (with SR2-3q, one PR) |
| SR2-3q | [A runsc failure after the command may have started is not told it did not start](briefs/SR2-3q.md) | SR2-3j | in review (with SR2-3p, one PR) |
| SR2-3n-p1 | Real-runsc test that a guest exit 2 with output stays a result: only the fake runsc tests it, and `TestIntegrationWorkerExec` exits 3, while exit 2 plus any runsc stderr counts as a runsc crash (CAP-8; Potency on #466; release; one argument, so it can ride the next SR2-3n push; brief to write) | SR2-3n | queued (release) |
| SR2-4 | [cgroup cpu, io and pids controllers](briefs/SR2-4.md) | #143 (RES-2 text) | merged (#155) |
| SR2-4i | [Host side of SR2-4](briefs/SR2-4i.md) | SR2-4 merged; host image | queued (blocked on the host image) |
| SR2-5 | [Second-line sends](briefs/SR2-5.md) | #143 (ADP-12 text) | merged (2e85d06) |
| SR2-7 | [Per-sender cap on the multi-part text buffer](briefs/SR2-7.md) | — | merged (5cddc94) |
| SR2-8 | [METRICS.md counts only collaborators](briefs/SR2-8.md) | — | merged (64220e9; #162) |
| SR2-9 | [ci.yml pins actions by SHA](briefs/SR2-9.md) | — | merged (64220e9; #162) |
| CH-21 | [Name and first-person voice](briefs/CH-21.md) | CH-12 strings; P2-3 | queued (split into CH-21a to CH-21e) |
| CH-21a | [First-person voice: lint test and tier-B sweep](briefs/CH-21a.md) | CH-12s | building (primary lane) |
| CH-21b | [Box name: setup suggestion and `NAME`](briefs/CH-21b.md) | CH-21a | queued (tier A) |
| CH-21c | [First-person voice: owner-page and recovery texts](briefs/CH-21c.md) | CH-21a | in review (all 13 packages swept; `owner` stays pending for CH-21e's `Agent: ` prefix) |
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
| W3-forget-b1-4 | [Owner confirms a restore with no anchor](briefs/W3-forget-b1-4.md) | W3-forget-b1, D-065 (#406) | Next build item B | merged (c422039; #436) |
| W3-forget-b1-5 | [The vault keeps the forget log for agentosd](briefs/W3-forget-b1-5.md): #409 R1 and P3; #409 R5 (c) and Security R4, moved from b1-6 and b1-7; the vault's log replaces the learn-dir file as the replay source (from b1-6); #409 Security L1 (f3), sealed destination copies from the one writer, and the forgetLog ordering test (moved from b1-6 by #519); #436 Potency (Q5) Also (#503 L3 re-review, release): b1-5 depends on b1-6's code (requirement 10 needs b1-6's learn-dir trust check; requirement 9 edits b1-6's new restoreentry.go); record in the package's ASSUMPTIONS.md that after AEAD sealing (req 9) destination copies are all-or-nothing, so b1-6's prefix rule is not expected to fire on them. | W3-forget-b1, W3-forget-b1-6 | Next build item B | queued (waits for W3-forget-b1-6, which waits on Mark's (d) ruling; requirement 7 also pending Mark) |
| W3-forget-b1-6 | [The restore entry checks the forget log safely](briefs/W3-forget-b1-6.md): #409 R2, R3, R5 (a), (b), (d), L2 (f4) and L3; #436 Security point 2; #487 UX point 1 (no held page; the restore prints the hold); #519's L3 points; R5 (c) and R4 moved to b1-5 Also (#503 L3 re-review, release): the new `agentosd.lock` lives in the socket dir (`/run/agentos`, tmpfs), so `RestoreBox` must create that dir privately (0700, owner uid) if it is missing, with the uid assumption in the package's ASSUMPTIONS.md; and see the b1-5 row for the (d) dependency. | W3-forget-b1, W3-forget-b1-7 | Next build item B | queued (pending Mark's (d) ruling; build waits) |
| W3-forget-b1-7 | [Text the owner a held restore, and take their answer](briefs/W3-forget-b1-7.md) | W3-forget-b1, W3-forget-b1-4 | Next build item B | building |
| W3-forget-b2 | [Builder-lineage rollback with A/B](briefs/W3-forget-b2.md) | W3-forget-a | Next build item B | merged (#321) |
| W3-forget-b2b | [Agent machine's work taken back as item 2](briefs/W3-forget-b2b.md) | W3-forget-b2 | Next build item B | merged (#327) |
| W3-forget-b3 | [Promised done text survives a restart](briefs/W3-forget-b3.md) | W3-forget-b1 | Next build item B | merged (4b60dc2; #425) |
| W3-forget-b2c | [Owed take-backs for W3-forget-b2b](briefs/W3-forget-b2c.md) | W3-forget-b2b | Next build item B | merged (#427) |
| W3-implicit | [Report accepted-implicitly guest effects](briefs/W3-implicit.md) | W3 PW3 | — | queued |
| W3-forget-b2c-2 | [Item 2's texts (`forgetAgentDone`, `forgetAgentNotYet` and the rest) are owed until they send](briefs/W3-forget-b2c-2.md), as W3-forget-b3 does for item 1; add a check that no done text in `ownerForget` reaches `inform` directly (release, UX-182-3 / CH-12; Defect: W3-forget-b2c; L3 on #425, second PR with this kind of finding) | W3-forget-b2c, W3-forget-b3 | Next build item B | merged (d63322a; #541) |
| W3-forget-b2c-f1 | [The in-boot retry of an owed take-back is unbounded and gives the owner no signal on a permanent error: bound it and add a STATUS line; send the done text on the restore path, for item 1 too (a restore that replays an item 1 forget still retrying owes the `forgetNotSaved` owner its done text; L3 release 2 on #559), and bound the silence on retries (folds the UX point f4)](briefs/W3-forget-b2c-f1.md) (release, tier A, L3 on #427; also Security #541 P1, the CH-12-lint; folds f2; builds after W3-forget-reach) | W3-forget-b2c | Next build item B | queued |
| W3-forget-b2c-f2 | [Restore the `ErrNotOpen` no-retry test guard](briefs/W3-forget-b2c-f1.md) (release, L3 on #427; F1-4 of the f1 brief) | W3-forget-b2c | Next build item B | queued (folded into W3-forget-b2c-f1) |
| W3-forget-b2c-f3 | [Privacy: restore while a done text is still owed](briefs/W3-forget-b2c-f3.md): an item 1 forget still retrying is not yet in the forget log (release, tier A, L3 on #427; replaces the earlier idea of a LATER line; builds first of f3, W3-forget-reach, f1) | W3-forget-b2c | Next build item B | building |
| W3-forget-b3r | [The local Wi-Fi page lists older tasks and can forget one](briefs/W3-forget-b3r.md) (potency R2, carried by W3-forget-b3; needs a page, socket route and forget path in `broker/localui`; release, L3 on #425; tier A, build on the strongest model) | W3-forget-b3 | Next build item B | merged (67ff471; #522) |
| W3-forget-b4 | [Fix #425 Security 4a S1-S3](briefs/W3-forget-b4.md): (S1) `learn.go` renames an unreadable owed file to `.bad` before `lostForgetOwed` saves the file that owes `forgetOwedLost`, so a crash between the two leaves the owner never told: keep it aside by hard link, then save the fresh file over it; (S2) in `Execute` a failed owed save is only logged, so a `retry` followed by a crash replays the forget with no done text owed (CAP-3): retry the save in `retry` or record it in ASSUMPTIONS; (S3) no test pins F4's order (tell the owner, then drop the entry; mutant M4 passes): add one whose owner send records the owed file's content at send time (release, tier A, Security 4a on #425, [note](reviews/security/2026-10-09-pr425-sec4a.md); its PR carries `Defect: W3-forget-b3`) | W3-forget-b3 | Next build item B | merged (#528) |
| W3-forget-reach | [Expose recall's done-or-owed signal (done means `Prov.TakenBackFrom(since)` and not in `Prov.TakeBacksOwed()`) as a `Reach` method in `broker/recalltool`](briefs/W3-forget-reach.md), so item 2 can save its owed entry before `takeBack` and close both b2c-2 residuals: the crash window between `takeBack` and the save, and a `TakenBack` owed by recall's `Retry` not surviving a restart (release, tier A, UX-182-3; L3 delta on #520, R1, [record](reviews/l3/2026-10-09-pr520-delta.md); also Security #541 P2: done only once the reset's reach is finished; builds after f3, before f1) | W3-forget-b2c-2 | primary; unclaimed | queued |
| W5 | [Owner channel](briefs/W5.md) | W3 | loops thread | queued |
| W5-Da | [Digest contract and durable digest queue](briefs/W5-Da.md) | W3 | builder (session_016Pe6Mkjo6CE6tLLdb2qAmX) | merged (a41c68d; #555) |
| W5-Da-r1 | Status wording and resolution path for surfaced digest states (unknown, not-sent-exhausted, expired, `Held`) ship with the first sender (release, lens 4 on #555) | W5-Da | Next build item B | queued (folded into W5-Dc, [brief](briefs/W5-Db.md)) |
| W5-Da-r2 | How a forgotten, still-unacknowledged source generation is acknowledged or requeued after `Forget` cancels its batch (release, L3 4 on #555) | W5-Da | Next build item B | queued (folded into W5-Db, [brief](briefs/W5-Db.md)) |
| W5-Da-r3 | Decide whether `broker/digestqueue` joins `TIER_A_BROKER` once W5-Db makes `Begin` the gate on an owner-facing send (release, L3 5 on #555) | W5-Da, W5-Db | Next build item B | queued (folded into W5-Db, [brief](briefs/W5-Db.md); decided: tier A) |
| W5-Da-r4 | Decide in W5-Db how a held batch (ready, past expiry, some source consumed) is resolved: `Collector.recover` currently acks its remaining sources although `Begin` will never send it; either skip held batches or say recover may finish them, and add a test (release, L3 delta on #555) | W5-Da, W5-Db | Next build item B | queued (folded into W5-Db, [brief](briefs/W5-Db.md)) |
| W5-Db | [Digest sender contract: `Begin` as the single gate, classified modemlink receipt, held/expired/forget resolution](briefs/W5-Db.md#w5-db-sender-contract-tier-a) | W5-Da | Next build item B | building (#573; A; folds W5-Da-r2 to r4) |
| W5-Dc | [Digest wiring into agentosd: store, daily send, STATUS lines, forget hook](briefs/W5-Db.md#w5-dc-wiring-into-agentosd-tier-a) | W5-Db | Next build item B | queued (A; folds W5-Da-r1) |
| W5-Dc-r1 | Owner quiet hours and unsolicited-text pacing (CH-15: default 3 per hour, owner-set; quiet hours hold all but STOP/RESUME confirmations): none exist in `owner`, so the digest and every other owner text ship without them; checks run before `Sender.Send` (release, L3 1 on #565) | W5-Dc | Next build item B | queued |
| W5-Dc-r2 | Digest time: L1 spec-diff for its default value (SPEC lists it with none; W5-Dc uses provisional 08:00 box-local, SG-2) and a package for the owner's text setting (release, L3 7 on #565) | W5-Dc | Next build item B | queued |
| W5-Dc-r3 | SG-3: L1 spec-diff for what goes out when the digest store is unavailable at the digest time (CH-15 "always sent" against OP-9); Mark rules whether W5-Dc's provisional DC-8 outage line is kept or removed (release, L3 delta on #565) | W5-Dc | Next build item B | queued |
| W5-Dc-r4 | Digest attempts: a NotSent from line-down or a full queue costs one attempt, so pick `limits.MaxAttempts` and the retry cadence (DC-1, DC-2) so a few hours of outage cannot exhaust a batch; the PR states how many daily tries it allows (release, lens on #573) | W5-Dc | Next build item B | queued |
| W5-Dc-r5 | Source-side forget duty end to end: a forgotten reference re-offered by a source in a higher generation is never sent; test it across `ownerForget`, the sources and the queue (release, L3 on #573; shared with DIG-1, which owns the sources) | W5-Dc | Next build item B | queued |
| W5-Dc-r6 | Digest evidence carries no personal data: the evidence regex accepts any digit string, so a phone number could persist as `Evidence`; test that the W5-Dc adapter persists only `Receipt.Evidence` (an item ID or fixed tag) (release, Security F3 on #573; reclassed from later by L3 delta on #573, OPERATING §2) | W5-Dc | Next build item B | queued |
| W5-Db-r1 | `CodeRecipient` proof scans whole packages: `TestRecipientCodeOnlyBeforeModemSend` parses only `at/driver.go` and `bridge/bridge.go`; scan every non-test file in `broker/modem/at` and `broker/modem/bridge` (`parser.ParseDir`) and assert `outbox` assigns `CodeRecipient` before `m.Send`, in the next package that touches `broker/modem/` (release, Security F2 and lens on #573; reclassed from later by L3 delta on #573, OPERATING §2) | W5-Db | Next build item B | queued |
| UX3-1 | [Visible provider sign-in and bounded retry](briefs/UX3-1.md) | P2-2w c4 | primary; unclaimed | queued (A; from #405) |
| UX3-6 | [Inspect every approval item over the owner channel](briefs/UX3-6.md) | L1 read-only command grammar | primary; unclaimed | queued (A; from #405) |
| UX3-7 | [Truthful, bounded withheld-result retrieval](briefs/UX3-7.md) | CH-20p minimum split promoted to Release in LATER.md (D-079 spec-diff) | primary; unclaimed | queued (A; from #405) |
| UX4-1 | [Preserve explicit choices on failed setup retries](briefs/UX4-1.md) | P2-2w c4; UX3-4 (acc. 6 only) | primary; unclaimed | queued (A; from #417) |
| UX4-2 | [Visible phone fallback and actionable errors](briefs/UX4-2.md) | P2-2w c4 | primary; unclaimed | queued (A; from #417) |
| W5a | [Loop 2 passive checks](briefs/W5a.md) | #54 merged, W3 | builder B (lenses) | merged (3d2daab; #169) |
| W5a-resume | [Per-grant resume on the local page](briefs/W5a-resume.md) | W5a, local page | builder (session_014jQE43g7uFA46BsQJD3VGh) | in review (tier A) |
| W5b | [Loop 3 update checks](briefs/W5b.md) | #53 merged, W3, network state (P2-3 modem or Wi-Fi) | Loop 3 thread (P3-5) | queued |
| W5c | [Clean-room builder](briefs/W5c.md) | #43 merged, W3 | clean-room thread (P4-2) | queued |
| W6 | [Recovery into the vault process and local UI](briefs/W6.md) | `vault.Reencrypt` (#45, P2-4d) merged and used by rotation; the restore command calls W3-forget-b1-6's restore entry (its vault-process endpoint closes its vault around the swap and leaves the learn-dir files owned by agentosd's uid), and the backup run writes b1-5's forget log copy to each destination | recovery thread (P2-8), after #64 | queued |
| W7 | [Compiled skills in live use](briefs/W7.md) | `suite.go` split, #52 merged | compiled-skills thread | queued (blocked) |
| W8 | [Owner builds](briefs/W8.md) | P2-4f | — | queued (blocked) |
| W9 | [Questions in the guest plane](briefs/W9.md) | P3-8 merged, #68 merged | — | merged (f38aeed8) |
| W9a | [Questions follow-ups (#95)](briefs/W9a.md) | W9 | Next build item A (part 2) | merged (#125 (part 2; part 1 #98)) |
| CH-20w | [Evidence delivery](briefs/CH-20w.md) | CH-20 merged; P2-6m wired into the vault process | — | queued (blocked on mail wiring) |
