# KRN-forget: the owner's erase by name, with sessions rewound before the reply (LOG-4, OWN-6, CH-25, D-169)

Work item: #3179 (the owner half of #2823; the kernel half merged in #3160, its fixes in #3182, the backup re-wrap in #3212 and the kernel process's erase wait in #3338). Tier A. Three slices, built in order: **a** #3413 (kernel and the owner socket), **b** #3179 (agentosd: the forget flow, the rewind and STATUS; the integration owner) and **c** #3414 (the owner's surface, pending one decision below).

## Goal

The owner names something ("Alice"), sees what the box holds under that name, confirms, and the box erases it (LOG-4). Before the owner is told, every agent session that read the erased content goes back to before that read and drops what it built from it (LOG-4, D-169). The answer leads with the outcome and says plainly what is not finished (OWN-6, LOG-4 fails closed).

## What main has today (checked at 90dd141)

- The kernel has subjects, sealed content, `Named`, `Erase`, `Confirm`, `Recall` and `Unerased` (`broker/kernel/erase.go`). The kernel process opens the key table at start (`kernel/proc/kernel.go:137`, #3230) with **no content stores**, and its `Erase` waits for backup re-seals without the lock (`proc.Kernel.Erase`, #3338).
- The owner socket (`kernel/proc/kernelsock.go`, `OwnerSide`) has **no** erase, named, recall or unerased call. agentosd's client (`owner/kernelsock`) has none either.
- **Nothing records which agent session read which sealed item.** KRN-erase left that to this row ("need planner and projection read tracking that the kernel does not have"). `vm.Manager.ForgetSince(lineage, since)` already rewinds a lineage and every fork of it, and passes the reset to the guest plane (`lateServices.Reset`, FORGET-FOLDS-3). `recallHeld` (`cmd/agentosd/recallheld.go`) already does the same job for the old recall's lineages: contain, roll back at start, record it, tell the owner.
- **No production path seals content or hands sealed content to a planner yet.** So in production `Named` finds nothing until a producer (mail bodies, photos under CH-26) seals under subjects. This row builds the erase and rewind path end to end against sealed test content; the producers and their delivery path are later rows, and design 2 makes them record their reads.
- `FORGET` texts get a fixed "not in this version" reply (`learnstate.go`, `forgetOffText`), and STATUS shows `forgetNotRunning` (`capoff.go`).
- The issue's "older backups may hold it on every erase" point is overtaken: `Confirmation` now names `Resealed` and `StillHeld` backups, or sets `BackupsUnknown` when no backup list is open (D-168, #3212).

## Decision needed (gates slice c only)

**SPEC v1.0 has no FORGET.** CH-11's control words are a closed set without it, and a text that is not a whole control word goes to the planner. CH-3 has no row for an erase. The only deletion surface SPEC describes is CH-26's, for photos: the box texts an owner-page link, and the page step deletes, as a LOG-4 erase. Options:

- **A. The owner page (recommended).** A signed-in page step: type a name, see the count and kinds found, confirm with a passkey tap over that list (the e4b tap pattern). A `FORGET` text gets a fixed reply naming the page. *For:* no SPEC change (this lane may not edit SPEC); a passkey proof, which a SIM swap cannot fake, for an act that destroys data; the same surface CH-26 already gives photos. *Against:* only where the page reaches (at home); more page code.
- **B. A `FORGET <name>` control word with a texted code.** The reply lists what was found and carries a one-time code; `YES <code>` erases. *For:* works from anywhere; less code. *Against:* needs an L1 spec-diff (CH-11 and a CH-3 row) outside this lane; a SIM swap can then erase the owner's data.

Slices a and b do not depend on the answer: b exposes `find` and `confirm` that either surface calls. Until Mark picks, slice c is not started.

## Design

1. **Owner-socket calls (a).** `OwnerSide` gains `named` (a label, at most 256 bytes; answers the found and unread subject IDs, never label text), `recall` (`State.Recall` of one subject, for the confirmation's counts and kinds), `erase` (a `procOp` calling `proc.Kernel.Erase`, so the backup waits stay outside the lock), `unerased` (`State.Unerased`) and `erasedreads` (design 2). `ErrContentClosed`, `ErrSubject` and `ErrErased` join `wireErrors`. No side gets a plain `read`: no socket returns sealed plaintext to anyone, which is the CH-25 and #3160 Security gate on `Read` and `Named`. The meter and clerk sides get none of these calls.
2. **Read tracking in the kernel (a).** `Kernel.ReadFor(now, hash, lineage)` is the only way sealed content may reach an agent session: it logs `content.read {hash, lineage}` (version 1, narrowing; a new type in the closed set, LOG-5), then opens the item; if the entry is not written, nothing is returned. `State.ErasedReads()` lists, for every erased subject, each lineage that read one of its items and the time of its first such read. It is a projection of the log (LOG-1), so it survives restarts and rebuilds from empty. `ReadFor` is not on any socket in this row: the first delivery row adds its call, and marks what it delivers as untrusted content (CH-25). The kernel's ASSUMPTIONS records the rule: a path that gives sealed content to a planner calls `ReadFor`.
3. **Matching (a).** `Named` compares labels after folding case (`strings.EqualFold`) and collapsing runs of whitespace, so "alice  smith" finds "Alice Smith". Fuzzier matching (a local retrieve pass, PLN-7) is later (Potency, #3160 issuecomment-6399688037).
4. **The forget flow (b).** `forgetFlow.find(name)` calls `named` and `recall` and returns a pending forget: the exact subject IDs found, the counts by kind, whether any subject could not be checked (`unread`), and a random one-time handle that expires after 10 minutes. `confirm(handle)` erases exactly those subjects (never re-resolving the name), each once; one erased meanwhile is reported, not an error. The kernel does not authenticate `Erase` (KRN-erase design 4), so the surface (c) must prove the owner before it calls `confirm`.
5. **The rewind before the reply (b, D-169).** After the erases return, b reads `erasedreads`, takes each lineage not yet settled, marks it contained (`vm.Config.Contained` and `grants.Config.Contained`, composed with `recallHeld.Contained`), calls `ForgetSince(lineage, firstRead)`, and records the lineage settled in `erase-rewound.json` in the machines directory (the `recall-settled.json` pattern, privfile atomic write). When any lineage read the content it also calls `keptReplies.forget()` (`evidence.go`, kept for exactly this), so kept and held agent replies built from it go too. Only then is the result returned to the surface. A rewind that fails leaves its lineage contained, says so in the result and in STATUS, and is retried at the next start.
6. **The start-up pass (b, D-169).** At each start, after the machines open and before any is served (where `recallHeld.settle` runs), b reads `erasedreads` and rewinds every lineage not settled, then tells the owner of each rewind not yet told. This covers a crash anywhere between the erase entry and the reply.
7. **The result, conclusion first (b, OWN-6).** One result type rendered by fixed wording, from `Confirmation`:
   - Done: "Forgot everything named Alice (3 items). It can no longer be read." Never "deleted from the disk" (#3160 Security: a crash can leave orphan ciphertext in a store).
   - Not finished, from `Unconfirmed`, never from `Unerased.Items` (which counts all items even when only the key is owed): `KeyTable` is rendered "the key", never `key-table`; a store by its plain name. "Not finished: the mail store has not deleted them yet. I keep trying, and STATUS shows it."
   - Backups: each `StillHeld` named with why; `BackupsUnknown` says older backups may still hold them; `Resealed` adds nothing.
   - `unread` subjects: "Some things could not be checked, so anything named Alice in them is still kept." `ErrContentClosed`: "Stored content can't be read right now, so nothing was forgotten."
   - Agents: "Your agent went back to before it read them" after a rewind; "Your agent could not go back yet; it is held from copying itself until it does" on a failure.
8. **STATUS (b).** `forgetNotRunning` goes. While `unerased` lists anything: one line per erase, by count and the stores owed, never by name ("Forget not finished: 1 erase waits on the key; I keep trying."). The owner's name is never kept: an erased label is unreadable by design. A contained lineage has its own line. An unreachable kernel gives one line, not silence.
9. **The surface (c).** Under A: `localapi` ops and codes, `localsrv` handlers with bounds and a rate, a `localui` Forget page behind sign-in (find, readback, passkey tap, result), and `forgetOffText` names the page. Under B: the control word in the owner channel and its code, after the spec PR. Either way it calls only b's `find` and `confirm`.

## Lifecycle matrix (integration owner: slice b)

| Stage | Outcome | What holds |
|---|---|---|
| find | kernel unreachable or content closed | nothing erased; the result says why; no handle |
| confirm | crash before `subject.erased` | nothing erased; the handle is gone; the owner asks again |
| confirm | crash after `subject.erased`, before the rewind | start: lineage contained, rewound, settled, owner told |
| rewind | `ForgetSince` fails | lineage contained; STATUS line; retried at start |
| rewind | crash after `ForgetSince`, before the settled write | start rewinds again (later work is taken back too: fails closed, ASSUMPTIONS) |
| reply | crash after settled, before the owner is told | start tells the owner once |
| stores | a store or the key delete fails | `unerased` lists it; STATUS by count and store until the kernel's Tick confirms |
| restart | normal | settled lineages are not rewound again; `erasedreads` rebuilds from the log |

## Not in this row

- Sealing producers (mail, photos) and their delivery to the planner through `ReadFor`; procedures and indexes rebuilt without an erased item (LOG-4's last sentence) wait for those producers.
- Start-up surfacing of `ContentReport.Unnamed` and `Missing` (#2682), restore's erase hold (#2865).

## Scope

- **a:** `broker/kernel/erase.go`, `broker/kernel/state.go` (the entry type), `broker/kernel/rederive.go` (`content.read` joins `recorded`), `broker/kernel/erase_test.go`, `broker/kernel/ASSUMPTIONS.md`, `broker/kernel/proc/kernelsock.go`, `broker/kernel/proc/kernelsock_test.go`, `broker/kernel/proc/content_test.go`, `broker/kernel/sim/erase.go` and `sim_test.go` (reads in the sim's crash run).
- **b:** `broker/owner/kernelsock/kernelsock.go` and its test (the client calls), new `broker/cmd/agentosd/forget.go` and `forget_test.go`, `broker/cmd/agentosd/main.go` (wiring and the start-up pass), `capoff.go`, `capoff_test.go`, `recallheld.go` (the composed `Contained` only), `broker/cmd/agentosd/ASSUMPTIONS.md`.
- **c (under A):** `broker/localapi`, `broker/localsrv`, `broker/localui` (a Forget page and its tests), `broker/daemon/daemon.go` (a `PageSocket` field), `broker/cmd/agentosd/learnstate.go` and its test.

**Guard files:** none (no new broker package). Slice a grows the trusted core (kernel and kernel/proc): before its build PR, a one-row DECISIONS.md PR under D-159 cites LOG-4 and D-169 (Mark's card cmsg_01R91wiieBzMSvPKFsAJVvuKTjvTbiZomrrfU1GfSTA8nx), and the PR carries its `Trusted-core:` line.

**Order (D-111).** No open PR touches slice a's files at 90dd141, so a can start now. b touches `cmd/agentosd` and `owner/kernelsock`, which #3403 holds, so it takes the serial agentosd slot after #3403. c follows b, and the decision.

## Acceptance tests

**Acceptance tests:**
- LOG-4 read tracking (a): `broker/kernel/erase_test.go::TestReadForLogsBeforeItOpens`: a failing log write returns no plaintext; after erase, `ErasedReads` names the lineage at its first read and a second read does not move it. Catches a delivery that leaves no record.
- LOG-1 (a): `erase_test.go::TestErasedReadsRebuildFromEmpty`: a replayed state equals the live one, `ErasedReads` included.
- LOG-5 (a): `erase_test.go::TestContentReadIsKnownAndNarrowing`.
- Matching (a): `erase_test.go::TestNamedFoldsCaseAndSpace`: "alice  smith" finds "Alice Smith"; "Alicia" does not.
- CH-25 gate (a): `broker/kernel/proc/kernelsock_test.go::TestNoSideReadsSealedContent`: no side's table has `read` or `readfor`; only `OwnerSide` has `named`, `recall`, `erase`, `unerased`, `erasedreads`; `named` answers carry no label text. Catches a socket that leaks plaintext.
- LOG-4 over the socket (a): `kernel/proc/content_test.go::TestEraseOverTheOwnerSocket`: seal, `named`, `erase`, then `unerased` empty and the item unreadable; a store that refuses delete stays in `unerased`.
- SIM-erase (a): `broker/kernel/sim/sim_test.go::TestSimEraseReachesEveryViewOnce` extended with reads: after every crash point, `ErasedReads` names each reader once.
- D-169 rewind before reply (b): `broker/cmd/agentosd/forget_test.go::TestTheReplyFollowsTheRewind`: a fake `ForgetSince` blocks; `confirm` does not return until it does, the lineage is contained meanwhile, and kept replies are dropped. Catches a reply sent first.
- D-169 start-up (b): `forget_test.go::TestStartRewindsWhatACrashLeft`: an erased subject with a reader and no settled record is rewound before any machine is served, and the owner told once; a settled one is not rewound again.
- Fail closed (b): `forget_test.go::TestAFailedRewindStaysContained`: `ForgetSince` fails; the lineage refuses fork and merge, STATUS has its line, the next start retries.
- Exactness (b): `forget_test.go::TestConfirmErasesOnlyWhatWasShown`: a subject labelled the same after `find` is not erased; an expired or reused handle erases nothing.
- OWN-6 wording (b): `forget_test.go::TestForgetResultWording`: a table of `Confirmation`s (key owed, a store owed, `StillHeld`, `BackupsUnknown`, unread, content closed) gives fixed texts that lead with the outcome, say "the key" and never `key-table`, never promise deletion from a disk, and take "not finished" from the stores.
- STATUS (b): `broker/cmd/agentosd/capoff_test.go::TestForgetStatusLines`: an unconfirmed erase gives a line by count and store, with no name; nothing owed gives no line; `forgetNotRunning` is gone.
- Surface (c, under A): `localsrv` and `localui` tests that an unsigned or replayed tap, or a tap over a different list, erases nothing, and that the page shows b's result text unchanged.

## Estimate

a: about 60k tokens (roughly 120 lines of kernel and proc code, 250 of tests). b: about 110k (300 lines, 400 of tests); checkpoint at 130k. c: about 80k. Each is one session.
