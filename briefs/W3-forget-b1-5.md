# W3-forget-b1-5: The vault keeps the forget log for agentosd

Board section: Integration: wiring merged packages into the box. Part of W3-forget-b1 (briefs/W3-forget-b1.md); SPEC CAP-3, A8.

**Goal:** forgets reach the authenticated log. Today `ownerForget.forgetLog` (`broker/cmd/agentosd/forget.go`) is nil in production, so `logForget` returns false and every forget's done text carries part a's caveat; `recovery.AppendForget` and `ExportForgetLog` (`broker/recovery/forgetlog.go:287`, `:367`) have no caller outside tests. #409 P3 ordered that the logger stays nil until the restore check is wired (W3-forget-b1-6, on which this package depends). After this package the vault process serves both calls to agentosd, agentosd appends each forget and keeps the learn dir's copy current, and agentosd cross-checks the vault's record of a held restore at start.

**Requirement IDs:** CAP-3 (forgets propagate) and A8, as in W3-forget-b1; security C3; ARC-1 (only the vault process holds the log's key and imports recovery). Tests carry `REQ: CAP-3, A8` (add ARC-1 on the import and socket tests).

**Sources:** BOARD row W3-forget-b1-5; #409 Security R1 and P3; #409 Security R5 (c) and L3, moved here from W3-forget-b1-6 (its "Placed elsewhere"); #409 Security R4, not carried by W3-forget-b1-7 (#487); `reviews/potency/2026-10-08-pr436.md` point 1; `broker/recovery/ASSUMPTIONS.md` Q5 and the b1-4 follow-ups paragraph.

## Requirements (each with a test)
1. **The vault serves the log** (R1). `cmd/agentos-egress` serves two calls on its socket: append a forget (goal, time, since, agent) through `AppendForget` with its TPM counter (`tpmCounter`), and export the log through `ExportForgetLog`. Only agentosd's uid may call them (peer credentials, as the socket's other per-caller checks do); the reply to an append is the exported log or a refusal reason, never the key. A locked vault refuses. Tests: agentosd's uid appends and exports; another uid is refused; a locked vault refuses; `ErrNoForgetLog` comes back as its own reason.
2. **agentosd appends each forget** (R1, P3). Production `main.go` sets `ownerForget.forgetLog` to a client of requirement 1. On success the done text drops part a's caveat; on any refusal (`ErrNoForgetLog` before the recovery key is set up, a locked vault, a down socket) `logForget` returns false and the caveat stays, so the owner is never told a forget is logged when it is not. Tests: success drops the caveat; each refusal keeps it; the goal text is not logged by agentosd.
3. **The learn dir's copy stays current.** After each successful append agentosd writes the returned log to `<learn dir>/forget-log.json` with b1-4's `writeSynced`, so the next backup's bundle carries it (the restore's own copy). Test: after an append the file holds the vault's export byte for byte; a failed write is logged and keeps the caveat.
4. **A copy at each destination.** `recovery` gains one function the backup run calls after `RecordBackup`, writing `ExportForgetLog`'s output to the destination under the name W3-forget-b1-6 reads. The production backup run is W6's (no backup runner is wired today); W6's row gains the call. Test: write, then b1-6's reader reads it back as an authentic copy.
5. **(c) A start without the marker cross-checks the vault** (#409 R5 c). The vault's status reply carries `State.Pending` (the reason only). At start, after `restoreHold` passes, agentosd asks; if the vault reports a pending reason and the marker is absent, agentosd enters W3-forget-b1-7's held mode (`heldMode`, `held.go`) with that reason's notice and no question. A vault that is locked or unreachable at start does not block the start; agentosd asks again when the vault reports unlocked, and holds then (closing machines it opened). Tests: pending in vault + no marker → held; "" → normal start; locked then unlocked with pending → held after unlock.
6. **The vault forgets a released hold** (b1-4 follow-up: "`State.Pending` is not cleared by the answer"). When `answerHeld` releases, agentosd tells the vault; the vault clears `State.Pending` only if the marker is gone and the learn dir's `forget-log.json` opens under its forget key. Without this, requirement 5 would hold a released box forever. Tests: release clears it; a clear request with the marker present, or with a log that does not open, is refused and the box stays held.
7. **Q5 says what the decoys do** (#436 Potency point 1a). Reword `broker/recovery/ASSUMPTIONS.md` Q5: drop "on average the real date is anywhere in the list"; state that when the last forget falls within 45 days of the backup, the real date is always the latest one shown, and that "later than all of these" stays offered. Test: an existing decoy test, or a new one, pins that case (last forget within 45 days of the backup → no decoy after it), so the record and the code cannot drift.
8. **Restored take-backs run before any agent machine opens** (#409 Security R4). On the start after a release, the learning plane's replay of the restored log (`readRestoredForgets`, `learn.go:110`) finishes, and its take-backs are applied, before the first agent or replay machine opens; if the replay fails, no machine opens. Test: release with a log holding a canary forget, then assert the take-back is recorded before the fake machine opener is first called, and a replay error leaves the opener uncalled. If this needs a restructuring of the start order beyond the replay call, split it into a release row rather than widening the package.

## Acceptance criteria
- Every requirement above has a passing test; CI green.
- `TestOnlyTheVaultProcessImportsRecovery` still passes: agentosd talks to the vault over the socket with its own types.
- No goal text, number or key in any log line or fixture; canary goals only.

## Open questions (flag in the PR; do not decide silently)
1. **Closer after-decoys (#436 Potency point 1b). Pending Mark** (routed by the coordinator, 2026-10-09); this package does not start building until he has answered, since option B changes requirement 7. Within 45 days of the backup the real date is always the latest shown, so an owner who knows that picks it without remembering.
   - (A, recommended for now) Keep D-071's 45-day spacing and record the limit (requirement 7). "Later than all of these" is the honest answer for a forget after the backup, so the cost is a weaker memory check for a recent last forget, not a wrong release of an old backup.
   - (B) Allow after-decoys closer than 45 days (e.g. down to 7) when the backup is recent. Strengthens the check; needs a ruling because D-071 sets the spacing, and closer dates are harder for the owner to tell apart.
2. **Which socket (builder may decide; record it).** Recommended: the existing vault socket with a per-uid check, not a new socket, to avoid a second listener in the vault process.

## Assumptions to record
- `broker/cmd/agentosd/ASSUMPTIONS.md`: forgets made before the recovery key is set up are not logged (the log's key comes from the recovery key), and their done text says so; the learn dir's copy is a convenience for the backup, checked only by the vault.
- `broker/recovery/ASSUMPTIONS.md`: Q5's rewording; the vault trusts agentosd's release report only as far as the log opening under its key.

**Needs:** W3-forget-b1; W3-forget-b1-6 (#409 P3: the logger stays nil until the restore check is wired), and so W3-forget-b1-7.

**Gate:** tier A (vault process and agentosd's forget path); strongest model; explicit threat check: another uid calling the socket, a forged release report, a vault locked at start, a machine opening before take-backs. Security lens signs off; potency lens on requirement 7.

**Scope:**
- `broker/cmd/agentos-egress/server.go` (or a new `forgetlog.go` there) and its tests;
- `broker/recovery/forgetlog.go` (the copy writer and the status field), `bundle.go` only if the status field needs it, their tests, `ASSUMPTIONS.md`;
- `broker/cmd/agentosd/main.go`, `forget.go`, `learn.go`, `held.go` (from b1-7), a new client file, their tests, `ASSUMPTIONS.md`.

**Estimate:** about 120k tokens, strongest model (tier A). Checkpoint at 80k: requirements 1–3 green. If requirements 5, 6 and 8 push past 150k, split them into a release row before continuing.
