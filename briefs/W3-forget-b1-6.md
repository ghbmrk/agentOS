# W3-forget-b1-6: The restore entry checks the forget log safely

Board section: Integration: wiring merged packages into the box. Part of W3-forget-b1 (briefs/W3-forget-b1.md); SPEC REC-1, REC-2, CAP-3, A8.

**Goal:** the forget-log check merged in #409/#436 runs only when a caller fills `recovery.Options` and `Layout` correctly, and no production caller exists yet: there is no restore command (that is W6, whose brief is a stub), and the vault process (`cmd/agentos-egress`) does not import `recovery`. This package delivers the one entry a restore command calls, so the command has no forget-log choice left to get wrong, and closes #409's release conditions and #436 Security point 2 in `broker/recovery/`.

**Requirement IDs:** REC-1 (restore onto new hardware), REC-2 (restricted mode until re-confirmed), CAP-3 and A8 as in W3-forget-b1; security C3 (authenticated forget log replayed over restores). Tests carry `REQ: REC-1, CAP-3, A8` (REC-2 on the restricted-state test).

**Sources:** BOARD row W3-forget-b1-6; #409 Security R2, R3, R5 (a)–(d), L3 point 3 (PR comments, head f629664); `reviews/security/2026-10-08-pr436.md` point 2.

## Design
A new `broker/recovery/restoreentry.go` exposes one function (name is the builder's; `RestoreBox` below). The W6 command calls it with the recovery key, the chosen backup, the destinations at hand and the box's learn dir; it fills `Options` and `Layout` itself and calls `Restore`/`RestoreDrive`. The vault process supplies its TPM counter (`tpmCounter`, `cmd/agentos-egress/trusted.go:403`) through a constructor that takes the counter as a required argument; nil is accepted only from a PC with no TPM and is logged. The W6 command itself, its UI and its vault-process endpoint stay in W6 (open question 2).

## Requirements (each with a test)
1. **(a) One forget-log path** (R5 a, L3 point 3). `RestoreBox` sets `Layout.ForgetLog` to the learn dir's `forget-log.json` (relative to the restore target), and `Restore` refuses an empty `Layout.ForgetLog` with an error before extracting anything. agentosd cannot import recovery (ARC-1, b1-4 Q6), so a testdata file read by both sides (as `recovery/testdata/confirm-v1.json` does) pins the file name and the `.pending`/`.confirm` suffixes; recovery's test checks `PendingSuffix`/`ConfirmSuffix` against it and agentosd's test checks `forgetLogFile` and its `".pending"` against it. Tests: empty layout is refused and nothing is written; a held restore through `RestoreBox` leaves its marker where agentosd's `restoreHold` finds it.
2. **(b) agentosd is stopped** (R5 b). agentosd takes an exclusive lock on a lock file in its learn dir at start and holds it for its life; `RestoreBox` takes the same lock without waiting and refuses ("stop the agent first") when it is held, and holds it until the rename into place is done. Tests: lock held → refusal, target unchanged; lock free → restore proceeds; agentosd's start fails cleanly when a restore holds the lock. The lock-taking line in agentosd is the only agentosd change in this package.
3. **Every destination's copy** (row). `RestoreBox` reads the forget log copy from every destination at hand under one fixed name per destination (the builder picks it and records it in ASSUMPTIONS; b1-5 writes it). An unreachable destination or missing copy counts as absent, logged by destination name; it never fails the restore. It also fills `Options.Newer` from the backup log (b1-4's follow-up). Test with fake destinations: copies from all reach the check; one unreachable is skipped; `Newer` holds the verified newer backups only.
4. **Size cap** (R3). `decodeForgetLog` refuses input over 4 MiB, and `RestoreBox` reads each copy through a reader that stops at the cap plus one byte (refusing, not truncating). An over-cap copy counts as absent; an over-cap restored log is forged. Tests at cap and cap+1 for both.
5. **A corrupted copy doesn't forge the restore** (R2). A copy that fails to open after a valid first entry contributes its MAC-verified prefix (entries before the first bad one), then is treated like any other copy; the restored bundle's own log failing still gives `forget-log-forged`. Rationale for the threat check: anyone who can corrupt a destination copy can delete it, which already counts as absent, so this adds no power; no unverified entry is ever used. Tests: corrupted copy + good copy → same result as the good copy alone; corrupted copy whose prefix is longer than the bundle's log → the prefix is used; corrupted bundle log → forged.
6. **The missing case opens the copies** (#436 Security point 2). When the bundle carries no forget log, `checkForgetLog` still opens the copies; the longest authentic one (same key, prefix rule as now) becomes the log the check continues with (anchored, or unanchored → the picker with that log's last date). Only when no authentic copy exists is the result `forget-log-missing`. Two authentic copies with different log IDs keep the restore held as forged. Tests: missing bundle log + authentic copy with forgets → not missing, and "Never" no longer releases; no copy → missing as before; two IDs → forged.
7. **(d) TPM anchor failure at `storeBackupKey`** (R5 d). Implements the ruling on open question 1. If unruled when the build starts, keep today's behaviour and pin it with a test, so the ruling changes one place.

## Acceptance criteria
- Every requirement above has a passing test; CI green; existing recovery tests updated only where they relied on an empty `Layout.ForgetLog`.
- `TestOnlyTheVaultProcessImportsRecovery` passes; agentosd still does not import recovery.
- Fixtures use synthetic keys and canary goals only.

## Placed elsewhere
- **(c) a start without the marker cross-checks `State.Pending`** needs agentosd to reach the vault, the same socket b1-5 builds for `AppendForget`/`ExportForgetLog`; it moves to W3-forget-b1-5 with the clearing of `State.Pending` on release, which b1-4 left unread.
- **#409 Security R4** (an agent machine opens before restored take-backs run) belongs to the start after release: W3-forget-b1-7 requirement 8.
- The restore command, its UI and the vault-process endpoint that calls `RestoreBox`: W6 (precondition added to its row).

## Open questions (flag in the PR; do not decide silently)
1. **(d) A failed TPM anchor when storing the recovery key (Mark).** Today `ensureForgetLog` saves the key and the log, then the anchor's `Define`/`Read` error fails `storeBackupKey`, so Provision or rotation reports failure after half its writes.
   - (A, recommended) Fall back to anchoring at the first forget (as a nil `Box.Counter` already does), record that the anchor is missing, and show it on the local page; `AppendForget` retries the anchor. Cost: until a forget anchors it, a restore on this same PC is unanchored and goes to the owner's picker instead of passing silently. Recovery-key setup never fails on a TPM fault.
   - (B) Fail storing the recovery key, and make the failure atomic (remove the key and log written before the anchor). Strictest rollback check, but an owner with a faulty TPM cannot set up recovery at all, which REC-1 depends on.
2. **Where the restore entry lives (coordinator).** (A, recommended) b1-6 delivers `RestoreBox` and the egress counter constructor; W6 builds the command and calls it (W6 row gains the precondition). (B) b1-6 also builds the command in the vault process, which pulls W6's UI and endpoint design into a tier-A forget-log package and pushes it past 150k.

## Assumptions to record (`broker/recovery/ASSUMPTIONS.md`, new section)
- 4 MiB holds the box's lifetime of forgets (an entry is well under 1 KiB; tens of thousands of forgets fit).
- An advisory file lock is enough to keep agentosd stopped: both sides are ours and run as root on the box; a hostile agentosd is out of scope for this check.
- A destination copy's verified prefix is as trustworthy as an intact copy's entries: each entry is MAC-chained under the recovery-key-derived key.
- Two authentic logs with different IDs do not arise from normal use (`ensureForgetLog` creates one log per vault), so holding is the safe reading.

**Needs:** W3-forget-b1; W3-forget-b1-7 (the held restore is not silent before a production restore path can create one).

**Gate:** tier A (recovery and the vault process); strongest model; explicit threat check over requirements 2, 4, 5 and 6. Security lens signs off.

**Scope:**
- `broker/recovery/restoreentry.go` (new), `forgetlog.go`, `bundle.go` (the empty-layout refusal), `factor.go` (only for the ruling on (d)), their tests, `testdata/` (the shared names file), `ASSUMPTIONS.md`;
- `broker/cmd/agentos-egress/trusted.go` (exporting the counter for the entry) and its test;
- `broker/cmd/agentosd/main.go` (the lock line only), the shared-names test in `broker/cmd/agentosd/`.

**Estimate:** about 110k tokens, strongest model (tier A). Checkpoint at 75k: requirements 1–5 green.
