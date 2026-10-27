# KRN-reseal-confirm: an erase's confirmation names every backup that can still give the key (LOG-4, KRN-7)

Work item: #3338, the release findings of #3332 (KRN-reseal-unlocked): L3 findings 1 and 2 (comment 6431388704), UX finding 1 (comment 6431390679) and Security finding 1 (comment 6431392768). Tier A.

## The gap

Since #3332, `proc.Kernel.Erase` (`broker/kernel/proc/kernel.go`) re-seals backups without the kernel lock and then asks `kernel.Confirm`. Two cases leave its reply wrong, and one leaves `Close` undocumented.

1. **A re-seal already running.** A Tick re-seal of backup B, prepared before the erase was logged, is running when the erase comes. `kernel.Reseals` skips B because it is handed out, so the erase's `wg.Wait` returns at once and `Confirm` names B StillHeld. Waiting for that re-seal is not enough either. Its table was prepared from the state before the erase, so it still gives the subject's key once it lands (`TestSecProbeEraseDuringAnUnlockedReseal`, `/mnt/project-files/builds/2026-10-27-pr3332-secprobe_test.go`). Only a re-seal handed out after the erase drops the key.
2. **A backup still being written.** `Backup` takes its snapshot under the lock, then writes the content object and only then, in `pendingPut.PutTable`, adds the backup to the `Set`. An erase in between is named in no backup at all: `Resealed` and `StillHeld` are both empty. Yet the table about to land gives the subject's key until `Backup`'s closing re-seal (`TestSecProbeEraseBeforeTheFirstPutNamesNothing`, same file; this was already true on main before #3332).
3. **`Close` and a hung re-seal.** `Close` neither waits for `h.reseals` nor says why. A hung re-seal's goroutine outlives the kernel, and its commit is dropped (`With` returns "kernel closed").

## Decisions

1. **The process tracks each running re-seal by backup.** `proc.Kernel` gains `running map[string]chan struct{}`, guarded by `mu`. `reseal` adds an entry for each re-seal it hands out, in the same `With` that calls `kernel.Reseals`. The goroutine closes and deletes the entry after its commit, under `mu`, **whether or not the commit ran**: a commit that finds the kernel closed still closes the channel, so no erase waits forever after `Close`. `broker/kernel` does not change.
2. **An erase waits for the re-seals of the backups it names, then for one prepared after it.** `proc.Kernel.Erase` does this in order:
   1. Under the lock, it runs `kernel.Erase`. It takes the names from `c.StillHeld`, and the channels in `running` for those names.
   2. Without the lock, it waits for those channels. These are re-seals prepared before the erase.
   3. It calls `reseal(now)` and waits for its group, as today.
   4. Under the lock, it takes the `running` channels of any named backup that is running again. A Tick took it between steps 2 and 3, and since the erase is already logged, its table drops the key. It then waits for those channels without the lock.
   5. Under the lock, it calls `Confirm`.

   Each wait is bounded by the target, as the erase's own re-seals are since #3317. A hung target delays the erase reply, never STOP. A re-seal that failed backs off as today, so the erase names that backup StillHeld with the failure's text, not with `errStillGiven`. The erase does not override the backoff, and Tick retries it.
3. **An erase waits for a backup write whose snapshot gives the subject.** It does not name the backup by a placeholder. `backups` gains `writing *write{live liveSet, ids []string, done chan struct{}}`. `Backup` sets it in the `With` that takes the snapshot, when it has anything to write (one `Backup` runs at a time, `bk.run`). `pendingPut.PutTable` appends the backup's ID in the `With` that adds the backup to the `Set`. `Backup` closes `done` and clears `writing` once its writes end, on every path (`defer`), before its closing re-seal. In decision 2's step 1, the erase also takes `writing` if `writing.live` holds the subject. Before step 2 it waits for `done`, then under the lock adds `writing.ids` to its names and their `running` channels to its waits. A write that failed before any table went out added no ID, so nothing is named, and nothing at a target gives the key.
   *Why wait, not name a placeholder:* every name in a Confirmation stays a backup ID that the `Set` can check. `Confirm`, the `Confirmation` type and the owner's text keep one meaning, and `broker/kernel` stays as it is. A placeholder would need a name that `Confirm` must keep StillHeld forever, because the `Set` never knows it, so the owner would never see that backup Resealed. The cost is the same as decision 2's: a hung target delays the erase reply.
4. **`Close` documents, and does not wait.** A re-seal still running at `Close` loses only its commit. That is the same as a crash after the put, which the next start recovers from: `Rewrap` takes the highest listed generation, and Tick re-seals again (`TestSecProbeCloseWhileAResealHangs`). Waiting, even with a bound, would only delay shutdown behind a dying drive. The doc comment on `Close` says this, and an `ASSUMPTIONS.md` row records it.
5. **Not this row.** No owner seam calls `proc.Kernel.Erase` yet (only tests do). Whoever wires the owner erase call also makes sure the owner hears about a later re-seal that succeeds. This row records that limit in `ASSUMPTIONS.md`, so the seam's brief finds it.

## Lifecycle (integration owner: this package)

| Stage | Outcome |
|---|---|
| Erase, no re-seal running and no write | as today: re-seal, wait, Confirm |
| Erase while a Tick re-seal of a named backup runs | waits for it, re-seals again, and the reply names it Resealed |
| That Tick re-seal fails | StillHeld with its error; Tick retries after the backoff |
| Erase while a backup is between snapshot and Set add | waits for the write, then names it; Resealed once re-sealed |
| That write fails before any table | nothing named; nothing at the target |
| Target hangs during any of these | the erase reply waits; STOP, Tick and other calls do not |
| Close while a re-seal hangs | commit dropped, channel closed, any waiting erase returns "kernel closed"; the next start re-seals |

## Scope

- `broker/kernel/proc/kernel.go`: `running`, `reseal`, `Erase`, and `Close`'s doc comment.
- `broker/kernel/proc/backup.go`: `writing`, `Backup`, `pendingPut.PutTable`.
- `broker/kernel/proc/reseal_test.go`, `broker/kernel/proc/backup_test.go`, `broker/kernel/proc/ASSUMPTIONS.md` (update MIG-4-recovery-e3-a, and add one row for decisions 4 and 5).
- `briefs/KRN-reseal-confirm.md`.

**Requirement IDs:** LOG-4, KRN-7.

**Guard files:** none. **Gate:** `broker/kernel/proc` is trusted core (`tools/trusted_core.txt`, `known`), so the build PR carries a `Trusted-core:` line. A one-row D-159 PR naming LOG-4 and this brief merges first (D-159 rule 3, the D-188 pattern).

## Acceptance tests

Each test names the mutant it kills. The reviewer reruns them.

- LOG-4: `kernel/proc/reseal_test.go::TestAnEraseWaitsForATickResealItNames`. Erase subject A, let Tick start a re-seal that hangs at the target, then erase B from the process. The reply has not come while the target hangs, and a STOP completes `within` the bound. After the release, the reply names the backup in `Resealed`, and its table gives neither A nor B. *Mutant:* drop decision 2's step 2 or step 3.
- LOG-4: `TestAnEraseAfterAFailedTickResealSaysWhy`. The same setup, but the hung re-seal then fails. The reply names the backup StillHeld with the failure's text, and the next Tick after the backoff re-seals it.
- LOG-4: `TestAResealTakenBetweenTheWaitsIsWaitedFor`. A Tick hands out the named backup between decision 2's steps 2 and 3 (through a test hook). The reply still names it Resealed. *Mutant:* drop step 4.
- LOG-4: `kernel/proc/backup_test.go::TestAnEraseDuringABackupWriteNamesIt`. This is the probe `TestSecProbeEraseBeforeTheFirstPutNamesNothing`, with the erase started on its own goroutine from the write's hook, because it now waits for that write. The reply names the new backup in `Resealed`, and its table at the target does not give the subject. *Mutant:* skip the `writing` wait.
- LOG-4: `TestAnEraseOverAFailedWriteNamesNothing`. The write fails before its first put. The erase returns, names no backup, and does not hang.
- KRN-7: `reseal_test.go::TestCloseLeavesAHungResealToTheNextStart`. This adopts `TestSecProbeCloseWhileAResealHangs`, and adds an erase waiting on the hung re-seal that returns "kernel closed" after `Close` and the release. *Mutant:* close the channel only inside the commit's `With`.
- KRN-7, LOG-4: the existing tests in `kernel/proc` (`TestAnEraseAtAHungTargetNeverHoldsStop`, `TestATickAtAHungTargetNeverHoldsStop`, the backup and re-seal tests) still pass, unchanged in what they assert. `go test -race ./broker/kernel/...` passes.

## Needs, order, estimate

**Needs:** #3332 (merged). **Serial (D-111):** BAK-records-fresh (#3316) also edits `kernel/proc/backup.go`, in `pendingPut.PutTable` and `openBackups`, which decision 3 touches too. Build this row only while #3316 has no open PR, before or after it. Whichever lands second rebases onto the other's `PutTable`. No other open PR touches `broker/kernel/proc` (checked 2026-10-27 03:50Z).
**Estimate:** about 60k tokens, one session: some 60 lines of code and 250 of tests. Checkpoint at 90k.

## Residual risks

1. An erase over a dying drive still waits as long as the drive hangs, as since #3317. The owner call's one-minute timeout ends the owner's wait, not the erase. The erase is logged and Tick finishes it. The owner hearing that later is decision 5's limit.
2. Decision 2 waits at most two rounds, because any re-seal handed out after the erase is logged drops the key. A third handout would need a second erase of the same subject, which `kernel.Erase` refuses (`ErrErased`).

## Board row

```board-row
{"section": "Migration to the capability kernel (D-139)", "cells": ["[KRN-reseal-confirm: an erase's confirmation names every backup that can still give the key: it waits for a running re-seal it names and for a backup still being written, and Close's handling of a hung re-seal is documented (LOG-4, KRN-7; #3332 release findings).](briefs/KRN-reseal-confirm.md)", "#3332 (merged); serial with BAK-records-fresh (#3316) on kernel/proc/backup.go"], "rest": " (release; sub A kernel lane; tier A; trusted-core growth under D-159)"}
```
