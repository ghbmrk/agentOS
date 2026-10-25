# KRN-erase: recall and erase in the kernel (LOG-4, kernel half)

Work item: #2823 (narrowed to the kernel half; the split is on the issue). Tier A.

## Goal

The kernel holds one data key per subject, seals content under it, lists what it knows about a subject, and erases a subject with one log entry that makes its content unreadable (SPEC LOG-4, with LOG-1, LOG-2, LOG-5). Today `broker/kernel` has no subject, no data key, no content reference and no erase (#2781 comment 6350369404). FORGET on the owner channel is rebuilt on this later (#2823's follow-up), so nothing here is wired into `cmd/agentosd` or the owner seam.

## Design

1. **Subjects are opaque.** `OpenSubject(now)` draws a random subject ID and a random 32-byte data key, writes the key to the key table, then logs `subject.opened {subject, key_id}`. The log never holds a key or a human name. A subject's name ("Alice", an address) is content of class `label` sealed under its own key, so after an erase nothing readable about it is left in the log (LOG-2 never rewrites old entries). Recall by name opens the labels of live subjects.
2. **The key table is outside the log.** The log is append-only and goes into every backup, so a key in it could never be destroyed. `Keys` is a small interface (`Put`, `Get`, `Delete`, `List`), durable when each call returns. `MemKeys` lives in `broker/kernel`; `FileKeys` in a new `broker/kernel/proc/keytable.go` keeps one file per subject in a 0700 directory, each sealed under the log's AES-GCM key with the subject ID as AAD, and `Delete` unlinks and syncs the directory. `FileKeys` is not wired into the kernel process here; the start-up slice (#2682) wires it.
3. **Content is sealed per subject and addressed by its ciphertext.** `Seal(now, subject, store, class, plaintext)` encrypts with the subject's key (AAD: subject ID and class, random nonce), names the result by SHA-256 of the ciphertext, hands it to the named `ContentStore` (`Put`, `Get`, `Delete`), and logs `content.stored {subject, store, hash, class}`. Addressing by ciphertext keeps a plaintext hash, which would let anyone confirm a guessed message, out of the log. `Read(hash)` refuses an erased or unknown subject before it touches a store.
4. **Erase is one entry, then the key goes.** `Erase(now, subject)` is an owner act (the owner channel authenticates it, like `Stop`): it logs `subject.erased {subject, stores}` and anchors, then deletes the key, then asks each store that holds the subject's items to delete them, logging `erase.confirmed {subject, store}` for each store that confirms. `subject.erased` is a narrowing entry: `Open` keeps it whether or not an anchor covers it. A subject ID is never reopened, and `Seal` on an erased subject is refused.
5. **Erase fails closed.** If the key delete fails, `Erase` returns the error and the subject is still erased in the log (re-applied at the next start, design 6). A store that does not confirm stays listed in a new `State().Unerased()` view (subject, item count, stores not confirmed) until it does; `Tick` retries the store deletes. `Unerased()` is a new view, not a change to `Status()`, which #3113 is changing. The returned `Confirmation` names the stores confirmed and not confirmed, and says older backups may still hold the content; naming those backups is the restore half's (#2865), since the kernel has no backup list yet.
6. **Every start re-applies the erases.** `k.OpenContent(keys, stores, now)`, called after `Boot`, deletes the key of every erased subject still in the table, deletes keys no `subject.opened` names (a crash between `Put` and the log write), and lists any opened, unerased subject whose key is missing. `Seal` and `Read` refuse until it has run. It is a separate call so `Boot`'s signature and its callers do not change.
7. **Recall.** `State().Recall(subject)` returns when the subject was opened, its items (store, hash, class, time), and, once erased, only the erase time, the item count and the stores not yet confirmed. Projections stay rebuildable: a state replayed from empty equals the live one (LOG-1).

Entry types `subject.opened`, `content.stored`, `subject.erased` and `erase.confirmed` are version 1 and join the closed set in `state.go` (LOG-5). None is widening. Their fold can live in a new `erase.go`, as task entries live in `task.go`.

## Not in this package

- Restore re-applying erases newer than a backup, the no-anchor, rolled-back and disagreeing holds, sealed classes and the passkey unseal; subject keys inside a backup: #2865 (comment on #2823 records the split).
- `broker/vm` durable retirement and the old recall lineages (#2823 comments 6374258303 and 6366173391): their own row, filed in the split.
- Rolling back a planner session that read an erased item, and rebuilding procedures and indexes without it: these need planner and projection read tracking that the kernel does not have; the FORGET follow-up names them when it is filed.
- The owner-seam entry in docs/LANES.md and the FORGET reply and page: the FORGET follow-up.

## Flags for review (D-159 rule 4)

Growth cites SPEC LOG-4, D-139 and Mark's card cmsg_01R91wiieBzMSvPKFsAJVvuKKsWFFLUuq73jvauERoVRhH (erase rebuilt as #2823). Before the build PR, a one-row DECISIONS.md PR names it (D-159 rule 3). Parts LOG-4 does not spell out:
1. **The key table as a store outside the log** (design 2). LOG-4 says the kernel holds each subject's data key and that erase destroys it, which a log entry cannot do; LOG-1 lists "key tables" among projections rebuilt from the log, which cannot hold a destroyable secret. This is the one new durable store in the trusted core.
2. **Opaque subject IDs with names as content, and ciphertext addressing** (designs 1 and 3): choices inside LOG-4 that keep personal data out of the append-only log.
3. **Residual risk.** On an SSD, unlinking the key file is logical, not physical: someone holding both the core's disk and its sealed-store key could recover a deleted key's blocks. LOG-4's "unreadable everywhere" holds for projections and later backups; record this in ASSUMPTIONS.md.

## Scope

- `broker/kernel/state.go` (entry constants and schema only), `broker/kernel/kernel.go` (`Erase`, `Seal`, `Read`, `OpenSubject`, `OpenContent`, the `Tick` retry), new `broker/kernel/erase.go`, new `broker/kernel/erase_test.go`, `broker/kernel/ASSUMPTIONS.md`.
- New `broker/kernel/proc/keytable.go` and `keytable_test.go`.
- `broker/kernel/sim/sim.go`, `sim_test.go`.
- `briefs/KRN-erase.md`.

Not `log.go`: `Open` already keeps non-widening entries. Waits for #3112, #3113 and #3116 to merge (D-111: they hold `state.go` and `kernel.go`).

**Guard files:** none (no new broker package). The trusted-core line count grows, so the PR needs a `Trusted-core:` line naming its own D-row (D-159 rule 3); tier A reviews apply.

## Acceptance tests

**Acceptance tests:**
- LOG-4 erase: `broker/kernel/erase_test.go::TestEraseMakesContentUnreadable`: after `Erase`, `Read` of every item fails, `Seal` on the subject is refused, and the key table no longer holds the key. Catches an erase that only marks the log.
- LOG-4 crash: `erase_test.go::TestEraseSurvivesACrashBeforeTheKeyGoes`: a crash after `subject.erased` is written and before `Delete`; reopen and `OpenContent` delete the key, and the item stays unreadable. Catches an erase lost between log and key table.
- LOG-4 fail closed: `erase_test.go::TestAStoreThatCannotDeleteStaysListed`: a store whose `Delete` fails keeps the subject in `Unerased()` across a restart until `Tick` gets its confirmation, logged once. Catches a swallowed store error.
- LOG-4 key delete failure: `erase_test.go::TestAKeyDeleteFailureIsReturned`: `Keys.Delete` fails, `Erase` returns the error, and the next `OpenContent` finishes it.
- LOG-4 orphans: `erase_test.go::TestAKeyNoEntryNamesIsDropped` and `TestAMissingKeyIsListed`.
- LOG-4 recall: `erase_test.go::TestRecallListsItemsThenOnlyTheErase`: items before, erase time and count after, no hashes after.
- LOG-4 privacy: `erase_test.go::TestTheLogHoldsNoKeyNameOrPlaintextHash`: scans every entry body for the key bytes, the label text and the plaintext's SHA-256.
- LOG-4 isolation: `erase_test.go::TestEraseLeavesOtherSubjects`: another subject's items still read.
- LOG-1: `erase_test.go::TestEraseStateRebuildsFromEmpty`: replay from empty equals live state, including `Unerased()`.
- LOG-5: `erase_test.go::TestEraseEntriesAreKnownAndNarrowing`: the four types are known at v1, none is widening, and an unanchored `subject.erased` survives `Open`.
- LOG-4 file table: `broker/kernel/proc/keytable_test.go::TestFileKeysDeleteIsDurable` (reopen after `Delete` does not list it; a file sealed for one subject does not open as another) and `TestFileKeysRefusesALooseDirectory` (mode check like `privfile`).
- SIM-erase (docs/migration/cases.md §4): `broker/kernel/sim/sim_test.go::TestSimEraseReachesEveryViewOnce`: the sim opens subjects, seals, erases and crashes at every write of the erase; at the end each erase has one `subject.erased`, at most one `erase.confirmed` per store, no key in the table, no readable item, and a rebuilt state equal to the live one.

## Estimate

About 90k tokens, one session: roughly 300 lines of kernel and proc code and 400 of tests. Checkpoint at 120k.
