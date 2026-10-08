# Opt-in bounded accounting file reader

Supply `pacingfile.Store{Path: protectedPath}` as the actual shared Gate's
PacingStore, retaining PacingRequireExisting=true and an explicitly reviewed
PacingMaxStoreLatency for provisioned startup. D42 NewProvisioned then binds
reservation/recheck/health as before. No daemon/default setting is changed and
no deployment or provisioning authority is conferred by choosing this type.

Load consumes at most MaxPacingStateBytes+1 bytes (512 KiB plus an overflow
probe). It rejects overflow rather than truncating an accounting image. The
maximum serialized size is now exported by grants, using the same existing
constant and schema; this reader cannot silently disagree with Gate validation.
On Linux open uses O_NOFOLLOW for the final path component and O_NONBLOCK to
avoid waiting on FIFO writers. Metadata comes from the opened descriptor, which
must be regular and within the size cap; the stream is independently capped
against growth after Stat. An empty file returns non-nil empty bytes, so it is
malformed state rather than first provisioning. ENOENT alone retains the existing
missing-image convention. All other read errors return fixed ErrStorage and no
bytes. Unsupported-platform Load fails closed without an unbounded fallback.

Save refuses over-cap buffers before touching the path, delegates the existing
change.FileStore atomic write/fsync/rename/directory-sync procedure, and returns
fixed ErrStorage on failure. There is no new writer, lock, retry, schema, timeout
worker or refund. Gate confirmation/reservation still owns accounting semantics;
uncertain or late Save retains the established recovery hold and strict reopen
must retain persisted debt. A failed Load prevents initialization/confirmation
Save in the actual Gate; oversized bytes are left intact for trusted recovery.

These checks address input byte bounds and final-descriptor type only. Parent
paths can still resolve through symlinks; hard links, same-UID replacement,
concurrent writers and a writable/private-directory failure are not qualified.
FileStore's `.tmp` creation remains dependent on protected exclusive directory
custody; this wrapper does not make its write procedure safe against adversarial
path mutation. Do not deploy in an untrusted/shared/writable directory or treat
final O_NOFOLLOW as end-to-end path custody. One trusted writer, encrypted private
state inventory, protected temporary/parent paths and reviewed backup/recovery
remain external requirements. No ownership or identity attestation is supplied.

Filesystem open/Stat/Read/Save can still stall: bounded bytes are not bounded I/O
latency or cancellation. D41's monotonic threshold observes late callback return
and reports in-flight recovery once the Gate is available; it cannot interrupt
construction or waiting calls. The explicit urgent/reissue fault availability
hold remains, including oversized/malformed input. No anti-deletion/rollback/
restore/config-integrity qualification, independent acceptance or CI green is
claimed. A valid older restored image can still pass strict startup.

Tests-first behavior reproduced unbounded acceptance. Local tests exercise the
exact cap and overflow, a 1-GiB sparse file refused by metadata, bounded stream
overflow, symlink/dangling-symlink/directory/FIFO refusal, real writer/strict Gate
reopen/expiry, oversized-state no-overwrite/no-temp recovery and sanitized errors.
They establish these component behaviors, not hostile filesystem or deployment
qualification. Strongest independent broker/security review remains required.

## Opt-in cooperating store lease

`OpenExclusive(absoluteLedgerPath)` acquires a Linux per-ledger nonblocking
`flock` on a retained `.lock` inode before constructing the Gate. It does not
load/provision the ledger. The dedicated parent must be owned by the effective
UID, mode 0700 and opened as a final non-symlink directory. Lock, ledger and
existing `.tmp` descriptors must be regular, owned by that UID, mode 0600 and
single-link. The path must be clean/absolute and cannot end in `.lock`/`.tmp`,
which are reserved cooperating-file names. No directory is created or chmodded;
reject a bad deployment rather than silently weakening its custody settings.
A missing lock is created at 0600. Unsupported platforms refuse this API without
an unleased fallback. Load/Save continue to use the bounded reader/FileStore
writer; no second accounting counter or persistence algorithm is introduced.

The returned pointer implements PacingStore. Construct exactly one actual Gate
against it and share that Gate with approval/question/digest consumers. Never
copy the ExclusiveStore or create two Gates from the same lease; a per-file
kernel lease excludes independent cooperating opens/processes, not duplicate
in-memory counters created by one caller. Ordinary Store/FileStore callers can
ignore the advisory lease, so trusted composition must exclude them too.

Every Load/Save serializes on this instance and observes current parent/lock
identity plus private ledger/temp metadata before and after I/O. Parent/lock
displacement, metadata refusal or I/O failure latches fixed storage refusal;
there is no live repair. Private error/path details are not returned. A bad
temporary symlink/hard link is refused before FileStore truncation in the tests.
These are observation boundaries, not an atomic defense against an actor who
can mutate the same UID's paths during the operation. Ancestor traversal and
same-UID rename/link races still need protected deployment custody. Neither
advisory exclusion nor metadata checks qualify hostile filesystem safety,
authenticated anti-delete/rollback/restore/config integrity, encrypted storage
or physical media durability. An authentic older image can still be reopened.

Before Close, use reviewed STOP/host quiescence and drain **all** old Gate users
and outstanding permissions. Close waits for this instance's synchronous I/O,
marks it closed, releases/closes the kernel lease and leaves the lock inode in
place. It is idempotent and closed instances refuse reads/writes. Never unlink
or replace `.lock` while any holder/contender can exist: a new inode can split
advisory custody. Close does not itself revoke already returned permissions,
stop the Gate/host, resume a scope or prove completion of forget. Fresh recovery
requires a new exclusive open and Gate against the same durable image, retaining
PacingRequireExisting and the configured latency observation. Gate.New/Load/
Save/Close may still block on synchronous filesystem I/O; no timeout worker or
qualified startup/STOP/runner-shutdown deadline is supplied. Preserve the
existing urgent/reissue storage/time/overdue-I/O availability review hold.

Tests first exposed duplicate opens, unsafe metadata/temp writes, replaced
custody and reuse after Close. Actual Linux independent open and child-process
exclusion, reserved/private path refusal, final lock/directory symlinks and
hard links, before-write temp refusal, displaced parent/lock quarantine,
closed-store refusal and strict spent-debt reopen pass locally. The subprocess
probe is skipped in the ordinary suite and invoked explicitly by its parent
test. These are component checks, not independent security or deployment
qualification. No daemon/default binding or activation is included.
