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
