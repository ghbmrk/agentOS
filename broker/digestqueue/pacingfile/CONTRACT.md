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
UID, mode 0700; all parent components are opened as non-symlink directories
using D51’s bounded descriptor walk. Lock, ledger and
existing `.tmp` descriptors must be regular, owned by that UID, mode 0600 and
single-link. The path must be clean/absolute and cannot end in `.lock`/`.tmp`,
which are reserved cooperating-file names. No directory is created or chmodded;
reject a bad deployment rather than silently weakening its custody settings.
A missing lock is created at 0600. Unsupported platforms refuse this API without
an unleased fallback. ExclusiveStore Load/Save use the held parent descriptor
for ledger reads, exclusive temporary creation, rename and directory sync (D50).
The bounded read and write/fsync/rename/sync protocol are retained; no second
accounting counter is introduced. Ordinary Store still delegates FileStore.

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
temporary symlink/hard link is refused before I/O in the tests. D50 additionally
refuses every pre-existing temporary file without truncating or adopting it.
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

## Retirement observation before lease release

ExclusiveStore.PacingHealth now exposes only immutable handle presence and an
atomic unavailable flag, with no I/O or I/O mutex acquisition. Close publishes
retirement **before** waiting for that mutex; any operation already running stays
serialized until it returns and the lease is actually released. Existing observed
custody/I/O failures publish the same flag. There is no live clear. Gate's optional
PacingStoreHealth integration now latches this signal before startup/admission,
after store completion, and in shared policy/host health reads. This closes the
D44 cached-health gap for this registered backend; other backends may still lack
a lifecycle signal. It does not inspect current path metadata during health.

Observed retirement prevents new Gate permission and host activation in the
covered checks. Retirement racing after a final observation, already-returned
permissions and other consumers still need reviewed STOP/all-user quiescence.
Close does not become authority revocation or a proof of drain. Synchronous
operations/Close still cannot be interrupted; the I/O-mutex test explicitly
models another operation holding the mutex, not qualified filesystem latency.
A generic blocked-Save test and actual leased-store/host STOP test supplement it.
Protected ancestor/same-UID/lock-inode continuity, one Gate/all cooperating writers,
restore/config integrity and startup control before Gate construction remain
external deployment/security qualifications. No daemon/default activation.

## Owned scoped session (W5-D46, opt-in review candidate)

`OpenSession(path, grants.Config)` rejects a supplied store, non-strict startup
and absent/out-of-range latency observation before acquiring custody. It opens
one ExclusiveStore and constructs exactly one Gate with the session's retirement
health adapter. Missing/faulted accounting remains held recovery rather than
provisioning a replacement image. Construction can block in Gate.New; independent
startup controls and trusted persistent configuration/provisioning remain required.

`Use(func(*grants.Gate) error)` shares that Gate and registers the entire callback
lifetime. Construct the question/approval consumers and NewProvisioned Host within
registered scopes, and keep each scope alive through all downstream work. Bound
methods, the Gate pointer, consumers, permissions and spawned goroutines must not
escape their registration. This is a trusted cooperating API, not a capability
sandbox. In particular, callback return is a caller assertion of quiescence, not
an inspection or revocation of permissions/handoffs. Drain asynchronous send work;
STOP and Host.Quiesce alone do not drain question/approval users. Never synchronously
await Session.Close inside Use, since that callback is itself a registered user.

`Close(ctx)` permanently retires admission and backend health before waiting.
It refuses new scopes, causes observed Gate/host recovery, and retains the lease
until all registered callbacks return. Cancellation during an incomplete drain
returns ctx.Err without releasing custody; retry Close after draining. Final lease
Close is serialized/idempotent and synchronous, and may block after drain despite
ctx. Context is not an I/O interruption, shutdown deadline or permission revoker.
Do not copy Session or reuse its Gate after retirement. Callback panic propagates
but unregisters the scope; that does not prove the callback's downstream work ended.

Local tests use actual exclusive leases, strict spent-debt reopen, missing-image
no-initialization, cancelled drain with cooperating-open refusal, and real question
Book plus Host STOP/Quiesce. They qualify those synthetic scopes only. Escaped users,
uncooperating writers, same-UID/ancestor/lock replacement, restore/config integrity,
real deployment latency and the storage-fault urgent/reissue availability tradeoff
remain external release/security holds. No daemon/default wiring or activation.

## Owned constructor and independent controls (W5-D47 review candidate)

`StartSession(path, cfg)` validates strict immutable options synchronously, then
returns a handle owning exactly one constructor worker and its eventual Session.
No retry, deadline replacement writer, boot, activation or daemon default is
created. `State().Line()` uses fixed owner operational wording. State/Use/retirement
use short state locks and do not wait for construction/admission I/O. Construct
independent owner controls first and keep their routing available; this handle is
neither an owner service nor an auth alternative. Actual daemon routing and its
resource/custody budget remain W5-D47-Q release qualification.

Before completion, Use returns ErrSessionOpening without invoking the consumer.
Constructor failure/panic yields fixed recovery and no Gate; a completed but
faulted/missing-ledger Gate remains available inside scopes to construct held
recovery/STOP controls. Ready only means constructor completion and cached healthy
accounting, never activation, filesystem freshness or qualified deployment.
OpenSession now unwinds its lease on constructor panic; StartSession contains
that constructor boundary without exposing the panic or private error details.
Trusted callbacks still cannot be assumed bounded or safe merely by containment.

Close permanently retires publication and shares an atomic retirement signal with
the constructor's backend adapter. The adapter checks it before Load/Save; a
constructor blocked at its clock cannot subsequently write after observing
retirement. Already-running synchronous operations are not interrupted or
refunded, and retirement can race a final observation. A late retired result is
closed by its owned worker before completion is published; no consumer can use it.
After readiness, Close preserves D46's registered-user drain contract. Known
cleanup errors remain fixed ErrStorage on subsequent Close rather than being
erased by idempotent lease Close. No recovery/reset/lease-release qualification
is inferred from either nil Close or a fixed error.

Cancellation bounds an incomplete constructor/user wait only. It does not detach
the worker, release an in-flight lease, start another writer or guarantee shutdown.
Retain the handle and its resources until Close actually completes. A constructor
or cleanup operation may remain stuck forever, occupying one worker/lease; admission
of startup handles and trusted callbacks belongs to reviewed daemon resource
composition. Do not synchronously await Close inside a Use callback. Escaped users,
callback return/panic, outstanding permissions and downstream handoffs retain D46's
trusted-quiescence limitations. Protected path/restore/config custody and actual
latency remain external qualification; urgent/reissue faults remain held.

Tests deliberately block the trusted clock inside actual Gate.New after real lease
acquisition. They prove independent held owner LocalStop, status/retirement,
cancelled-wait custody, late no-write/no-publication cleanup and strict debt reopen.
They model blocked construction, not a qualified blocked filesystem or deployment
latency. Synthetic descriptor corruption proves known cleanup-error retention.
No duplicate live owner service or default daemon assembly is supplied.

## Explicit startup admission slot (W5-D48 review candidate)

D47 owns one worker per handle but does not limit repeated StartSession calls.
A consistently reused `StartupSlot` now admits one owned startup across paths.
Its zero value is usable; do not copy it. Start refuses occupied admission before
another constructor, even for a different ledger or an already completed, failed
or retired handle. Invalid configuration on an empty slot leaves it empty.
Constructor completion and handle Close alone never automatically free the slot.

`Drain(ctx)` retires the owned handle through D47 Close and releases admission
only after successful constructor completion, registered-user drain and cleanup.
An incomplete cancelled wait or known cleanup fault leaves occupancy held; explicit
retry does not erase the fault. Concurrent drains join one owned close attempt,
without a new drain worker; a joiner's cancellation changes only its wait. A joined
caller receives the initiating attempt's result, which can include that caller's
context cancellation, and may explicitly retry later. State locks never surround
constructor/user wait or cleanup I/O. Completion is tied to the captured handle,
so an old result cannot clear a subsequent owner. A successful drain permits a
new explicit Start; it does not activate, auto-retry or reactivate the old Gate.

Use returned handles for State and scoped consumers. While managed, do not call
handle Close concurrently outside Drain: that bypasses the slot's single-close
composition. Retain the same slot and handle through cancellation/fault/shutdown.
Never await Drain inside an owned Use callback, which is itself a drain participant.
Creating another slot, calling StartSession directly or escaping scope/permissions
bypasses the cooperating resource bound. Actual daemon owner identity/routing and
startup admission remain W5-D47-Q; this is an opt-in primitive, not a global quota
or enforced authority boundary. No default wiring or activation is supplied.

Local tests cover different-path refusal before another clock/constructor, 32
concurrent starts admitting one actual constructor, cancelled blocked startup and
retained real lease, actual question Book send plus concurrent drain wait and
strict spent-debt reopen, known descriptor cleanup faults, invalid configuration
and stale retired handles. These synthetic scopes do not qualify malicious writers,
path/restore/config continuity, downstream escaped work, deployment I/O latency
or shutdown deadlines. Synchronous work can still hang forever, holding occupancy.
The urgent/reissue storage/time/overdue/invalid-input availability hold is unchanged.

## Digest-checked provisioned manifest (W5-D49 review candidate)

`ReadProvisionedManifest(reader, expectedSHA256)` requires a nonzero caller-trusted
pin before any read, consumes at most 16 KiB plus one overflow byte, and refuses
reader errors, overflow, digest mismatch and noncanonical/invalid v1 JSON. Canonical
bytes are encoding/json of ProvisionedManifest in its declared field order with
no trailing newline. Fields are `version`, `ledger`, `requests_per_hour` and
`max_store_latency_ms`. Version is 1; ledger is clean absolute/non-root/non-NUL,
without reserved .lock/.tmp suffix; allowance is 1..4096 and threshold 1..300000 ms.
No defaults, disable flag, volatile mode, first-provision option or policy callbacks
are read from the image. Digest-matched malformed/unknown/duplicate/reordered JSON
still fails. The immutable decoded value retains no reader/file/wire pointer.

ManifestSettings.Start requires the existing owner StartupSlot and a trusted clock
in grants.Config. Leave RequestsPerHour and all Pacing fields unset; competing
bindings are refused even when equal. The decoded settings bind the explicit limit,
PacingRequireExisting=true and positive threshold, retaining every other supplied
Gate field. Other authority/quiet/urgent callbacks, common approval/question/host
identity and their downstream scopes remain caller composition/review obligations.
Slot errors retain their fixed existing meaning. Missing or allowance-mismatched
state returns a faulted held Gate; no image initialization, counter reset or refund.

A deployment may serialize the documented wire struct and store those bytes, then
supply an independently trusted expected digest when reading. This API never
writes/provisions/discovers/persists/approves that pin or configuration file. Do not
compute the expected digest from the same untrusted bytes being checked. Digest
equality alone is not provenance, authenticity, freshness, anti-rollback/restore,
protected-file custody or trusted persistent configuration qualification. Updating
approved configuration and its external pin is an authorized deployment task,
not this decoder's authority. Replay of matching old bytes is not detected here.
File reads are synchronous and can block indefinitely; owner controls must already
exist before config loading. No config-source symlink/ancestor/same-UID protection
or filesystem latency claim is added. The exact-byte format is deliberately strict;
format/schema policy needs independent review before any deployment adoption.

Local tests cover exact byte/policy boundaries, over-cap consumption, zero/wrong
pin and private reader errors, unknown/duplicate/noncanonical JSON, invalid settings,
competing callback ownership and zero settings. Actual synthetic config-file read/
replacement and immutable decoded values, actual slot/lease/Gate strict debt reopen,
missing-image no-initialization and allowance-mismatch no-overwrite are tested.
Actual daemon configuration custody/routing/provisioning remains W5-D47-Q; inherited
base/security and urgent/reissue fault availability holds remain. No default daemon
wiring, activation, migration, pin provisioning or external acceptance claimed.

## Descriptor-anchored lease I/O (D50)

After parent acquisition, ExclusiveStore uses openat for bounded ledger Load and
exclusive O_CREAT|O_EXCL|O_NOFOLLOW temporary creation, Renameat within the held
directory and fsync on that directory descriptor. Ledger metadata is validated
from the actual opened descriptor, including private ownership/mode/single-link
and the shared byte cap plus overflow probe. Missing versus empty stays distinct.
Read/write/short-write/sync/close/rename failures return fixed storage refusal and
latch through the existing wrapper. FileStore/ordinary Store behavior is unchanged.

A safe regular existing `.tmp` is now refused too. It is never truncated/adopted.
A failed new write leaves its temporary image as unresolved recovery residue;
there is no automatic unlink, repair, retry or partial-write refund. Before rename,
observe the named temporary's private metadata and exact created inode and check
retirement; after rename require directory sync and the outer custody observation.
A late sync/outer-check failure may already have replaced state: no permission is
returned, and conservative strict reopen uses actual persisted bytes.

The deterministic displacement test models a path replacement BETWEEN the outer
check and I/O: actual read/write/rename stay in the acquired directory, leaving
replacement directory and a synthetic symlink target untouched. The next outer
observation latches displaced custody. This does not prove atomic custody checks:
parent acquisition/verification still traverse ancestors (D51 rejects symbolic
components but does not qualify ancestor permissions/mounts), a same-UID actor can
race temporary/ledger/lock names, lock replacement can split advisory exclusion,
and old valid images replay. Permissions already handed out are not revoked.
Synchronous descriptor I/O and Close can still hang forever. W5-D50-Q holds trusted
residue cleanup after total drain and actual protected-path/media/latency/restore/
config and current-main integration qualifications. Strongest independent security
and external batch review remain; D37 urgent/reissue fault hold is preserved.

## Bounded nofollow parent resolution (D51)

ExclusiveStore acquisition and named-parent custody observation resolve each
parent component from an opened `/` directory using openat with O_DIRECTORY,
O_NOFOLLOW and O_CLOEXEC. Each step retains its predecessor until the next opens,
then closes the predecessor; only two traversal descriptors coexist. A symbolic
ancestor is refused even if it points to the already held final parent inode.
Initial refusal occurs before lock creation; observed later refusal latches the
existing backend/Gate recovery hold with no ledger write or urgent bypass.

Validate before opening: clean absolute non-root ledger path, no NUL, no reserved
`.lock`/`.tmp` suffix, at most 4095 bytes including the ledger basename, and at
most 64 parent components excluding `/` and the ledger basename. Both acquisition
and custody re-observation apply the same limits. These opt-in compatibility
restrictions need external adoption review; no implicit symlink resolution,
canonicalization, shorter-path fallback, mkdir/chmod or provisioning is supplied.
A digest-accepted manifest may still name a path the lease rejects: startup holds,
never replaces its configuration or initializes a different image.

Tests reproduce D50’s symbolic-ancestor acceptance and link-back-to-same-inode
acceptance before implementation. Exact/over depth and byte bounds are exercised
with real directories, including descriptor-relative I/O when full `.lock` paths
would exceed PATH_MAX. Failed lookups release traversal fds; actual Gate urgent
hold and strict reopen preserve spent debt after trusted path restoration/drain.

This walk is not atomic whole-path identity, ancestor permission/ownership
attestation, mount/root namespace continuity or hostile same-UID/name custody.
Directory names can still change between steps; final parent identity is observed
and ledger operations remain pinned to the acquired descriptor. Acquisition may
still encounter an untrusted real directory; the existing final-parent privacy
checks do not qualify every ancestor. Root/ancestor mounts, lock replacement,
advisory noncooperators, old valid restore/config replay and escaped permissions
remain release holds. Bounded traversal count is not bounded synchronous I/O time:
Open/Openat/Fstat/Close or storage can stall and retain the startup slot/worker.
W5-D51-Q/W5-D50-Q/W5-D47-Q and D37 availability holds remain. No recovery cleanup,
refund, retry, revocation, default activation, deployment or security acceptance.

`DiscardDuplicateTemporary(path, trustedLedgerSHA256)` is a separate explicitly
invoked recovery action after complete registered and downstream quiescence. A
nonzero caller-trusted pin precedes acquisition of a new cooperating lease. Both
current ledger and temporary must exist, be nonempty bounded private regular
single-link files, and have byte-identical descriptor-read images matching that
ledger pin. Observed descriptor/named identity and metadata must remain stable
across reads and before descriptor-relative Unlinkat of the temp. Only temp is
removed; ledger/lock are never written, renamed, removed or substituted. Held
directory sync and explicit lease close must succeed. Ordinary Save/startup do
not call it; nonduplicate/partial/missing/unsafe/oversized residue stays held.

This data-only action neither validates nor repairs accounting schema, authenticates
or proves freshness of the supplied pin, provisions state nor activates a Gate.
Tests preserve actual spent debt on strict reopen; malformed identical bytes still
hold normal/urgent admission after cleanup. Same-UID name replacement can race
observation and unlink; all-user quiescence, trusted pin/source/operator, root/
ancestor/mount/lock custody and actual media/sync/close/latency require strongest
independent release qualification (W5-D54-Q and existing Q rows). An error after
unlink/sync/close is uncertain cleanup; retain recovery controls and do not restart
until trusted determination, no automatic retry or repair. Any synchronous operation
may hang without a deadline. No refund, revocation, restore/rollback/config-integrity
or hostile-name safety claimed; D37 fault availability hold remains.

`StartupSlot.RecoverDuplicate` admits the explicit D54 action through the same
owner resource as `Start`/manifest startup. A current startup, incomplete consumer
drain or admitted recovery refuses competing work before another operation. Its
synchronous action runs without holding the state mutex: fixed `RecoveryState`
wording and independent owner controls remain available. No worker is created.
The method owns only actual D54 duplicate removal, not a public supplied callback.
Successful sync/close releases admission only for a future explicit Start. Failure
or panic returns fixed ErrStorage, latches RecoveryHeld, and refuses all future
Start/recovery/Drain; no reset/retry API or private exception text. Invalid zero
pin/nil slot refuses without occupying an available slot.

This extends cooperating in-memory admission, not persistent/global quota or
revocation. Another slot/direct helper/reboot/escaped work bypasses it; approved
actual daemon/operator routing must reuse one owner slot. An operation may hang
forever with occupancy retained. On failure independent trusted custody/persistence
recovery is required; resource availability must not silently bypass the hold.
W5-D55-Q and all prior Q/security/base qualifications remain external. A state
line is not permission, actual media/latency freshness or accounting qualification.

`StartupSlot.StartManifest(reader, expectedPin, cfg)` admits one owned attempt
before reading configuration. It reuses the bounded canonical D49 image and
separately trusted nonzero pin/clock, rejects competing pacing options, then
constructs one strict Gate/lease inside that SAME worker. No second StartSession
worker is launched. Both startup modes use the original shared completion/late
cleanup path, preserving known cleanup faults. Reader failure/panic exposes no
consumer and uses fixed recovery state, with slot occupancy until complete Drain.

State/Use never wait for reader I/O. Cancellation retires publication and keeps
worker/reader/slot custody. Retirement observed before/after the read skips lease
acquisition and Gate construction; later racing retirement uses the existing
backend checks and late cleanup, never publishing consumers. This is observation,
not interruption or atomic cancellation of every syscall. The caller must retain
reader ownership through complete Drain (retired status alone is insufficient);
reader/clock callbacks must not synchronously await their own Drain. Synchronous
reading/construction/cleanup may hang indefinitely with one worker retained.

Direct reads/StartSession/another slot escape the cooperating bound. Pin/source/
clock/authentication/persistence/config/provisioning, complete consumer handoffs
and actual daemon/operator resource routing remain external release qualifications.
No HTTP client, pin discovery, reader-closing policy, fresh allowance, provisioning,
default activation, deadline, replacement worker or custody/media qualification.
D37 availability and existing Q/current-main/#268 holds remain unchanged.

## W5-D62 explicit residue review

InspectTemporary(path, separatelyTrustedLedgerPin) is a synchronous trusted review
operation after TOTAL consumer drain. It acquires a fresh cooperating lease,
verifies nonzero ledger pin before I/O, uses existing bounded private nofollow
stable descriptor reads and name observations, and returns only immutable value
sizes/digests plus absent/duplicate/different status. It never writes/unlinks ledger
or temporary; acquisition may create the stable lock inode. Empty/unsafe/oversize
images, pin/read/custody/close faults return fixed ErrStorage and zero report.
Unsupported platforms refuse. No bytes/paths/underlying errors are returned.

Report equality describes bytes, not schema, freshness, age, allowance lineage,
authenticity or persistence. Matching old/malformed bytes can compare; no report
authorizes cleanup, recovery, refund, activation or restart. TemporaryDigest is
review evidence, never a ledger trust anchor. Nonduplicate residue remains held
for ordinary and urgent requests. Trusted external recovery determination and
qualified custody remain required. No automatic diagnosis/startup/recovery hook.

## W5-D63 opt-in protected ancestors

OpenExclusiveProtected(path, trustedOwners) validates a nonempty/max16/unique
owner UID list and copies it before I/O. The SAME bounded nofollow acquisition
walk checks every opened root/component descriptor: directory, permitted UID,
no group/other write bits (sticky world-write is refused). Final dedicated
parent still requires euid/private0700. Later named custody walks use the copied
policy; observed failure latches backend health and Gate recovery/ordinary+urgent
refusal. Legacy OpenExclusive is unchanged; unsupported platform refuses.

Policy is caller-trusted, not discovered from filesystem ownership. This is not
root/namespace/mount/ACL/same-UID/lock/restore qualification or an atomic whole-
path snapshot. Synchronous walks/I/O may hang. No fallback, mode repair, provisioning,
activation or auto-retry; Session/startup/manifest/daemon adoption remains separate.
