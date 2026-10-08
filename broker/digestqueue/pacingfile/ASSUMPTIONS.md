# Leased accounting I/O assumptions (D50–D54)

| # | Assumption | Spec basis | If it changes |
| --- | --- | --- | --- |
| 1 | Linux directory descriptors/openat/renameat address the held directory even if its pathname changes. | OP-1 | Refuse unsupported targets; qualify equivalent substrate before adoption. |
| 2 | Even with D51 bounded nofollow lookup, parent permissions/mounts and directory/lock names remain under trusted custody; same-UID mutation is outside this component's qualification. | OP-1, OP-8 | Hold deployment until independently qualified; inode observations do not prevent hostile name races. |
| 3 | All writers cooperate with one retained lock inode and exactly one Gate per owned lease. | CH-15 | Preserve startup/consumer composition hold; advisory flock is not enforcement against noncooperators. |
| 4 | Existing or failed `.tmp` is unresolved state. Only trusted recovery after full drain may remove it. | OP-1, CH-15 | Do not automatically truncate/adopt/unlink/retry it; review recovery custody explicitly. |
| 5 | File write/fsync/rename/directory-sync success is only the configured filesystem's contract. | OP-1 | Qualify actual crash/media behavior independently; any error is a latched hold, not a refund. |
| 6 | Config pins, clock, strict state, backup/restore and all-user quiescence remain externally trusted. | CH-15, OP-1 | Refuse unsafe composition; descriptor anchoring is not anti-rollback/restore/config authentication or permission revocation. |
| 7 | Synchronous filesystem I/O may block forever; D41 observes latency without cancellation. | OP-8 | Keep independent owner controls/owned startup resource admission; do not start replacement writers after timeout. |
| 8 | Paths within 4095 bytes and 64 parent components without symbolic ancestors are sufficient for the reviewed opt-in deployment. | OP-8, OP-1 | Review compatibility; never silently follow links/canonicalize or relax the bounds. Namespace and ancestor permission custody remain externally qualified. |
| 9 | **Explicit duplicate-only recovery.** The caller authenticates the expected ledger pin/source and proves complete registered/downstream quiescence before invoking DiscardDuplicateTemporary on a fresh cooperating lease. Stable private names/lock/ancestor custody are independently qualified: metadata observations cannot prevent same-UID check-to-unlink replacement. Only exact duplicate bytes are removed; schema/freshness/restore/permissions are not repaired. Any error, including after unlink/sync/close, retains trusted recovery hold until persistence/custody determination. | CH-15, OP-1 | Keep W5-D54-Q/W5-D47-Q/W5-D50-Q/W5-D51-Q and strongest independent review before release; no default/startup/Save invocation, automatic cleanup/retry or activation. |
| 10 | One consistently reused StartupSlot owns startup AND explicit recovery for this owner. The caller owns synchronous recovery lifetime. Failure/panic holds admission without a reset/retry API until independently trusted custody/persistence determination. Another slot/direct helper/reboot or escaped work is outside this composition's enforcement. | CH-15, OP-8, CH-2 | Preserve W5-D55-Q and existing Q rows before actual daemon/operator adoption. Fixed status/STOP remain independent; no persistent/global quota, worker interruption, authority activation or silent hold bypass. |
| 11 | Configuration reading is admitted through one consistently reused StartupSlot.StartManifest and one owned worker. Reader and clock are trusted synchronous callbacks; keep reader ownership through complete Drain, never await that drain inside those callbacks. Another slot/direct read bypasses this cooperative admission. | OP-8, CH-15 | Preserve independent owner controls and W5-D47-Q/W5-D55-Q plus all trusted pin/config/custody qualifications. Reader may hang forever; no cancellation, replacement worker or global/persistent quota. |

## W5-D62 diagnosis custody

InspectTemporary is trusted broker/operator review, not an agent/plugin tool.
Caller must completely drain ALL registered and escaped downstream work, retain
separately trusted ledger pin/source, and stabilize names/custody. The function's
fresh advisory lease refuses cooperating live/incomplete-drain sessions but cannot
prove full drain, stop noncooperators or bind another slot/reboot. Observed digest/
metadata/status is not an atomic hostile same-UID/name/ancestor/mount/lock snapshot.
Do not bootstrap expected ledger pin from the checked image or use temporary hash
as ledger authority. Old/malformed bytes replay. A report never authorizes restart
or deletion; nonduplicate residue remains held. Ledger/temp are read-only, while
lease acquisition may create the stable lock inode. Read/verification/close errors
zero the report and require external recovery; synchronous work can hang forever.
W5-D62-Q/prior Q/current-base/security/pin/media/latency holds remain. No automatic
repair/retry/activation/refund/revocation/globalquota/anti-restore/config integrity/
hostile-path or deployment latency qualification; D37 urgent/reissue hold preserved.

## W5-D63 trusted ancestor policy

OpenExclusiveProtected observes explicit permitted owner IDs and write modes for
every root/component in descriptor acquisition and later custody walks. Owners
must be separately trusted and persistently configured; ID membership does not
attest authenticity or authority. Root need not be UID0; never infer trustees from
the same checked path. Copied policy prevents caller slice mutation from silently
relaxing an existing lease. Incompatible writable/readability/ownership ancestry
is refused, without /tmp/sticky exception or automatic permission changes.

Same-UID/privileged actors, ACLs, mount/namespace replacement, lock splitting and
noncooperators remain unqualified. Metadata checks are observations, not atomic
path/name custody or media freshness. Legacy constructors/direct other slots/old
image restore can bypass this opt-in composition. No startup/Session/manifest or
agentosd/default adoption. W5-D63-Q and prior security/current-base/config/pin/root/
operator/full consumer/media/latency holds remain. D37 ordinary/urgent/reissue
storage/time/overdue/invalid-input hold is not bypassed. No revocation/deadline/
interruption/refund/anti-delete/rollback/restore/config-integrity claim.

Positive tests use AGENTOS_PROTECTED_TEST_ROOT or UserHomeDir, explicitly configured
synthetic UID trustees and failure on unsafe/unwritable ancestry; no hidden skip or
security fallback. Fresh replay explicitly uses the private review-stack root,
not world-writable /tmp. Test-root compatibility is not deployment qualification.

## W5-D64 versioned policy custody

Version2 trusted-owner policy is explicit and pin-covered, not discovered root
trust. Decoded settings own reader-independent arrays; predecoded startup copies
policy before its constructor worker and actual protected lease retains a copy.
Version1/default/direct/other-slot paths can bypass this opt-in composition. Matching
old config/state/policies replay; expected pin/source/provenance/persistence/schema
adoption/provisioning/root namespaces remain external W5-D64-Q and prior Q holds.
Never bootstrap expected pin from checked bytes. UID/mode metadata observations
are not atomic whole-path/ACL/mount/same-UID/lock/media custody qualification.

Reader/config/constructor/I/O/drain can hang indefinitely holding one worker/slot/
lease; caller owns reader through total drain, independent owner controls before
config load, and ALL downstream consumers. Retired late bytes observed before
construction publish no Gate/clock/lease/write; no I/O interruption or deadline is
implied. Existing panic/unwind/cleanup-fault hold behavior remains. No agentosd or
operator default/schema adoption, refund/permission revocation/replacement writer/
anti-delete/rollback/restore/config-integrity/globalquota claim; D37 ordinary/urgent/
reissue storage/time/overdue/invalid-input hold preserved. External batch/strongest
security/current-base/SUB3/full consumer/pin/media/latency qualifications remain.

## W5-D65 cleanup uncertainty

An observed close/unlock failure may occur after partial resource release. Fixed
repeated failure is not forced lock retention, persistent admission state, media
qualification or restart authorization. Trusted external determination is required
before reuse; no automatic retry/repair/reset or second cleanup worker. Health is
retired before mutex wait, which may hang indefinitely with synchronous I/O.
Owned os.File preclose tests model OS faults safely, not disk failures or custody.
Constructor-time panic/unwind error propagation is separate and not fixed here.
All full-consumer/current-base/config/root/pin/media/latency/independent security
holds remain; D37 ordinary/urgent/reissue faults are never bypassed. No revocation,
interruption/deadline/refund/anti-delete/rollback/restore/config-integrity claim.

## W5-D66 unwind failure propagation

Private constructor unwind status is owned by the synchronous constructor worker,
then latched under Startup's publication mutex. It is not storage freshness or
persistent recovery state. Another slot/direct constructors/reboot can bypass the
cooperating in-memory hold. Actual faulted post-acquisition handoffs and separate
completion/admission models test propagation components; no whole-startup hostile
fault injector, disk/media or retained/released lock proof is claimed. Acquisition-
time cleanup failures remain separate from Gate assembly unwind qualification.
No new callback/hook/worker, retry/reset/repair/replacement writer, revocation,
activation or deadline. Synchronous construction/cleanup may hang forever. Trusted
external recovery and full consumer/root/config/pin/operator/media/current-base/
strongest independent security holds remain; D37 fault availability not bypassed.

## W5-D67 recovery policy adoption

Optional settings are explicit broker/operator authority from independently pinned
configuration; equality to a caller digest does not authenticate freshness/source.
Ledger authority is separate from the manifest or temporary digest. Matching old
settings/bytes replay. Omitting settings/v1/direct calls/other slots/reboot bypass
this opt-in policy. Copied owners avoid rereading caller settings after admission;
caller still owns trusted config/operator/full downstream quiescence and all writers.
UID/mode/name/version observations are not atomic root/ACL/mount/same-UID/lock/media
custody. Duplicate check-to-unlink races remain; failed unlink/sync/Close requires
trusted external determination before restart, no reset/retry/repair/activation.
Diagnosis never grants cleanup/restart; nonduplicate/unsafe/missing/partial/oversized
input stays held, malformed duplicate cleanup does not repair accounting schema.
New variadic signatures change function-value types: source/API adoption requires
explicit independent review. Synchronous acquisition/read/action/drain/Close can
hang forever with custody retained, no interruption/deadline/refund/revocation/
global or persistent quota/anti-delete/rollback/restore/config-integrity claim.
W5-D67-Q/inherited current-base/consumer/pin/root/media/security/latency qualifications
remain, preserving D37 ordinary/urgent/reissue fault availability hold. Tests use
owned synthetic roots/files/pins only, no shared-root chmod/hidden skips/fallback.
