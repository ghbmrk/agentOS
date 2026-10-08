# Optional durable shared pacing

This is review scaffolding for CH-15, CAP-10 and CH-11, not daemon activation or
independent security acceptance. Nil `Config.PacingStore` preserves legacy
volatile behavior. Configure a private exclusive store to persist the **actual
Gate** shared by approval requests, `question.Config.Reserve`, and
`dailypolicy.Config.Budget`; do not instantiate a separate digest counter.

The structurally compatible `change.FileStore` supplies existing write/fsync/
rename/directory-sync persistence. No new filesystem writer or external package
is needed. Use a distinct protected path, one live Gate writer, a trusted
qualified clock, and bounded Store/Now callbacks. The existing FileStore loads
the complete file before the Gate's byte validation; filesystem storage must
also be protected against adversarial file growth, symlinks and concurrent
replacement. The file contains only policy limit and accounting timestamps,
never owner text, question prompts, intent IDs, receipts or recipients.

Construction loads canonical schema-1 JSON, checks the configured limit,
ordered timestamps and trusted time, prunes expired reservations, and confirms
the image durably before admitting requests. The limit is 1–4096 for this
optional mode (zero/negative take the Gate's existing default). A policy-limit
change requires a separate reviewed migration; it cannot reset an allowance.
Missing state is treated as **trusted first provisioning** only when the trusted
configuration leaves `PacingRequireExisting` false. Set it **true** for every
provisioned installation/restart. In required mode an absent Store or a Load
returning nil state latches recovery before any initialization Save; no file is
created and no request/question/digest reservation is granted. An existing
canonical empty allowance is valid state, unlike an empty file. The storage
schema and accounting algorithm are unchanged.

Provisioning must happen under reviewed authority with exclusive store custody,
then the installation's trusted persistent configuration must require existing
state before runtime starts. This component does not persist that deployment
setting, infer installation history or authorize switching back to provisioning.
Nil Store plus the required flag is a configuration error represented by the
same fixed recovery hold, so it cannot silently select volatile behavior.
Default false preserves legacy opt-in callers, and is not a qualified restart
configuration. Deletion is refused when required mode is retained, but a valid
older file/backup may still pass. Authenticated anti-rollback/anti-deletion
custody, trusted configuration integrity, multi-writer locking and restore
freshness remain external qualification requirements; this flag alone is not
such proof.

Every Reserve and request take commits before returning permission. Requests,
questions and digests consume the same allowance. A reservation is spent even
if later context, STOP, owner-channel failure or transport refusal proves a
non-send. No refund/retry shortcut is supplied. An aged question's one turn
before a waiting approval batch is persisted in the same transaction. Requests
outside pacing (urgent/active/reissued) still count. The newest `limit`
timestamps are sufficient: any discarded older timestamp expires no later than
all retained ones, so whenever discarded debt is live, at least `limit` newer
reservations still prevent a paced send. This keeps storage and urgent append
work bounded while preserving exact remaining paced allowance.

Any invalid state, failed Load/Save, zero time, unsupported clock range or
rollback latches `ErrPacingRecovery`, with no underlying error/path disclosure.
Both before-write and after-replacement failures quarantine the live object.
There is no in-place clear/retry. Quiesce the old Gate and recover with a fresh
Gate against the **same** store; constructor confirmation must succeed. If the
failed reservation did not persist, it never returned permission and cannot
have handed off; if it persisted, its count remains spent after reopening.
A recovered allowance does not prove freshness against a restored older file.

All request handoff paths check the returned take count, including reissued
texts and reissued local-page approvals. Failed accounting keeps waiting items
queued. When a durable save stalls across engine STOP, a post-save stopped
check prevents handoff and retains the already-spent reservation. STOP itself
does not acquire the pacing store's lock or wait for its I/O in the tested
journal path. This does not qualify hardware STOP latency or introduce atomic
ordering against a STOP racing after the final check.

**Availability review hold:** healthy urgent and reissued traffic bypass the
rate limit, but storage failure or invalid time holds even these requests.
That prevents silent accounting bypass, and conflicts with any interpretation
of the R3 reissue rule that requires delivery despite broken accounting.
Strongest independent broker/security review must explicitly settle that
tradeoff before wiring this option. STOP/RESUME confirmations live in the owner
control channel, not Gate.take, and this option does not pace them. The held
waiting request can still expire; no claim that storage faults cannot hide an
urgent alert is made. The health signal must reach trusted recovery/status
wiring before production. Ordinary allowance exhaustion is not a recovery
failure.

Persistence currently serializes under the Gate's existing mutex. This avoids
another counter, conflicting writers or a save/permission race; a slow store
can delay other Gate policy work and health reads. No timeout worker that
could outlive the operation is created. Store latency/availability qualification
and cancellation-aware scheduling remain integration work.

Tests use actual FileStores, reopen and before/after-write cuts; mixed request/
question reservations, aged priority, staggered urgent debt, exact expiry,
concurrency, malformed state and clock rollback are covered. A blocked real
save exercises prompt engine STOP and refusal of post-STOP reissue handoff.
They are local evidence, not carrier/device qualification or CI acceptance.


Required-mode tests first exposed missing/deleted-state resets and a nil-store
fallback. Actual FileStore checks now prove refusal leaves missing/empty paths
unchanged, provisioned spent debt survives strict reopen, and normal hour expiry
still permits the intended allowance. These establish the explicit configuration
behavior, not successful provisioning authorization or anti-restore acceptance.
