# W5-D2 durable digest queue — implementation candidate

This package realizes the storage/state-transition foundation of W5-D1. It is
not wired into agentosd, the owner channel, change.Pipeline or modemlink and cannot
send a text. External security review is required before integration. OP-1 and
OP-2 tests exercise notification identity/recovery only; they do not qualify
those requirements for every executor or establish A4/A10/A11 acceptance.

## Caller and storage boundary

1. Only fixed broker-rendered digest notices enter this queue. Do not expose this
   API to guests or use it for approval codes, stale decisions, auto-replies,
   agent text, provider requests or other effects. Snapshot hashes establish
   consistency, not authenticity, authorization or trustworthy wording.
2. One broker coordinator owns one Queue and its Store. Mutexes serialize threads,
   not independent processes. Store.Load must return one complete replacement;
   successful Save must commit the file and containing directory durably.
   Existing change.Store implementations satisfy the interface. This package
   reuses that boundary instead of introducing another on-disk writer. Private
   directory ownership, no untrusted filesystem writers, encryption and recovery
   inventory remain mandatory before daemon wiring. No symlink-safe file opener
   or encryption implementation is asserted here.
3. Capacity and retry numbers are explicit Limits, not hidden product defaults.
   The policy is persisted; mismatched policy, old schemas, unknown fields and
   corrupt state fail closed. Migration/configuration changes need their own
   reviewed path. No live source may silently reset generation or change its
   source identity to evade the retained high-water ledger.
4. Every source provides durable, nonconsuming, immutable generations. Source
   acknowledgment must consume only the exact generation/hash and be idempotent.
   Enqueue success precedes source Ack; only then call Queue.Acknowledge. A source
   generation appended later is not consumed by acknowledgment of its predecessor.
   Acknowledge cannot prove the source callback happened: it is a trusted broker
   integration API. Source implementations and collection wiring are follow-ons.

## Persistence and transition behavior

The batch contains copies of exact snapshots and a per-source acknowledgment
bitmap. Enqueue is atomic and idempotent for the same associations, contents and
creation/expiry times. Changed content/times or mixed duplicate/new associations
are rejected. Repeated collection must recover pending acknowledgments first;
independently generating new times for an existing snapshot is a conflict.

Every mutation is copy-on-write. Any Store.Save error quarantines the Queue,
including reads, until reopen. The caller cannot acknowledge sources on failed
admission. Reopen validates, changes sending attempts to unknown, and durably
re-saves the observed state even when nothing was sending: Load after a failed
directory sync is not enough to prove durable admission. If that save fails, no
usable Queue is returned. Callers treat reopen failure as capability unavailable.

Begin persists sending before transport invocation, only for ready batches with
all source acknowledgments. Finish binds observations to the current attempt.
A timeout or missing receipt is unknown. Only trusted affirmative not-sent
evidence permits another bounded attempt; an opaque evidence reference alone is
not proof. Transport acceptance is distinct from carrier delivery and owner
visibility. None feeds owner outcome or implicit-acceptance accounting.

Expiry affects ready notices only. In-flight and unknown sends remain unresolved.
Expire moves only ready batches with no consumed source to expired. A ready batch
past expiry with any consumed source stays ready and is reported by Held; callers
must surface that hold, not acknowledge an expired batch or invent a successful
send. Compact keeps an expired, cancelled or failed batch while any source is
unacknowledged, so recovery keeps blocking instead of wedging the source. Capacity includes unresolved/history records until
explicit compaction. Source ledger capacity remains bounded and is never silently
evicted; exhaustion requires visible recovery and an explicit migration policy.

Forget prechecks all matching batches and refuses without mutation if any matching
send is unresolved. Otherwise it purges entire matching batch payloads/references,
cancelling unsent batches while preserving accepted/expired terminal facts. A
mixed-source batch is wholly purged; integration must requeue unaffected source
notices safely or report the cancellation. Completion must also cover source
state, transport containment, all copies/backups and tombstones; this API alone
is not end-to-end CAP-3. Hash/source-generation dedupe metadata stays private and
must be included in reviewed retention/encryption/forget policy. Concurrent
forget and actual transport dispatch require integration containment; no atomic
cross-process forget/send guarantee is asserted.

Compaction discards terminal payloads, keeps every per-source high-water identity
and never rewinds the batch sequence. Repeated retired generations cannot be
re-enqueued. It never removes unknown/sending batches. Queue.Get/List are owned
copies, not send authorization; senders must call Begin and obey existing STOP,
quiet-hours, pacing, reservation, disclosure and authority checks separately.

## Remaining integration packages

- Source adapters: change/owner/question notices with persisted generations and
  peek/ack semantics; shared UNDO/MORE ID lifetimes and exact-source validation.
- Collection coordinator: durable admission then idempotent source Ack, recovery
  of partial acknowledgment and explicit full/expired/recovery status.
- Sender: current bridge protocol, fixed owner cadence and control priority;
  classified transport receipts and independent proof for not-sent retries.
- Daemon configuration/private storage, clock restrictions, retention, migration,
  encrypted backup/restore and forgotten-source cancellation.
- Assembled crash/outage/clock/forget tests and actual carrier/device evidence.

The current modemlink lossy outage behavior is unchanged. No auto-reply timing or
owner-visibility evidence is replaced by this queue.
