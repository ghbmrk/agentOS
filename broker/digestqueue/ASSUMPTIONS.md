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

begin (unexported; called only by Sender.Send) persists sending before transport invocation, only for ready batches with
all source acknowledgments. Finish binds observations to the current attempt.
A timeout or missing receipt is unknown. Only trusted affirmative not-sent
evidence permits another bounded attempt; an opaque evidence reference alone is
not proof. Transport acceptance is distinct from carrier delivery and owner
visibility. None feeds owner outcome or implicit-acceptance accounting.

Expiry affects ready notices only. In-flight and unknown sends remain unresolved.
Expire moves only ready batches with no consumed source to expired. A ready batch
past expiry with any consumed source stays ready and is reported by Held; callers
must surface that hold, not acknowledge an expired batch or invent a successful
send. Compact keeps a cancelled or failed batch while any source is
unacknowledged, so recovery keeps blocking instead of wedging the source; an
expired batch is dropped once no ledger entry points to it (W5-Db). Capacity includes unresolved/history records until
explicit compaction, except dead batches below. Source ledger capacity remains bounded and is never silently
evicted; exhaustion requires visible recovery and an explicit migration policy.

Forget prechecks all matching batches and refuses without mutation if any matching
batch is Sending (ErrInFlight). Otherwise it removes matching snapshots per snapshot from
ready and expired batches (W5-Db below) and redacts accepted, failed, cancelled
and unknown batches whole. An unknown batch keeps its state, attempts, evidence,
dates and Late, so its STATUS line and the next digest's line about it stay
(OP-9, CH-15); validate admits Redacted on Unknown as on terminal states, finish
refuses any redacted batch (ErrState) and begin already does, so it is never
resent or revived, and Compact keeps it, as it keeps every unknown batch
(W5-Dc-r7), until Enqueue evicts it for room (W5-Dc-r9 below). The source duty below holds for it too: a re-offer of the forgotten
generation is ErrConflict, a higher generation is admitted. Redacting an unknown batch whole while keeping its state is a
reading CAP-3 supports, not one SPEC states: its text is a derived copy nothing
renders again, and a text the owner may already have is an action already taken.
The Sending refusal is bounded: Send finishes the batch within the transport's
wait, and a crash makes it unknown on reopen. Completion must also cover source
state, transport containment, all copies/backups and tombstones; this API alone
is not end-to-end CAP-3. Hash/source-generation dedupe metadata stays private and
must be included in reviewed retention/encryption/forget policy. Concurrent
forget and actual transport dispatch require integration containment; no atomic
cross-process forget/send guarantee is asserted.

Compaction discards terminal payloads, keeps every per-source high-water identity
and never rewinds the batch sequence. Repeated retired generations cannot be
re-enqueued. It never removes unknown/sending batches. Queue.Get/List are owned
copies, not send authorization; only Sender.Send may begin a batch, and callers obey existing STOP,
quiet-hours, pacing, reservation, disclosure and authority checks separately.

## W5-Db sender contract

- The gate is structural: begin and finish are unexported and
  TestOnlySenderSendCallsDeliver fails if any non-test code other than (*Sender).Send
  names begin, finish or Deliver. One provisional exception (SG-3): the fixed
  queue-outage line (W5-Dc DC-8), which carries no queued content.
- Render failure, empty rendering or render panic is recorded NotSent
  ("render-failed"): the transport was never called, so it is affirmative proof,
  and it consumes one bounded attempt.
- If finish cannot persist, Send returns OutcomeUnknown and the error; the queue
  is quarantined and reopening turns the sending attempt unknown, never resent.
- A context ended during Deliver makes NotSent unprovable (Unknown); Accepted
  with evidence stands. A transport panic is Unknown.
- modemlink.SendReceipt reports not-sent only when the bridge never took the
  text: refused before queuing, timed out while still queued (checked under the
  link lock), or CodeRecipient. CodeRecipient => not sent rests on bridge.go
  emitting it only for a non-owner item before m.Send, or via codeOf from
  at.ErrNumber, which only Dial returns; TestRecipientCodeOnlyBeforeModemSend
  pins both by AST. Caveat: the bridge is trusted to report codes honestly; a
  lying bridge could misreport CodeRecipient, but it could equally misreport
  CodeOK, so this adds no new trust.
- modemlink does not import digestqueue; the Transport adapter is W5-Dc.
- Held batch: recover finishes its remaining acks; Late re-arms it once (sets
  Late and a new expiry), only when Held reports it and every source is acked.
  begin's expiry check is unchanged.
- Forget is per snapshot on ready/expired batches; a ready batch left empty is
  cancelled. Source duty: drop the forgotten reference, never re-offer a
  generation containing it, offer a higher generation without it. A forgotten
  generation re-offered is ErrConflict, so Collect fails visibly until then.
- Expired batch: recover skips it; Enqueue re-admits the same source, generation
  and hash as a new Ready batch when the ledger batch is expired and still holds
  that snapshot (validate accepts an expired batch whose snapshot the ledger has
  since moved past). Non-expired batches keep OP-1 idempotence and ErrConflict.

## W5-Dc wiring (agentosd)

- Storage: queue.json and digest-sources.json under -digest (default
  /var/lib/agentos/digest) through change.FileStore. At start the directory is
  created 0700 if missing, refused if a symlink or not a directory, otherwise
  set to 0700, and any leftover `*.tmp` is removed so a save cannot inherit a
  wider mode; a refused directory leaves the store down (STATUS line). No digest
  runs without -modem-bridge; the queue opens on the first tick, never at
  construction, so a failed open is a STATUS line, not a crash loop.
- Digest time: provisional 08:00 box-local (SG-2, W5-Dc-r2). One daily step
  per calendar day after 08:00; a box started later sends that day's digest at
  once. Days are counted from the box clock; a clock moved back never sends a
  second digest for a day already done (LastDay is persisted).
- Attempts (W5-Dc-r4): a NotSent costs one attempt. Ready batches are retried
  every 30 minutes, so a batch gets 48 tries over its own day and 48 over its
  late day; MaxAttempts is 96, and a line-down or full-queue outage under 24
  hours cannot exhaust a batch.
- Limits: MaxBatches 128, MaxSnapshots 16, MaxAttempts 96, MaxBytes 8 MiB.
- Sources: "day" (generation = days since epoch, its fixed line only when no
  other source is pending) and "digest-status" (one line per surfaced
  batch not yet carried by an accepted digest, at most 3 per digest; its carried
  map is persisted, so a line is carried once unless its carrier itself turns
  unknown). DIG-1 owns the other sources.
- Transport: the adapter keeps only Receipt.Evidence (the bridge's item ID or
  fixed tag); the recipient number and text never reach the queue. An
  unrecognised receipt outcome is Unknown with no evidence.
- Render refuses (NotSent "render-failed") a digest over control.MaxText; it
  never cuts one. Bounding the sources' total length is DIG-1's.
- Outage (DC-8, provisional, SG-3): when Collect fails and the queue no longer
  reads, one fixed line through owner.Inform from the daily step only, at most
  once per box-local day, never retried; the STATUS line stays while the queue
  is down. The daily step's LastDay is persisted, so a restart does not repeat
  it; if the state store fails too, only the in-memory latch holds and a
  restart may send the line again that day.
- Forget (CAP-3): ownerForget calls the queue's Forget for the item reference
  after its own forget; an Unknown batch holding it is redacted and the forget
  is done (W5-Dc-r7). ErrInFlight (a Sending batch holds it) leaves the forget
  owed on the existing retry path. The start-up tombstone
  replay asks the queue's Forget again before the done text and retries with
  backoff until it holds, so a restart between forget and purge cannot report
  the forget done (security B2 on #592). A reference the queue has not purged
  (not open, a store refusal, or ErrInFlight) is kept by the box and saved in its state store
  (`digest-sources.json`, `forgets`) before the refusal returns: every open
  loads it and purges it before any send, no Ready batch holding it is sent
  meanwhile, and it is dropped once the queue's Forget holds. The hold so does
  not depend on boot order or on the forget owner's owed file (security B2' on
  #592). Every open also asks the queue to forget each tombstoned goal and
  stays down until each holds, so a stop between the tombstone and the purge
  with the owed save failed too sends nothing (W5-Dc-r12).
  agentosd starts the digest after the forget owner's start-up replay.
  If the state store also fails, the hold is in memory only until a restart.
  The box sends under its lock, so its own forget never sees a Sending batch:
  with the queue open, only a store refusal (which breaks the queue until the
  next open purges) reaches the hold; the Ready-batch skip in sendReady stays
  as a guard and is pinned directly (W5-Dc-r7).
- Owed collection (CH-15, L3 1 on #592): a Collect error with the queue still
  reading leaves the day owed (LastDay not advanced), shows a STATUS line, and
  collects again every digestRetry (30 minutes); after a restart the owed day
  collects at once. One digest goes out per day.
- Gate (OP-2, DC-6): TestDigestGate parses the broker tree. Deliver is named
  only in digestqueue/sender.go and three listed non-digest sites; cfg.Transport
  only where main assigns it and as digestqueue.NewSender's argument in
  openLocked; cfg is never copied bare; digestTransport only inside its own
  constructor and methods; no reflect, MethodByName or Method in agentosd;
  sendOutage takes no parameters and informs only digestOutageLine; Batch
  Snapshots and Snapshot Lines are read only in render, carrier and refersTo.

- Quiet hours (CH-15, W5-Dc-r1b QH-7): `sendReady` sends nothing while the
  owner's quiet hours hold (`digestConfig.Quiet`, the owner channel's
  `Quiet`); the batch stays Ready and the first step after they end sends it,
  not the next 30-minute retry. The digest never reads the hourly allowance
  (SG-r1-6). With the setting unchanged a wait cannot pass the batch's
  Expires: quiet hours are under 24 hours, a batch due in them is made at the
  digest time, and Expires is the next day's digest time, so the window ends
  first. A setting widened while a batch waits can pass it; then the existing
  Late path sends that day's digest once, as a late digest, before the next
  day's (TestDigestWaitsForQuietHoursToEnd). If quiet hours end just before
  the digest time, the held digest and the new one go minutes apart.

## Remaining integration packages

- Source adapters: change/owner/question notices with persisted generations and
  peek/ack semantics; shared UNDO/MORE ID lifetimes and exact-source validation.
- Collection coordinator: durable admission then idempotent source Ack, recovery
  of partial acknowledgment and explicit full/expired/recovery status.
- Sender wiring (W5-Dc): modemlink adapter for Transport, render wording
  including the late header, fixed owner cadence and control priority.
- Daemon configuration/private storage, clock restrictions, retention, migration,
  encrypted backup/restore and forgotten-source cancellation.
- Assembled crash/outage/clock/forget tests and actual carrier/device evidence.

The current modemlink lossy outage behavior is unchanged. No auto-reply timing or
owner-visibility evidence is replaced by this queue.

Dead batches give way to today's digest (W5-Dc-r9). A dead batch can never be
sent again and is kept only so a caller can name it: Unknown (redacted or not),
or Ready, Late and not before its Expires at the new batch's created time (held
again after one re-arm). Enqueue appends the new batch, then, while the new state
holds more than MaxBatches batches or its JSON passes MaxBytes, removes the
lowest-ID dead batch; if none is left and it still does not fit, ErrFull and the
store is unchanged. Eviction and admission are one save. With room, nothing is
evicted, so STATUS and the digest name every dead batch as long as it exists
(OP-9); one goes only when the alternative is refusing today's digest (CH-15
outranks keeping an old notice). Seq and every Latest entry stay, so a re-offer
of an evicted batch's generation is ErrRetired (or ErrConflict for an older one):
eviction removes text and never revives or resends it (CAP-3). Its sources are
all acknowledged (validate and Late require it), so none is wedged. Assumed:
Enqueue's created is the caller's now (agentosd Collect passes it); a created in
the past only makes fewer late batches dead. Sending, Ready not dead, terminal
and held-not-yet-late batches are never evicted here; terminal ones are
Compact's. Rejected: age-based retention in Compact (needs a horizon SPEC does
not give and still fills with more dead batches than MaxBatches inside it); a
caller Retire after the line is carried (a carrier that keeps going Unknown never
carries it); moving dead batches to Cancelled (claims not sent, loses the line).
