# W5-D15 opt-in owner-note source integration

Config.DigestNotes explicitly supplies a separately opened digestnotes.Source.
No default source/path is created and agentosd is unchanged. With no source,
legacy TakeDigestNotes, counters, urgent alerts and code behavior are preserved.
With a source, trusted challenge drops, vault-limit flags, challenge transitions
and wrong-local-code times become typed source events. TakeDigestNotes then
returns no lines: a source failure cannot silently switch to destructive reads.
The source's durable Peek/Ack interface is the only notification consumer.

Record errors quarantine only the source. A fixed OwnerDigestStatus line is
included in owner/local STATUS; underlying error text, paths, keys and code values
are not disclosed. Existing code attempt/lockout decisions and urgent alerts are
unchanged. Text and local STOP use their immediate containment paths and bypass
an owner lock held by a notification write; tests block that actual Store.Save
and verify both entry points. Ordinary source writes are synchronous under the
owner worker lock, so slow storage can delay other owner operations. Bounded
storage latency and resource admission remain deployment prerequisites.

The owner and daemon control-path import guards inspect digestnotes under the
same network/process/third-party/broker dependency bans. The new package has no
broker dependencies or inference call. Store and source configuration are trusted
broker composition, never guest-supplied. Producer registration, matching owner
clock/timezone, private encrypted storage, one writer, retention and backup/forget
rules must be reviewed before enabling. Do not pass agent text through this source.

A successful source Record proves that typed event is durable. It does NOT make
owner code-state and note-source writes atomic: a physical crash after an authority
state commit but before Record can leave the notification missing. Likewise a
failed Record cannot promise retention of an unconfirmed event. Source health is
visible, but closing this gap requires reviewed transactional event/outbox or
reconciliation work. This candidate must not be advertised as complete guard-event
capture or deployment qualification.

Source snapshots/acknowledgments are distinct from queue admission, transport,
carrier/owner evidence and acceptance. No queue adapter, sender, timer or daemon
is enabled here. Full STOP/forget/pacing/quiet policy and complete text rendering
remain integration gates. Strongest independent broker/security review and an
explicit threat check are required before wiring this opt-in configuration.

## W5-D20 transactional owner-state outbox foundation

`NewDigestOutbox` is a standalone, explicitly composed single-writer coordinator
for the owner Store. It embeds at most 128 typed unretired events, a private source
binding and a producer floor/hash inside State. `Commit(event, mutate)` saves a
copy containing **both** the authority mutation and its outbox event through one
owner Store.Save. `Update(mutate)` saves an authority-only mutation while retaining
all outbox metadata. Neither callback may have external side effects or rewrite
outbox fields. State and MemStore copy the complete nested metadata and entries;
caller-owned arrays and callbacks cannot change a confirmed stored transaction.

This coordinator is not used by existing Channel handlers or agentosd. Do not run
it concurrently with Channel, another coordinator or another writer to the same
Store. A future handler integration must delegate **every** authority mutation to
one coordinator, classify the guard event at the actual code-state transition,
and preserve code replay limits, lockouts, urgent alerts and immediate STOP.
Calling Commit from after an existing authority save would reintroduce the gap.
Current W5-D15 anonymous recording remains unchanged and retains its original gap.
There is no claim of retroactive event capture before this coordinator is opened.

Opening validates the retained outbox, durably claims ordered source mode, verifies
the source binding and checkpoint, and re-saves observed owner State before use.
An empty outbox may pair only with source sequence zero. A retained outbox accepts
its exact acknowledged floor/hash, or exactly its first pending ID/hash already
saved by that source. Source reset, another key, a source behind the floor, more
than one event ahead, a changed pending event or missing retained metadata holds
for explicit recovery. Do not reset IDs, discard backlog, edit hashes or invent a
new binding to force open. Backup skew and downgrade need a reviewed migration.
Older owner binaries ignore unknown State fields and can erase this outbox; no
rollback/deployment is qualified. Restoring the source key can restore its binding,
so the floor/hash checks remain necessary alongside binding equality.

Flush processes retained IDs in order: source RecordOnce confirmation → owner
retirement save → next event. A source digest may be acknowledged before an
uncertain retirement is recovered; replay still retires the exact producer ID
without restoring its consumed counts. Source failures retain all authority-side
entries and permit later transactions until the bounded backlog is full. Source
health is inspectable separately. Full capacity and producer wrap refuse a guard
transaction **before its callback**; no entry is evicted or silently coalesced.
How capacity refusal maps to conservative code/lockout policy is an integration
review decision, not a new automatic handler behavior here.

Any owner Store.Save error quarantines the coordinator: State, Commit, Update and
Flush refuse until fresh owner/source objects are reopened and observed state is
confirmed. A source mismatch also quarantines it. A source save error quarantines
that source, and cannot itself erase retained authority entries. Flush checks
cancellation between synchronous store calls; it does not interrupt a hung store.
Bounded storage latency, private encrypted storage, one-writer exclusion, resource
admission, retention/forget and STOP/dispatch integration remain prerequisites.

The actual-file fault tests inject errors before and after owner transaction save,
source ingestion and owner retirement. Independent objects verify that authority
and pending events cannot tear across one owner replacement, and source replay
counts once across retirement uncertainty. These are caller-error cuts around
real atomic FileStores, not power loss, media fault or hardware qualification.
No code verifier, model, modem, sender, scheduler, queue consumer or carrier runs.
Strongest independent broker review and an explicit threat check are required.

## W5-D21 composition and capture-error visibility

Existing Channel handlers are anonymous producers. New refuses a known ordered
DigestNotes source, including an empty claimed source, and refuses any State with
transactional DigestOutbox metadata. The latter prevents an unintegrated channel
from booting on a file whose authority changes must pass through the coordinator.
Refusal changes no stored state and invokes no engine authority. This is a
composition check, not a replacement handler, startup STOP service or writer lock.
Do not migrate the daemon's active store to outbox mode before reviewed handler
integration, downgrade rules and control-path availability are implemented.

An anonymous source outage still permits the existing owner channel to start;
valid code checks and immediate text/local STOP remain independent of notification
storage. UsesOrderedProducer reports last confirmed mode, not successful recovery
of an uncertain claim. Source Health continues to flag that uncertainty.

All anonymous Record errors now latch a capture-failure flag on the channel,
including mode/input refusals that leave Source.Health healthy. A late external
claim after construction is therefore visible in the same fixed digest-status
wording, cannot fall back to destructive notes, and does not change code counters
or STOP. The flag clears only with channel reconstruction after the composition
and recovery checks; later successful records cannot silently erase evidence of a
missed event. It is not durable event retention, does not reconstruct that missed
event after a crash, and does not close the anonymous producer's transaction gap.
Source registration and lifecycle remain trusted single-writer composition.
