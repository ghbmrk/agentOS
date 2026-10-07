# W5-D13 durable owner-note source (unenabled)

This source accepts only trusted broker Events: challenge-mode code-message drops,
silent/counting vault-limit hits, challenge-mode transitions, and wrong local-code
timestamps. It holds no code value, message text, owner goal, grant or send right.
It renders the existing owner-note fixed wording. There is no owner channel,
queue adapter, timer, transport or guest tool wiring in this candidate.

A separate source ledger is needed because the pipeline source models change
adoptions and the question source models untrusted agent questions, while the
owner authority Store models code/lockout state. Reusing those writers for guard
notification accounting would couple independent failure and trust boundaries.
Reuse the mature durable byte-store interface (e.g. change.FileStore), standard
JSON/HMAC and existing fixed count/timestamp rendering conventions instead.

Successful Record durably retains a typed event. Peek persists one nonconsuming
bounded generation and returns owned copies. Domain-separated HMAC receipts bind
its counts, captured timestamp prefix, overflow count and exact rendered lines.
Ack consumes precisely those counts/prefixes; newer events survive. Authentic old
receipts are idempotent, but still require a successful durable save. Receipts
prove source issuance, not owner/effect authority, visibility or carrier delivery.

At most 200 wrong timestamps are kept; additional events are counted, not silently
dropped. At most 20 times are rendered individually. An overflow accumulated after
a pending snapshot remains in the next generation. Counters/generations cannot
wrap. The serialized source state is bounded to 64 KiB and strict-decoded on
reopen; unknown/corrupt state and a different configured timezone name refuse.
The timezone's identity is configuration, not a frozen timezone database version.
An OS/timezone-rule update needs deployment qualification; pending lines remain
immutable. Full owner text can still exceed the sender's text limit, and large
counts can be secret-shaped: the sender must visibly hold such content or use an
independently reviewed renderer, never bypass disclosure or cut lines silently.

Every uncertain save quarantines this source until fresh durable reopen. Reading
visible bytes after a post-replacement error alone is insufficient: New resaves
observed state before use. Failure of Record cannot promise retention of that
unconfirmed event; integration must expose source health, retain existing control
operation and never report a source/queue acknowledgment as successful. This
module controls only notification accounting. It cannot decide STOP, code checks,
lockouts, urgent alerts or whether a failed code attempt counted.

Deploy on broker-private encrypted storage with one writer and bounded retention/
backup/forget policy. Timestamp history is private. The stored authentication key
is broker-private source metadata, never a provider credential, owner code or
transport payload. Do not expose Event/receipt methods to guests. No end-to-end
forget, encrypted-volume, power-cut, containment or carrier qualification is
claimed. External strongest-tier broker/security review and threat check remain
required before integrating or enabling this source.

## Ordered producer receipts (W5-D17)

`RecordOnce(id, event)` is an opt-in single-producer ingestion protocol on a
fresh source. IDs start at 1 and advance exactly by 1. The source atomically
persists the count/timestamp change with the ID and a domain-separated SHA-256
hash of the normalized typed event. Wrong-code timestamps normalize to UTC,
without a monotonic component; code values and message bodies remain absent.

Only the latest ID may be retried. Equal ID and equal event re-save durable
state and return success without adding a count. Equal ID with different
content, stale IDs, gaps, zero IDs and empty events are refused without changing
state. A source's persisted producer high-water survives digest acknowledgment
and reopen. One ID and one fixed-size hash bound replay storage. They convey
no owner authorization, send permission or carrier receipt. Sequence wrap is
refused. Concurrent calls serialize through the existing source mutex.

Anonymous `Record` cannot be mixed with ordered ingestion. An existing source
that contains or has snapshotted anonymous events cannot silently migrate into
the ordered protocol, even after acknowledgment. Empty, unsnapshotted state is
eligible. Older schema-1 files with absent producer fields still reopen in
anonymous mode; both producer fields must be valid together when present.
The prior implementation will reject new producer fields, so downgrade requires
an explicitly reviewed migration, rather than stripping replay protection.

Any save uncertainty quarantines the instance. Reopen re-saves observed state
before use; retrying the exact latest event adds it once if the prior replacement
did not happen, or adds nothing if it did. This also holds after its digest has
already been acknowledged. Tests cover before/after actual file replacement,
independent file/source objects, pending receipt preservation, acknowledgment,
changed parameters, legacy mixing and concurrent equivalent retries. File
replacement tests model caller uncertainty, not power-loss/media qualification.

A future authority outbox must commit a typed event and this ID in the **same
owner-authority transaction** as the relevant guard decision, retry it through
`RecordOnce`, and durably retire it before advancing to the next ID. Restoring
source and producer backups at different points, resetting IDs, multiple
producers, key rotation, missing retained outbox events and storage deadlines
require an explicit recovery contract. This candidate does not implement that
outbox or close W5-D15's authority-to-note capture gap. No owner integration,
daemon registration, sender or runtime qualification is enabled here.

## Source pairing before an authority outbox (W5-D19)

`ClaimProducer` durably selects ordered ingestion before the first event. The
claim excludes anonymous Record even at sequence zero and survives reopen.
A virgin source or an already ordered source may be claimed; anonymous history,
including acknowledged digest generations, requires an explicit migration.
Pre-D19 ordered state remains readable because a positive ingestion sequence
already implies ordered mode. Older binaries reject the new optional mode field.

`ProducerCheckpoint` is broker-private pairing/recovery data: a stable
HMAC-derived binding to the ledger key, the latest ingestion ID and its event
hash. It contains no key, code, message body or owner authority. A reset ledger
with a new key has a different binding; digest acknowledgment never resets its
producer checkpoint. Bindings deliberately link private source and outbox state;
do not expose them as guest tools, owner messages or public telemetry. Source
and authority storage must stay single-writer and privately composed.

An authority outbox must persist that binding, its acknowledged producer floor
and last event hash, plus all unretired typed events in the same transaction as
the guard state change. At recovery the source must match the binding and either
the floor/hash or exactly its next retained event/hash. A source behind the floor,
more than one event ahead, reset IDs, missing outbox entries or another producer
must hold for explicit recovery. No constructor may silently pair historical
notes with a fresh empty outbox. Claim uncertainty quarantines the source until
reopen and durable confirmation; an unpaired claim creates no event or authority.

`EventHash` canonicalizes a typed event for private checkpoint matching. Equal
instants use UTC, monotonic components disappear, and a zero-time instant in any
location means absent WrongAt. A differently represented Go zero time cannot
turn an otherwise empty event into a valid notification. Hash equality never
replaces source binding, owner authorization or transport evidence.

No owner-state outbox, producer routing, transport or daemon registration is
implemented by this source-lifecycle candidate. In particular W5-D15's anonymous
producer must not receive a claimed source. Its authority-to-note crash gap
remains until separately reviewed transactional capture and recovery are wired.
