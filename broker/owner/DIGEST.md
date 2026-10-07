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
