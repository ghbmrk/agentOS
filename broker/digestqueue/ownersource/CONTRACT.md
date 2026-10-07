# W5-D16 owner-note collector adapter (unenabled)

This closed broker Source registers `owner-notes` and connects digestnotes' real
Peek/Ack to the durable collector. The complete typed note snapshot is retained
as a bounded broker-private Receipt, never a text line. The outer queue hash,
source identity, generation and exact lines are cross-checked before invoking the
source's HMAC-bound acknowledgment. Goal references are refused: this source holds
only guard counts/timestamps, not owner task content. Strict JSON decoding refuses
unknown fields/trailing values. Validate proves issuance, not owner authority.

Queue admission must precede source acknowledgment; collector recovery repeats
exact old receipts after partial acknowledgment. Tests reopen actual owner code,
note-source and queue files after source Ack but before the queue ack bit; a later
real owner-channel challenge drop survives into generation two without changing
code authority. Another test combines real change and owner-note sources: a failed
owner-note acknowledgment recovers without changing already-acknowledged change
associations, and a later change event survives independently. Full queue admission
and rehashed receipt forgeries cannot consume the source.

No producer text, code values, transport, timer, guest tool or daemon registration
is enabled. Do not text the Receipt or serialize the whole queue batch to a sender.
Owner clock/timezone, trusted source registration, private encrypted one-writer
state, retention/backups and forget/reset identity are deployment prerequisites.
Clearing/rekeying a source cannot silently reset its generation beneath a retained
queue high-water mark; coordinate reset/migration rather than weakening dedupe.

W5-D15's authority-to-note two-store capture gap and synchronous write latency
remain inherited integration limits. This adapter does not fix them. Receipt
validation does not complete queued/backup/transport deletion or dispatch policy.
Counts/timestamps remain private. Only a reviewed guarded sender may consume lines,
under STOP, quiet hours, shared pacing, priority, resources and complete disclosure
checks. Source/queue acknowledgments never imply owner/carrier visibility or
acceptance. Strongest independent broker/security review and threat check required.
