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
