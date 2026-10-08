# OSS-6s-a: Constant daily batch, idempotent ledger, cover send

Board section: Backlog refill (2026-10-05). Split from OSS-6s on #325; OSS-6s-b carries the Tor transport.

Part a of the publication sender (`pubid.Sender`, OSS-6 P9, security W3 and N1 on #163). It builds everything that does not touch the network: the batch shape that is the same on the wire every day, the idempotency ledger, and the daily cover send. Bytes leave only through a `Transport` interface, which tests fake. OSS-6s-b implements that interface over Tor, to the relays.

**Rulings this rests on**
- Q2 (Mark, 2026-10-08, #325): a constant daily batch of **16 slots × 64 KiB = 1 MiB**. This is an image constant, so an update can change it. Overflow carries to the next day.
- Q1/Q3 (D-062, SPEC OSS-6): Tor always, with no direct fallback. Publishing is silent to the owner. This part does not choose the transport. The constant cadence and padding are on in every configuration; there is no setting that turns them off.

**Requirement IDs.** Tests carry `REQ: OSS-6`. The acceptance items below are numbered OSS-6s-a1 to a9, and each test names the item it covers in its name or comment.

- **a1 Constant size.** Every daily send is exactly `Slots × SlotSize` bytes (16 × 65 536) after framing, whatever the number of items (0 to 16 slots' worth). The test sends days with 0, 1 and 16 items and a day with overflow, and checks that every frame is the same length.
- **a2 Fixed cadence, empty days included (cover send).** Every counted day produces one send, also when nothing is due. A cover batch is a validly signed batch with zero items under that day's key, so it can't be told apart from a real batch without verifying and parsing it. The test covers a run of empty days between real ones: one send per counted day, all the same size.
- **a3 Overflow carries.** Items take whole slots. An item uses ceil(signed size / slot payload) consecutive slots. At release, due items are taken in queue order while they fit. The rest stay queued and leave on a later counted day, never early. They don't count against the next day's draw, and no item is lost or reordered. An item too large for the whole batch is refused at `Queue`: `MaxPayload` falls to what fits 16 slots after signing and framing. The ASSUMPTIONS row states the arithmetic.
- **a4 Idempotent by day and batch hash.** The ledger key is (day, SHA-256 of the canonical unpadded batch). Re-sending a key already confirmed is a no-op. A different batch hash for a day already confirmed (the clock more than 400 days back, N1) is new and is sent, never dropped as a duplicate.
- **a5 Retries repeat the same bytes.** The padded frame for a key is fixed on its first attempt: padding comes from a stored seed or from the key, so a retry after a crash or an error re-sends identical bytes and observers never see two versions. The test fails the transport after it has accepted the data, then retries, and checks one logical publication with byte-identical frames.
- **a6 Crash safety.** The ledger is written atomically, in the same style as the pubid outbox. A crash between the transport accepting and the ledger recording leads to a re-send of the same frame (a5), never a second different frame for that key.
- **a7 Padding reveals nothing.** Padding bytes are from crypto/rand (or a keyed stream over a stored random seed). No length field outside the signed envelope shows the real item count. The framing is documented in ASSUMPTIONS.
- **a8 Import fence.** The sender lives in its own package (for example `broker/pubsend`). `TestOSS6PubidReachesNoOwnerStoreOrNetwork` still passes, and `pubsend` imports no network package itself: the network sits behind `Transport`.
- **a9 Queue bound.** When the transport is unreachable, frames wait. When the backlog passes the bound, the oldest are dropped (SPEC OSS-6). The bound value comes from OSS-6p; until then it is a named constant marked provisional in ASSUMPTIONS. The drop goes in the owner-visible log only (OSS-1), never in a text, the digest or STATUS.

**pubid changes (in scope).** `Publisher.Release` currently calls `Sender.Publish` only when something is due (`publisher.go`, `if len(due) > 0`). It must call it on every counted day (a2), and select by slots (a3). Lower `MaxPayload` (a3). **Ordering:** #319 (OSS-6e) edits publisher.go's clock and outbox fields. Start after #319 merges, or merge main in when it does, and don't edit those lines. The publisher's guarantees G1 to G4 (D-046, the OSS-6 clock row) must still hold: overflow only lengthens waits.

**Out of scope (OSS-6s-b and others).** The Tor SOCKS transport, the relay list, delivery acknowledgements (OSS-6p values), a fresh circuit per batch and key (OSS-6i, whose test lands in b), and the repository's pull, verify and append job (OSS-6j).

**Synthetic canaries only.** No credentials, tokens or personal data in code, tests or fixtures.

**Needs:** OSS-6 (merged); #319 ordering as above

**Gate:** lenses (security, privacy); tier A expected (effects)
