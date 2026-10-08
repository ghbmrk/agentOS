# OSS-6s-a: Constant daily batch, idempotent ledger, cover send

Board section: Backlog refill (2026-10-05). Split from OSS-6s on #325; OSS-6s-b carries the Tor transport.

Part a of the publication sender (`pubid.Sender`, OSS-6 P9, security W3 and N1 on #163). It builds everything that does not touch the network: the batch shape that is the same on the wire every day, the idempotency ledger, and the daily cover send. Bytes leave only through a `Transport` interface, which tests fake. OSS-6s-b implements that interface over Tor, to the relays.

**Scope:** `broker/pubsend/` (new) with its tests and ASSUMPTIONS.md; `broker/pubid/publisher.go` (`Release`, `MaxPayload`) with its tests and ASSUMPTIONS.md; this brief; the BOARD row.

**Rulings this rests on**
- Q2 (Mark, 2026-10-08, #325): a constant daily batch of **16 slots × 64 KiB = 1 MiB**. This is an image constant, so an update can change it. Overflow carries to the next day.
- Q1/Q3 (D-062, SPEC OSS-6): Tor always, with no direct fallback. Publishing is silent to the owner by default; the a9 owner-visible log is the only owner channel. This part does not choose the transport. The constant cadence and padding are on in every configuration; there is no setting that turns them off.

**Requirement IDs.** Tests carry `REQ: OSS-6`. The acceptance items below are numbered OSS-6s-a1 to a9, and each test names the item it covers in its name or comment.

- **a1 Constant size.** Every daily send is exactly `Slots × SlotSize` bytes (16 × 65 536) after framing, whatever the number of items (0 to 16 slots' worth). The test sends days with 0, 1 and 16 items and a day with overflow, and checks that every frame is the same length.
- **a2 Fixed cadence, empty days included (cover send).** Every counted day produces one send, also when nothing is due. A cover batch is a validly signed batch with zero items under that day's key, so it can't be told apart from a real batch without verifying and parsing it. The test covers a run of empty days between real ones: one send per counted day, all the same size.
- **a3 Overflow carries, no head-of-line block, no order leak.** Each item takes whole slots: ceil(signed, framed size / slot payload) of them, in a row.
  - *Bound.* A named constant bounds the overhead. It covers the per-item signature, envelope and slot or length header, and also the batch envelope, the batch signature (a2's zero-item cover batch is signed too) and any batch header. Tests check it against every registered `Signer` kind. `MaxPayload` is derived so that `Slots × SlotSize ≥ batch overhead + ceil-slot(MaxPayload + item overhead)`: one maximum-size item fits an empty batch. An item over `MaxPayload` is refused at `Queue` and never enters the queue.
  - *Selection.* At release, carried items go first, ordered by due-day cohort, oldest first. Newly due items come after them, as the youngest cohort. Within one cohort, the order carries no queue information: a fresh crypto/rand permutation, or ascending SHA-256 of the payload keyed by that day's key. Items are taken in that sequence until the first item that doesn't fit, and the rest carry. Stopping at the first misfit is safe under cohort order. Every item fits an empty batch (Bound), so each day publishes at least the head of the oldest cohort. Only older cohorts, or items of its own cohort, can be ahead of a given item, so nothing that came due later ever overtakes it.
    - Test 1 (P4, queue order must not show): on an overflow day, which items of a cohort carry does not depend on their queue order.
    - Test 2 (bounded wait): under constant overload, every item is published within N counted days of its due day. N = ceil(B / (C − m + 1)), where:
      - C is the slots items can use: `Slots` minus the slots the batch overhead takes, derived from the overhead constant (Bound).
      - m = maxItemSlots, the slots of a `MaxPayload` item. m ≤ C, so the divisor is at least 1.
      - B is the unsent item slots due at or before the item's due day, counted at that day's release, before selection.
      - The test asserts against C, never `Slots`, and includes an adversarial cohort order (a 1-slot item ahead of an m-slot item). The whole queue reshuffled as one cohort each day would let one item lose the draw indefinitely, and cohort order is what prevents that.
  - *Storage.* A carried item is stored with its due day (its cohort), a monotone counted-day index, not a wall-clock date, so cohort order holds under the N1 clock-back case. The loader sanity-bounds it as it bounds `Wait` with `maxWait`. It refuses a due day after the current counted day, or one older than the longest wait the queue bound allows (`MaxQueue` × m days). A fixed `maxWait` age limit would drop items that are legitimately carried under overload. A carried item also carries an explicit `Carried` flag, or is stored as `Wait == 0` plus the due day, and the outbox loader (`publisher.go`, today's `Wait < 1` check) accepts it. A carried item is never decremented below due: today's `it.Wait--` would make it -1, and it would never be due again. Carried items leave on the next counted day and are never lost. A test restarts the publisher with a carried item in the outbox: it loads, and it leaves on the next counted day.
  - *ASSUMPTIONS row for a3.* It gives the overhead bound and the arithmetic. It also records three residuals: (i) carrying shows publicly that a day was full, because an item appears after its maximum delay; this is inherent to the Q2 ruling. (ii) The loader refuses a stored item above `MaxPayload`, so a future constant change by update (Q2, OSS-6m) must not lower `MaxPayload` below items already stored, or must migrate them. (iii) "Silent" follows D-062's "silent to the owner by default": the a9 owner-visible log is the only owner channel.
- **a4 Idempotent by day and batch hash.** The ledger key is (day, SHA-256 of the canonical unpadded batch). Re-sending a key already confirmed is a no-op. A different batch hash for a day already confirmed (the clock more than 400 days back, N1) is new and is sent, never dropped as a duplicate.
- **a5 Retries repeat the same bytes.** The padded frame for a key is fixed on its first attempt: padding comes from a stored seed or from the key, so a retry after a crash or an error re-sends identical bytes and observers never see two versions. The test fails the transport after it has accepted the data, then retries, and checks one logical publication with byte-identical frames.
- **a6 Crash safety.** The ledger is written atomically, in the same style as the pubid outbox. A crash between the transport accepting and the ledger recording leads to a re-send of the same frame (a5), never a second different frame for that key.
- **a7 Padding reveals nothing.** Padding bytes are from crypto/rand (or a keyed stream over a stored random seed). No length field outside the signed envelope shows the real item count. The framing is documented in ASSUMPTIONS.
- **a8 Import fence.** The sender lives in its own package (for example `broker/pubsend`). `TestOSS6PubidReachesNoOwnerStoreOrNetwork` still passes, and `pubsend` imports no network package itself: the network sits behind `Transport`.
- **a9 Queue bound.** When the transport is unreachable, frames wait. When the backlog passes the bound, the oldest are dropped (SPEC OSS-6). The bound value comes from OSS-6p; until then it is a named constant marked provisional in ASSUMPTIONS. The drop goes in the owner-visible log only (OSS-1), never in a text, the digest or STATUS.

**pubid changes (in scope).** `Publisher.Release` currently calls `Sender.Publish` only when something is due (`publisher.go`, `if len(due) > 0`). It must call it on every counted day (a2), and select by slots (a3). Lower `MaxPayload` (a3). #319 (OSS-6e, the clock and outbox fields) is merged; build on main. The publisher's guarantees G1 to G4 (D-046, the OSS-6 clock row) must still hold: overflow only lengthens waits.

**Out of scope (OSS-6s-b and others).** The Tor SOCKS transport, the relay list, delivery acknowledgements (OSS-6p values), a fresh circuit per batch and key (OSS-6i, whose test lands in b), and the repository's pull, verify and append job (OSS-6j).

**Synthetic canaries only.** No credentials, tokens or personal data in code, tests or fixtures.

**Needs:** OSS-6 (merged)

**Gate:** lenses (security, privacy); tier A expected (effects)
