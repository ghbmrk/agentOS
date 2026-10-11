# OSS-6s-a-f: pubsend ledger read cap, and producer sizes against MaxPayload

Board section: Backlog refill (2026-10-05). Follow-up to OSS-6s-a (#411), from the LATER rows `OSS-6s-a f1` and `OSS-6s-a f2`. Started on 2026-10-09 at the coordinator's request, as an exception to D-048's hold on LATER rows before the first release; the PR does not merge until Mark confirms that exception.

**Scope:** `broker/pubsend/pubsend.go`, `broker/pubsend/pubsend_test.go` and `broker/pubsend/ASSUMPTIONS.md`; `broker/pubid/ASSUMPTIONS.md` (row P10 only); this brief; its BOARD row; the two LATER rows it finishes, and one LATER row for any finding it raises.

**Not in scope:** `OSS-6s-a f3` (waits on W6) and `OSS-6s-a f4`; anything in OSS-6s-b's scope (Tor transport, relay list, pull job); `broker/pubid/*.go`; the constants `MaxPayload`, `Slots`, `SlotSize`, `MaxWaiting`.

**Requirement IDs.** Tests carry `REQ: OSS-6`. Acceptance items are OSS-6s-a-f1 and f2; each test names its item.

- **f1 Bounded ledger read.** `pubsend.New` reads at most `maxLedgerBytes` = `MaxWaiting`×2×`FrameSize` (14 MiB) of the ledger before decoding or `validate`; a longer file is an error, never taken as empty and never read whole. The bound must hold the largest valid ledger: `MaxWaiting` waiting entries whose batch is `FrameSize` bytes (base64 in JSON, ×4/3) plus their seeds, and `maxConfirmed` confirmed keys.
  - Test 1: a ledger file of `maxLedgerBytes`+1 bytes, a valid empty ledger followed by zero bytes (a sparse file), is refused by `New`.
  - Test 2: the JSON of the largest valid ledger fits in `maxLedgerBytes`.
  - Test 3 (strict load, S3): bytes after the ledger's JSON value, other than whitespace, are refused. Without this, Test 1's file under the cap would load, since the decoder reads one value and stops.
- **f2 Producers fit `MaxPayload`.** P10 in `broker/pubid/ASSUMPTIONS.md` gains one line recording the planned producers' expected sizes against `MaxPayload` = 261,116 bytes, from their existing caps: an OSS-8 attestation is at most `update.MaxAttestationSize` = 16 KiB; a clean-room result (C13 K2) is up to `cleanroom.MaxResultBytes` = 8 MiB in files of up to `cleanroom.MaxFileBytes` = 1 MiB. Where a producer does not fit, the line states the condition on its publisher package. Documentation only; no test.

**ASSUMPTIONS.** pubsend S3 records the read cap and the strict load.

**Gate:** L3 review; tier from `tools/risk_tier.py`.

**Needs:** OSS-6s-a (merged)
