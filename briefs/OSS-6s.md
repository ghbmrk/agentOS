# OSS-6s: Publication sender

Board section: Backlog refill (2026-10-05).

Publication sender (OSS-6 P9, security W3 on #163): the `pubid.Sender` that publishes each day's batch, idempotent by day and batch hash (a clock more than 400 days back can form a second, different batch for a day already published; it must not be dropped as a duplicate, security N1 on #163), with network-level unlinkability as a requirement: an anonymity transport, or a fixed daily cadence padded to a constant batch size so batch size and empty days do not show

**Needs:** OSS-6

**Gate:** lenses (security, privacy)

**State on the board before the 2026-10-08 index split:** queued
