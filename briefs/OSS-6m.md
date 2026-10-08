# OSS-6m: Measure the daily publication batch constant

Board section: Backlog refill (2026-10-05). Optional; does not block OSS-6s-a (Mark, #325 Q2).

Measure the real per-day output (count and signed size of hints, OSS-8 attestations and clean-room artifacts) on the test box or from synthetic runs. Report the backlog it implies under the constant 16 slots × 64 KiB. Mark's ruling expects a backlog to clear in a day or two, inside the 7-day stable-release soak (UPD-5). Propose a new constant, shipped by update, only if the measured backlog would pass the soak or slots go mostly unused. Also measure the realized drain under overload. Because `MaxPayload` fills an empty batch, the guaranteed drain is only 1 slot a day (OSS-6s-a a3 Test 2, q = C − m + 1 = 1). If the worst-case or measured wait would pass the soak, consider a `MaxPayload` below a full batch, which raises q (#325 L3). No personal data in the measurement. Requirement IDs: OSS-6.

**Needs:** OSS-6s-a

**Gate:** L3
