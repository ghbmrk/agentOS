# DEL-2: Send outcomes for owner replies: retry what is known unsent, flag what is uncertain (DEL-sd b, provisional)

Board section: Owner-benefit review (2026-10-09). Finding from the 2026-10-09 owner-benefit review (point 2). Mark's choice, 2026-10-09: **an SMS whose delivery is uncertain is flagged to the owner, not resent automatically.**

**Tier:** A (`broker/cmd`, `broker/owner`, `broker/modemlink`). Strongest model. About 70k tokens.

**Needs:** DEL-1 (the outbox whose entries this package resolves).

## Today

- **SMS.** `evidence.send` (`cmd/agentosd/evidence.go:211-215`) calls `e.notify`, which is `owner.Channel.Notify` (`owner/channel.go:899`), which calls `Modem.Send`. A failure is only logged: no retry, nothing kept. `modemlink.Link.Send` maps every non-Accepted receipt, Unknown included, to `modem.ErrDown` (l.231-232, 262-266). The three-way `SendReceipt` (`ReceiptAccepted`, `ReceiptNotSent` "provably never given to the modem", `ReceiptUnknown` "the text may have gone") exists at `modemlink.go:274`. Its only user is the digest transport (`cmd/agentosd/digest.go:738`).
- **Email.** `deliverOnce` (l.249) creates a new intent ID, `"evidence/" + randHex(8)`, on every attempt, and `deliver` retries 3 times (`deliverRetries`, l.126). The journal's effect fingerprint (`journal/intent.go:284`) ignores the ID. So a retry while attempt 1 is `OutcomeUnknown` or `InFlight` is held (`*HeldError`, `engine.go:296-315`), and it ends up kept with the reply marked failing. This is the right outcome by accident. A retry after a known outcome is not deduplicated: if a later attempt runs after an earlier one actually Succeeded (for example after a crash and DEL-1's replay), a second email goes out.
- **Kept replies.** `keptReplies` (l.531-583) holds 20 entries for 7 days. `list()` has no production reader (CH-20p is not built), so a kept reply is invisible to the owner today.

## Requirements (local IDs; DEL-sd b when the spec diff merges)

- **DEL-2a, the SMS outcome is three-way.** The owner channel gains a send that returns the receipt (use `SendReceipt`; do not widen `modem.Modem` if an adapter suffices). The evidence path maps the result:
  - Accepted: done.
  - NotSent: retried with bounded backoff across restarts (the entry stays in the outbox), for up to 24h. After that it is kept, and a short text later says it could not be sent.
  - Unknown: **not resent.** The entry is marked uncertain, the full text is kept, and the next SMS that does go out carries the line "An earlier reply may not have arrived; reply SHOW to see it" (exact words through the owner-wording check). It is flagged once.
- **DEL-2b, a stable email intent.** The intent ID is derived from the outbox entry (machine plus message ID plus attempt group), not random, so a replay after a crash finds the earlier intent. If the earlier intent Succeeded, it is not resent. If it is `OutcomeUnknown`, it is flagged as in DEL-2a and not resent. If it was Denied or NotSent, it may be retried.
- **DEL-2c, the owner can see what was kept.** One owner command (SHOW, or the existing nearest verb if there is one; check `owner/` before adding) returns the newest kept or uncertain reply, clipped to one SMS with a count of the others. This is a stopgap until CH-20p; record it as provisional in ASSUMPTIONS.
- **DEL-2d, every outcome is recorded.** Every outbox entry ends as sent, kept (with a reason), or uncertain, and the log line names which. `evidence.send` no longer only logs.

## Tests (written first)

- Fake modem receipts: NotSent then Accepted gives one delivery. Unknown gives no resend, one flag line on the next SMS and the text kept. Accepted gives nothing more.
- A NotSent entry survives a restart and is retried. After 24h it is kept with the "could not be sent" text.
- Email: a replay after a crash with the earlier intent Succeeded sends nothing; with it `OutcomeUnknown`, the reply is flagged and not resent (journal fake or real journal in a temp dir).
- SHOW returns the newest kept reply with the count, and does nothing when there are none.
- No real numbers or addresses in fixtures; use synthetic canaries.

## Scope

`broker/cmd/agentosd/evidence.go`, `evidence_test.go`, `main.go` (wiring), `broker/owner/channel.go` and its tests (receipt-returning send and the SHOW verb), `broker/modemlink/` only if an adapter is needed, `broker/cmd/agentosd/ASSUMPTIONS.md`.

## Not in scope

The local page for kept replies (CH-20p). Digest delivery, which already uses receipts (W5-Dc).
