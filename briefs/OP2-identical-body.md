# OP2-identical-body: a reworded repeat of a known success is asked (OP-2)

Board row: issue #1677. Source: #1433 delta 9 reviews (Security R25, P/UX/L3 L21). Class: release. Tier: A (`tools/risk_tier.py`). Builder: strongest model. Usage estimate: 60k tokens, checkpoint at 45k.

**Why (facts, verified at main eed5253).** SPEC OP-2 (SPEC.md:380, Mark's approved sentence) defines an identical repeat as "the same record to the same recipients by the same action", with no body. `recentRepeat` (`broker/grants/gate.go`) also requires the same body (`sameBody`) before it marks a request as already sent, so a reworded send of the same record to the same recipients within 24h of a known success goes out unasked under a pre-allowance (ADP-9) or an auto-reply rule (ADP-11). D-116 and GR35 state the code's reading, not the SPEC's.

## Requirements (from SPEC.md)

- **OP-2** (SPEC.md:380): an identical repeat within 24h of a known success MUST NOT go out without the owner's explicit confirmation, even under ADP-9 or ADP-11.

Package IDs:
- **OP2-IB-1** A request on the same account, action, verified record and recipients as a send known to have gone within 24h is asked, marked `Sent`, whatever its body, under an auto-reply rule (ADP-11) as on any ask. (A pre-allowance without a reply rule carries no body, ADP-9 `Rule.Params`, so there the body never differs.)
- **OP2-IB-2** A request on another record of the same thread (Security R21's widening, beyond the SPEC's "same record") is a repeat only with the same body, as on the may-have-gone side: a reply that says something new elsewhere in a thread is a new send.

**Acceptance tests:**
- OP2-IB-1: `broker/grants/op2body_test.go::TestARewordedSendOfTheSameRecordIsMarkedSent` (fails if a reworded send of the same record is asked without the already-sent mark) and `::TestARewordedAutoReplyToTheSameMessageIsAsked` (fails if a reworded auto-reply to the same message is queued unseen).
- OP2-IB-2: `broker/grants/repeat_confirm_test.go::TestTheSameBodyInReplyToAnotherMessageOfTheThreadIsARepeat` (unchanged: new text on another record of the thread stays a new send).

## Design

Drop the body condition from the known-success side of `recentRepeat`, so the `sent` mark uses the same match as the `tried` mark (same record whatever the body, or same thread with the same body). The thread choice keeps auto-replies usable in a live conversation: asking every reply anywhere in a thread for 24h would turn ADP-11 off for any thread with a recent reply, which the SPEC sentence does not ask.

## Scope

`broker/grants/gate.go`, `broker/grants/op2body_test.go`, `broker/grants/repeat_confirm_test.go`, `broker/grants/repeat_test.go`, `broker/grants/gate_test.go` and `broker/grants/outcome_test.go` (their auto-replies each answer their own message, since a second reply to the same message is now a repeat), `broker/grants/ASSUMPTIONS.md` (GR35), `decisions/D-116.md`, `briefs/OP2-identical-body.md`. **Guard files:** none.

## Out of scope

A SPEC change (the issue's alternative): not needed, since the code moves to Mark's wording.

## Done

CI green; OP2-IB-1 and OP2-IB-2 covered by tests carrying `REQ:` with their IDs.
