# OP2-erased-overclaim: an erased send is a repeat only of a send to the same recipients, and says so (OP-2, CH-10)

Board row: issue #1678. Source: #1433 delta 9 reviews (Security R26, P/UX/L3 U26). Class: release. Tier: A (`tools/risk_tier.py`). Builder: strongest model. Usage estimate: 70k tokens, checkpoint at 50k.

**Why (facts, verified at main f27aee0).** `recentRepeat` (`broker/grants/gate.go:1085`) sets `same := u.Erased`, so any send erased after it went (CAP-3 erasure runs on every owner source deletion, `broker/journal/erase.go:9-13`) matches every later send on its account and action for 24h, whatever its record and recipients. Each such send is asked and told "already sent <time>; send it again?", a false fact about a named record and recipient (OP-2's "the request says when it was already sent", CH-10's verified facts), and every ADP-9 pre-allowance and ADP-11 auto-reply on that account and action is suspended for the day. The journal keeps an erased intent's recipients (`erase.go:12`), so the recipients can still be compared.

## Requirements (from SPEC.md)

- **OP-2**: an identical repeat within 24h of a known success MUST NOT go out without the owner's explicit confirmation, and the request says when it was already sent.
- **CH-10**: the owner's line states only verified facts.

Package IDs:
- **OP2-ER-1** An erased send is a rival of a request only when its kept recipients equal the request's (case-folded, as `sendID` compares them). A send to other recipients, erased or not, is not a repeat: under a pre-allowance it goes unasked.
- **OP2-ER-2** When every known-success match is erased, the owner is told the send may repeat one whose record was erased, never "already sent": the text line ends `may repeat a send whose record was erased (it went 09:00 Oct 5); send it?`, the page notice reads `r3: your agent wants to send "invoice 2000". It may repeat a send whose record was erased (09:00 Oct 5). Approve or deny on my Wi-Fi page before ..., or reply NO r3.`, and the page's undo line reads `A send on this account went at 09:00 Oct 5 and its record was later erased, so this may repeat it. Approve only if it should go.` A match that is not erased keeps "already sent". The mark is not part of `ItemSum`, as `Sent` is not.

**Acceptance tests:**
- OP2-ER-1: `broker/grants/op2erased_test.go::TestAnErasedSendToOtherRecipientsIsNotARepeat` (the #1433 R26/U26 probes: fails if a pre-allowed send of another record to another person is asked after an erase) and `broker/grants/repeat_confirm_test.go::TestASendErasedAfterItWentStillCountsAsSent` (unchanged: the same recipients are still asked).
- OP2-ER-2: `broker/grants/op2erased_test.go::TestAnErasedOnlyRepeatIsMarkedErased`, `broker/owner/repeat_test.go::TestAnErasedOnlyRepeatSaysItMayRepeat`, `broker/localui/repeat_test.go::TestThePageSaysAnErasedOnlyRepeatMayRepeat`.

## Design

`recentRepeat` compares an erased rival's `fold(u.Intent.Recipients)` with the request's recipients and skips it if they differ; record and body cannot be compared, so a same-recipient erased send still counts on both sides (Security R23). `repeat` gains `erasedOnly`, true when every known success behind `sent` was erased; `verdict.marked` copies it to a new `owner.Item.SentErased`, and the three renderers (`owner.Channel.itemLine`, `owner.Channel.renderLocked`, `localui` approvals view) choose the erased wording when it is set.

## Scope

`broker/grants/gate.go`, `broker/grants/op2erased_test.go`, `broker/grants/ASSUMPTIONS.md` (GR35), `broker/owner/render.go`, `broker/owner/approvals.go`, `broker/owner/repeat_test.go`, `broker/localui/approvals.go`, `broker/localui/repeat_test.go`, `decisions/D-116.md`, `briefs/OP2-erased-overclaim.md`. **Guard files:** none.

## Out of scope

- An exact effect-fingerprint match against an erased send keeping "already sent" (the issue's optional refinement): it needs the journal to expose an erased use's EFP, and an EFP match implies the same recipients, so OP2-ER-1 already covers which sends are asked; only the wording would differ.
- `sentSince` (`broker/grants/retry.go:172`, the RETRY line's resubmission check) still takes any erased send as a match; it only adds a "may go twice" warning to an ask that is already shown.

## Done

CI green; OP2-ER-1 and OP2-ER-2 covered by tests carrying `REQ:` with their IDs.
