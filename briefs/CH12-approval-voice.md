# CH12-approval-voice: page-approval notices as a first-person question

Issue: #2190 (SPEC-D127, #2157). Tier A (`tools/risk_tier.py`: broker/owner); the dispatch row said B. Build on the strongest model.

**Needs:** CH-12 (approval text reads as a first-person question, same verified fields and codes).

**Scope:** `broker/owner/approvals.go`, `broker/owner/localapprove_test.go`, `broker/owner/repeat_test.go`, `broker/owner/ASSUMPTIONS.md`, and one line in `broker/owner/reaction_test.go:314` (main's owner tests do not compile: `RequestEach` takes `[]time.Time` since #2205, and the batch subtest still passes `[]time.Duration`; fixed on this branch). Nothing else.

**Change:** `renderLocked`'s three "your agent wants to V \"O\"" notices (page-only requests: erased repeat, page-confirmation, recipient count) become "Can I V \"O\"?" with the same fields in the same order: `<ID>:` label, UNVERIFIED marker, verb, quoted object, recipient count, erased-send time, deadline, `reply NO <ID>`. The "already sent" and "again?" notices are already questions and stay.

**Out of scope:** low/high-tier `itemLine` texts (render.go), MORE pages, reply texts. Raise as a `release` finding if the reviewer wants them.

**Acceptance tests (REQ: CH-12):**
- `TestTheLocalNoticeNamesTheActionAndTheDeadline`: exact text, every verified field present.
- `TestAConfirmationTakesOneCodeOnThePage`: question form, verb, object, deadline, NO code, no YES, no recipient.
- `TestPageErasedRepeatNoticeIsAQuestion` (repeat_test.go): erased time kept, question form.
- `TestPageNoticesFitTheirSegmentBudget` (new): every page notice with maximal fields is GSM-7 and within `MaxSegments`, and no "your agent wants" remains.
