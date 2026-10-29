# CH12-approval-voice-b: every approval text as a first-person question

Issue: #2190 (SPEC v1.0 CH-12, D-127). Part a (`briefs/CH12-approval-voice.md`) turned the page-only notices into questions and left the texted low and high tier wording (CH12V-3) and the `<ID>:` label (CH12V-1) for this part. Tier A (`tools/risk_tier.py`: broker/owner). Strongest model. The kernel does not render approvals yet (triage comment on #2190, 2026-10-29), so the wording stays in `broker/owner`.

**Needs:** CH-12: an approval text, and each item of a batch, is fixed wording from verified fields (verb, object, recipient or amount, reversibility, expiry, valid replies) that reads as a first-person question in plain sentences; a leading `<ID>:` label is not required.

**Scope:** `broker/owner/approvals.go`, `broker/owner/render.go`, `broker/owner/ASSUMPTIONS.md`, the owner tests whose goldens change (`channel_test.go`, `localapprove_test.go`, `repeat_test.go`, `retry_test.go`, `review_test.go`), a new `broker/owner/voice_test.go`, and the wording-only test edits that follow in `broker/daemon/kernelretry_test.go`, `broker/daemon/retry_test.go`, `broker/grants/channel_test.go` and `broker/grants/resume_test.go` (no production change in daemon or grants).

**Change:** a lone item's text asks `Can I <verb> "<object>"[, <detail>,][ to <recipients>][ for <amount>][ again]?`, then its reversibility as a sentence, then any repeat, erased-send, retry or restart note, `Expires`, and the replies. A batch asks `Can I do these N things?` over its item lines. No approval text starts with `<ID>:`; the ID stays in the replies. Fields, caps, order and tier are unchanged.

**Out of scope:** MORE pages, batch item lines (`itemLine`), reply and STATUS texts.

**Acceptance tests:** REQ: CH-12.
- `TestApprovalTextIsAFirstPersonQuestionWithEveryField` (voice_test.go, new): at every field's cap, for every combination of reversibility, notice, UNVERIFIED and restart note, every verified field is present in order, there is no ID label, and the text fits three GSM-7 segments with the longest request ID and grid cell. A text that would not fit takes a short form that keeps every field, notice and restart note, and only then.
- `TestABatchIsOneQuestion` (voice_test.go, new): one question over the items, ID only in the replies.
- `TestApprovalTextIsFixedWordingFromVerifiedFields` (channel_test.go): exact golden, one segment.
