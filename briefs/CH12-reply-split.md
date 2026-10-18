# CH12-reply-split: send a long agent reply as up to three texts instead of cutting it

Board section: Owner-benefit review (2026-10-09). Work item #2160, from Mark's "Fix + redesign" choice in the human-native texting thread (2026-10-17). Built on CH15-converse (#2159), which also edits `evidence.go` (D-111): merge waits for #2159.

**Why.** A reply longer than one text is clipped and ends "Cut here. Ask me to send it in shorter parts." (`keptLong`). A person texting would send the rest. CH-12 (D-127): a longer agent reply is sent as consecutive texts, split at a paragraph, line or sentence boundary (a word boundary only when a sentence does not fit), at most three texts; the CH-19 check runs on the whole reply before it is split.

**Requirements:** CH-12, CH-19.

**Change.** `evidence.sendSplit` (outbox replies with no mail destination, or from a public machine) cuts the reply with `splitReply` into at most three texts, each within `control.MaxText` after `AgentPrefix`, and sends them in order. Past three, the third text ends with the existing `keptLong` note and the reply is kept whole, as today. A secret-shaped reply (`owner.SecretShaped` on the whole text) goes as one text, which the owner channel turns into its local-UI pointer, so a code split across texts cannot pass the per-text check. A text that does not go stops the rest and keeps the reply. No numbering: the spec does not ask for it.

**Acceptance tests:** CH-12: `broker/cmd/agentosd/split_test.go::TestLongReplyArrivesWhole`, `::TestTooLongReplyIsCutInTheThirdText`, `::TestSplitPrefersParagraphsThenLines`, `::TestSplitKeepsRunesAndEmoji`, `::TestFailedTextStopsTheRest`; CH-19: `::TestSecretIsCheckedBeforeTheSplit` (all new); `broker/cmd/agentosd/evidence_test.go::TestLongRepliesAreKept` (updated to a reply past three texts).

**Guard files:** none.

**Out of scope.** The third text's pointer to the rest on the local UI (CH-12, D-127): the local page does not show kept replies until CH-20p, so no text names it yet (UX U2, `noPage`), and `keptLong` stays. `control.Fit`'s GSM-7 rewrite of agent text (CH-12's UCS-2 rule) and the CH-19 check across the agent's earlier texts since the owner's last message: separate packages. The emailed-summary path is unchanged.

**Scope:** `broker/cmd/agentosd/evidence.go`, `broker/cmd/agentosd/evidence_test.go`, `broker/cmd/agentosd/split_test.go` (new), `broker/cmd/agentosd/ASSUMPTIONS.md`, `briefs/CH12-reply-split.md`.

**Usage estimate:** 60k tokens.
