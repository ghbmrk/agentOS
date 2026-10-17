# CH12-ucs2: send agent text in the encoding it needs, emoji and line breaks kept

Board section: Owner-benefit review (2026-10-09). Work item #2188, from Mark's direction that texting with the box feel as human as possible (D-127). Built on CH12-reply-split (#2160) and CH15-converse (#2159); shares `evidence.go` with #2184, #2191 and #2193 (D-111), which wait for this.

**Why.** `control.Fit` rewrites every non-GSM-7 character, line feed included, to `?`, so the agent's "Done 👍\nSee you at 3" arrives as "Done ?See you at 3". CH-12 (D-127): agent conversation text keeps its characters, emoji and line breaks included, and is sent in UCS-2 when it is not GSM-7; control characters other than LF and bidi controls are removed before the CH-19 and CH-21 checks; each agent text keeps the three-segment limit in its own encoding. Broker texts stay GSM-7.

**Requirements:** CH-12, CH-19.

**Change.** New `owner.CleanAgentText` drops Unicode Cc except LF and the bidi controls (U+202A–202E, U+2066–2069, U+200E, U+200F, U+061C); joiners and variation selectors stay. New `owner.Room(s, suffix)` is the largest rune-boundary prefix of `s` that fits three segments in its own encoding after `AgentPrefix` and before `suffix` (`modem.Segments`). `owner.agentText` (Converse, NotifyAs, NotifyNow) cleans, then discloses, then sends the prefixed text as written when it fits three segments; only a longer push falls back to `control.Fit`. `evidence.sendSplit` cleans before its whole-reply CH-19 check, and `splitReply` caps each part at `Room`, so a reply with emoji is cut for UCS-2's 201 units. The modem already sends UCS-2 PDUs when a text needs them.

**Acceptance tests:** CH-12: `broker/owner/agenttext_test.go::TestAgentTextKeepsEmojiAndLineBreaks`, `::TestAgentTextStripsControlsAndBidi`, `::TestRoomCountsTheEncoding`, `::TestLongPushStaysWithinOneText`; `broker/cmd/agentosd/ucs2_test.go::TestEmojiReplySplitsForUCS2`, `::TestTooLongEmojiReplyIsCut`, `::TestPlainReplyRoomIsUnchanged`; CH-19: `broker/owner/agenttext_test.go::TestBidiSplitCodeIsStillHidden`, `broker/cmd/agentosd/ucs2_test.go::TestControlsGoBeforeTheWholeReplyCheck` (all new). The existing `split_test.go` tests keep passing unchanged.

**Guard files:** none.

**Out of scope.** The CH-19 check joined to the agent's earlier texts since the owner's last message; grapheme-boundary cutting and its edge tests (#2184); pushes longer than three segments, which still fall back to `control.Fit` (GSM-7); held digests joined by `heldTexts`, which still go through `control.Fit`; the agent's own reactions (#2195).

**Scope:** `broker/owner/agenttext.go` (new), `broker/owner/agenttext_test.go` (new), `broker/owner/pacer.go` (`agentText` only), `broker/owner/channel_test.go` (`checkFormat` only), `broker/cmd/agentosd/evidence.go`, `broker/cmd/agentosd/ucs2_test.go` (new), `broker/cmd/agentosd/ASSUMPTIONS.md`, `briefs/CH12-ucs2.md`.

**Usage estimate:** 80k tokens.
