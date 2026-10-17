# CH12-ucs2: agent text keeps emoji and line breaks (UCS-2 when needed); Cc and bidi controls stripped

Work item: #2188. Board section: Human-native texting (spec #2157, D-127). Tier A (risk_tier.py: broker/owner, broker/control and broker/cmd are A), so the strongest model builds and L3 plus lens review apply. Row 7 of dispatch 2026-10-17-2000 said B; the code paths make it A.

**Goal.** `control.Fit` (broker/control/text.go) maps every non-GSM-7 character to `?` and drops `\n`, so "Done 👍\nSee you at 3" reaches the owner as "Done ?See you at 3". On main it still does (verified at 59eb45d). CH-12: agent text keeps its characters, sent as GSM-7 if every character fits, else UCS-2 (67 characters a segment); broker templates stay GSM-7.

**Requirement IDs:** CH-12.

**Change.**
1. An agent-text path beside `Fit` in `broker/control/text.go`: strip Cc other than LF and the bidi controls (U+202A-202E, U+2066-2069, U+200E/F, U+061C) first; choose GSM-7 if all characters fit, else UCS-2; cut to three segments in the chosen encoding. `Fit` itself is unchanged for broker texts.
2. `broker/owner/pacer.go` `agentText` uses the new path; the strip runs before `Disclose` and the CH-19 check, so a stripped text is what is checked. Joiners and emoji ZWJ sequences stay whole.
3. `broker/cmd/agentosd/evidence.go`: room counting in `sendSplit` and `splitReply` becomes encoding-aware (segment size 153/67 per text, `maxText` was bytes); a reply with an emoji splits at 3 x 67-char segments per text, never mid-surrogate or mid-ZWJ sequence. The CH-19/CH-21 checks keep running on the whole reply before the split.

**Acceptance tests** (all new, each fails on main): `broker/control/text_test.go::TestCH12AgentTextKeepsEmojiAndLF`, `TestCH12AgentTextEncodingChooser` (GSM-7 stays GSM-7; one emoji flips to UCS-2; segment limit 153 vs 67), `TestCH12StripsCcAndBidi` (U+202E, U+2066, U+0007, kept LF); `broker/owner/converse_test.go::TestCH12ConverseSendsEmojiWhole`; `broker/cmd/agentosd/evidence_test.go::TestCH12SplitCountsUCS2Room` (2.5-text emoji reply arrives whole, in order, none split inside a ZWJ sequence). Existing `TestCH12*` and `fit_test.go` stay green.

**Scope:** `broker/control/text.go`, `broker/control/text_test.go`, `broker/owner/pacer.go`, `broker/owner/converse_test.go`, `broker/cmd/agentosd/evidence.go`, `broker/cmd/agentosd/evidence_test.go`, `broker/cmd/agentosd/fit_test.go`, `broker/owner/ASSUMPTIONS.md`, this brief. Not main.go or setup.go (#2241, #2015 open).

**Dependencies:** after #2250 merges (W5-Dc-r15 edits `broker/owner/pacer.go`; D-111). Build first of the group: #2184 (split by encoding) is gated on it, and the three other packages edit `evidence.go`/`converse.go` (D-111: one at a time, order CH12-ucs2, CH15-chat-window, OWN4-ack). Check no open PR touches the scope when starting. G1 is off (D-128); the live G2 list already allows control, owner, agentosd and voice.

**Usage estimate:** medium (about 100k).
