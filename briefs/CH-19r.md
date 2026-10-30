# CH-19r: a held code expires in owner-set hours; its pointer names kind and source, never the value

Board section: Owner channel and approvals (SPEC §10). Work item #906, D-089 and D-239, SPEC CH-19 as amended by #3931, scope update in issue comment 6506288006. Release.

**Why.** The owner channel keeps every withheld secret-shaped text for the owner page for the kept days (default 30). A one-time code is dead within minutes, so a month-long copy only gives a stolen disk live codes, and the generic pointer ("it may contain a code or key") tells an away owner nothing about whether it is worth going home for.

**Changes.**
1. **Split the classes** (`broker/owner/disclose.go`). `SecretShaped` becomes `TokenShaped` (known token formats) or `CodeShaped` (a 4-10 character code next to a code word, on every fold, as now). `AgentToken` and `AgentCode` read the three agent readings as `AgentSecret` does. `ExpireCodes(text)` returns the text with its codes replaced by `[expired]`: first the code-like tokens near a code word, then every code-like token, then the whole text, stopping at the first result that is not `AgentCode`; a text that is not `AgentCode` as stored (its code showed only before controls were stripped) expires whole. `CodeKind(text)` names the kind without the value: "a code of 6 digits" when every code found is N digits, otherwise "a code".
2. **Kind and pointer** (`broker/owner/keep.go`). A withheld text in which the patterns find a code, read as received, is kept as kind `KeptOneTime`, a key beside it included (the key keeps its days, the code expires); one with only a token stays `KeptSecret`. With no key, its pointer is fixed wording built from the kind and the source the channel knows: "I held back a code of 6 digits in a message from your agent. Read it on my Wi-Fi page." for agent text, "... in one of my notices ..." for the broker's own disclosed posts. It never carries the value or a display name. `withheld` recognises exactly these pointers, so agent text that imitates one still gets the agent prefix.
3. **Store** (`broker/cmd/agentosd/evidence.go`, `main.go`). A `KeptOneTime` item records `CodeUntil` = kept time + code hours. Once past it, reads show `ExpireCodes(text)` with `CodeExpired` set, and the sweep (now every minute) writes that over the stored text, so the live code leaves the disk; the item keeps its kept days. `-code-hours` (1 to 24, default 1) sets the hours; outside the bound agentosd refuses to start, as `-kept-days` does.
4. **Page** (`broker/localapi/held.go`, `broker/localui/held.go`). `HeldItem.CodeExpired`; the Held page names the one-time kind and says when its code has expired.

**Source.** No caller of the owner channel carries a verified source today: agent text comes from the planner, and the mail clerk has no share route to the channel (evidence.go header). So the pointer names the source the channel itself verifies (the agent, or the box's own notice). Naming a mail sender by canonical address needs a caller that hands the channel a clerk-verified sender; that is a follow-up once one exists, never planner-supplied text.

**Requirement IDs:** CH-19 (as amended by #3931, D-239).

**Acceptance tests:**
- CODEH-1 `broker/owner/codehours_test.go::TestCodeIsClassedApartFromTokens`: a code next to a code word is code-shaped and not token-shaped; a token format is token-shaped; `SecretShaped` is their union.
- CODEH-2 `::TestCodePointerNamesKindAndSourceNotValue`: Converse, Notify and Post of a code text keep it as `KeptOneTime` and send a pointer naming the digit count and the source, carrying no digit run of the code and no sender display name; a token text keeps the generic pointer; agent text that copies a pointer is never sent bare as one.
- CODEH-3 `::TestExpireCodesLeavesOtherTextReadable`: the code (plain, spaced, fullwidth) is replaced, the surrounding words stay, and the result is never `CodeShaped`.
- CODEH-4 `broker/cmd/agentosd/evidence_test.go::TestHeldCodeExpiresAtTheHour`: before the hour the code is shown; at the hour the page shows the item, its other text readable, the code expired, and once swept the code is not on disk; the item stays to its kept days.
- CODEH-5 `::TestCodeHoursBound`: 0 and 25 are refused, 1 and 24 accepted, default 1.
- CODEH-6 `broker/localui/held_test.go::TestHeldPageSaysCodeExpired`.
- CODEH-7 `broker/owner/codehours_test.go::TestEveryHeldCodeGetsHours` and `broker/cmd/agentosd/evidence_test.go::TestHeldCodeBesideAKeyExpires`: a code beside a key, and one found only before controls are stripped, are kept as `KeptOneTime` and expire at the hour; the key keeps its days.
- CODEH-8 `broker/owner/codehours_test.go::TestNoHeldCodeOutlivesItsHours` and `broker/cmd/agentosd/evidence_test.go::TestHeldCodeShowsItsExpiredView`: the owner channel hands the keeper the expired view (`Keeper.KeepCode`); a text whose strip changed it expires whole, so a code a control hid beside a visible one goes too.
- Updated, not new: `broker/owner/keep_test.go` (the secret case is a code, so its kind and pointer change).

**Scope:** `broker/owner/disclose.go`, `broker/owner/keep.go`, `broker/owner/codehours_test.go` (new), `broker/owner/keep_test.go`, `broker/owner/ASSUMPTIONS.md`, `broker/cmd/agentosd/evidence.go`, `broker/cmd/agentosd/evidence_test.go`, `broker/cmd/agentosd/main.go` (the flag only), `broker/localapi/held.go`, `broker/localui/held.go`, `broker/localui/held_test.go`. `broker/owner/pacer.go` only for `checkAgent`'s one withhold call, which passes the text as received (#2189 edits `agentText` there).

**Estimate:** about 120k tokens, one session.
