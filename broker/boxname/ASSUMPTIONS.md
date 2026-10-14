# boxname: assumptions

Built for CH-21b against SPEC CH-21 and CH-11. Each row is a reading of the
spec that a reviewer may want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| B1 | "Letters" is any Unicode letter (`unicode.IsLetter`), so "Zoë" passes; apostrophe is `'` or U+2019, since phones substitute the curly one. Digits, punctuation, tabs, newlines and format characters (U+202E) fail. | CH-21 "1 to 32 letters, spaces, hyphens and apostrophes" | Narrow to GSM-7 letters if CH-12 length budgets require it (LATER CH-21b l2) |
| B2 | Length counts characters (runes) after trimming and collapsing runs of spaces; the stored name is that normal form. | CH-21 "1 to 32" | Count bytes or GSM septets instead |
| B3 | A control word is refused only as the whole name, compared on letters ignoring case, so "S-t-o-p" fails and "Stop Watson" passes. The set is CH-11's words plus PAUSE, REVOKE, LOOP, LOOPS. | CH-21 "not a control word"; CH-11 | Refuse any name containing a control word |
| B4 | "AgentOS" and "assistant" are refused as substrings of the letters-only, lower-cased name, so "Agent OS" and "Assist-ant" fail. Look-alike letters are not folded (LATER CH-21b l1). | CH-21 | Fold confusables before comparing |
| B5 | "Not the owner's name" is equality on letters only, ignoring case and spacing, against the owner name the caller passes; with no owner name known the rule is skipped. A name that only contains the owner's name passes. | CH-21 | Refuse first-name or substring matches |
