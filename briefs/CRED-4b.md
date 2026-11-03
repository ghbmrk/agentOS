# CRED-4b: Credentialed browser executor in the broker

Board section: Backlog refill (2026-10-05).

Credentialed browser executor in the broker (plan P2 item 6; CRED-4, CRED-6): S5's action protocol as a broker executor in its own sandbox, sessions held by the vault process, verbs on the fixed list, canary sessions for A5; fixture sites first, the 5 live sites when S5's network policy allows

**Needs:** S5 fixture suite

**Gate:** lenses (security: executor)

**State on the board before the 2026-10-08 index split:** queued, unblocked (fixtures); lane claude2

**Part 1 (PR #300):** the broker gate (`broker/browser`: closed v0 protocol, declared origins, CRED-10 output filter outside the driver) on `pkg/claude2-CRED-4b-browser-gate`.

**Part 2:** the driver in its own broker-owned sandbox, vault-held and A5 canary sessions, CRED-6 intents, and a CI job running the real driver ([assumptions](../broker/browser/ASSUMPTIONS.md) K1-K14). Part 2 cannot close until a trusted source outside the driver derives the password-ref set and the gate calls `OmitValues` on every snapshot (K14, CRED-4).

## CRED-4b-r1 (#1111): the gate derives the password refs

**Requirements:** CRED-4. **Class:** release. **Finding:** #211 combined lens point 4 (K14): a page that mislabels a password field, or a driver that reports no password refs, gets its value through.

**Scope:** `broker/browser/gate.go`, `broker/browser/omit.go`, `broker/browser/gate_test.go`, `broker/browser/omit_test.go`, `broker/browser/ASSUMPTIONS.md`, this brief.

**Change:** the gate derives the password refs from the snapshot (every entry field showing a value the agent did not type into it on that page) and calls `OmitValues` on every snapshot before the CRED-10 filter; `password_fields` becomes the gate's count ([assumptions](../broker/browser/ASSUMPTIONS.md) G10, K14).

**Acceptance tests:** `TestGateOmitsEntryValuesTheDriverDidNotReport`, `TestGateOmitsChildValuesAndCopies`, `TestGateKeepsTextTheAgentTyped`, `TestGateTypedTextIsNoOracle`, `TestGateShortValueKeepsPageAndRefs`, `TestGateTypedTextFollowsTheTypeReply`, `TestGateTypedGuessIsNoOracleThroughCopies`, `TestGateTypedFieldShowsAGuessEitherWay`, `TestGateOmitsValuesOfFieldsWithoutRefs`, `TestGateTypedNonEntryKeepsNothing` (`broker/browser/gate_test.go`), `TestEntryRefs` (`broker/browser/omit_test.go`), and every existing `OmitValues` test.

## CRED-4b-r2 (#2245): password-field follow-ups

**Requirements:** CRED-4. **Class:** release. **Finding:** #2245 (#2246 reviews 6239557715, 6239610403, comments 6239722241, 6239829840): a page can echo a typed guess beside an equal password value, borrow the typed field's ref through a `[ref=…]` token in a value, give a password input `role="spinbutton"`, show a value in a screenshot's pixels, or refill a field with the text the agent once typed.

**Scope:** `broker/browser/gate.go`, `broker/browser/omit.go`, `broker/browser/gate_test.go`, `broker/browser/omit_test.go`, `broker/browser/ASSUMPTIONS.md`, this brief.

**Change:** a line's ref is taken only from its attribute run; `spinbutton` is an entry role; a rich-text child (paragraph, generic) is structure, not a value; a value of a field also showing on any line outside the field and its ancestors withholds the whole snapshot (the verb's outcome stays), and inside its ancestors it is scrubbed at any length; text the agent put on pages (typed, or a navigate URL's query values and fragment) is treated the same whether or not it matches, withheld when 4 or more characters of a whole text show outside an omitted field's ancestors and scrubbed inside them, and past 1024 remembered texts or typed refs every page with an omitted field is withheld (PR #2273 reviews); a typed record is forgotten once a snapshot shows that field with other text or empty; a screenshot is not taken, or is discarded, when the page shows a field value the agent did not type ([assumptions](../broker/browser/ASSUMPTIONS.md) G8, G10, K14).

**Acceptance tests:** `TestGateOmitsSpinbuttonValue`, `TestGateScreenshotWithheldForUntypedFieldValue`, `TestGateForgetsStaleTypedText`, `TestGateEchoOutsideFieldWithholdsSnapshot`, `TestGateRefInValueCannotBorrowTypedRef`, `TestGateGuessEchoIsNoOracle`, `TestGateGuessEchoAfterOverflowIsNoOracle`, `TestGateOmitsChildValuesAndCopies` (`broker/browser/gate_test.go`), `TestCRED4PasswordValueScrubbedFromOtherNames`, `TestCRED4RefOnlyInAttributePosition`, `TestCRED4RichTextChildrenAreNotValues`, `TestCRED4ShortValueScrubbedFromAncestors`, `TestEntryRefsStaleTyped`, `TestEntryRefs` (`broker/browser/omit_test.go`), and every existing gate and `OmitValues` test.

## CRED-4b-r3 (#4406): refs from an earlier page or snapshot

**Requirements:** CRED-4. **Class:** release. **Finding:** #4406 (Mark's approval of the stale-reference recommendation, Questions 8): the gate keeps the refs of a page the driver has left, and a screenshot's own snapshot can leave the gate's refs and the driver's apart.

**Scope:** `broker/browser/gate.go`, `broker/browser/gate_test.go`, `broker/browser/statelink_test.go`, `broker/browser/fixture_test.go`, `broker/browser/ASSUMPTIONS.md`, this brief.

**Change:** a reply without a snapshot from another URL, or naming none, and every screenshot reply leave the gate no refs until the next snapshot, and every verb on a ref the gate does not hold is refused with `unknown_ref`; the test driver stays on its page like the real one ([assumptions](../broker/browser/ASSUMPTIONS.md) K16).

**Acceptance tests:** `TestRefFromAnEarlierPageIsRefused`, `TestTypeOnARefTheGateNoLongerHoldsIsRefused`, `TestRefsAfterAScreenshotAreTheDriversLast` (`broker/browser/statelink_test.go`), `TestFixtureRefsFollowTheDriversDocument` (`broker/browser/fixture_test.go`, real driver), and every existing gate test.
