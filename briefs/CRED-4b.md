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

**Acceptance tests:** `TestGateOmitsEntryValuesTheDriverDidNotReport`, `TestGateOmitsChildValuesAndCopies`, `TestGateKeepsTextTheAgentTyped`, `TestGateTypedTextIsNoOracle`, `TestGateShortValueKeepsPageAndRefs`, `TestGateTypedTextStaysOnTheNextPage` (`broker/browser/gate_test.go`), `TestEntryRefs` (`broker/browser/omit_test.go`), and every existing `OmitValues` test.
