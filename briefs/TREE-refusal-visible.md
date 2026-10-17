# TREE-refusal-visible: say what a refused managed tree kept

**Owner:** either peer. **Class:** later. **Implementation risk:** tier A (guest-bridge path; the issue said B).
**Board section:** Security and architecture review (2026-10-08); work item #1462 (UX U-1 of #1449).
**Requirements:** CAP-5, OWN-14
**Dependencies:** none.

## Goal

When the broker answers `managed_tree` with no version, the bridge refuses it and keeps its tree, but the console line reads `managed tree: broker answer: no tree version; nothing changed`, and "nothing changed" reads as "the tree did not change upstream". Reword it so the line says what was refused and what was kept.

## Scope

`broker/cmd/agentos-guest-bridge/tree.go`, `broker/cmd/agentos-guest-bridge/tree_test.go`, this brief. **Guard files:** none.

Out of scope: the STATUS line when the guest's version lags the adopted tree (agentosd wiring). That stays on #1462's follow-up, per the issue's 2026-10-17 triage scope.

## Acceptance tests

**Acceptance tests:** `broker/cmd/agentos-guest-bridge/tree_test.go::TestBridgeNoVersionRefusalSaysTheTreeWasKept`: a `managed_tree` answer with files and no version fails the sync with exactly `refused a managed_tree answer with no version; kept the current tree`. Catches: the old wording, or a refusal text that drops what was kept. The existing `TestBridgeKeepsItsTreeWhenTheBrokerDoesNotSendOne` "no version" case still pins that the tree and version held are unchanged.

ASSUMPTIONS.md: none added; TREE-fold-wipe-1 already states the refusal and does not quote its text.

## Handoff and estimate

Checkpoint: 30k tokens, an estimate rather than a ceiling.
