# ROUTE-1: Broker label routing: private content to the controller and workstations only, helper apps cleared only

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** REV-6, REV-5
**Acceptance:** A14.
**Dependencies:** —

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. REV-6 as merged routes by content class: private is the default, mixing taints, and helper apps get cleared content only. The broker has no node classes yet.

## Scope and intended change

`broker/` routing and label code (`broker/modelroute/`, `broker/verb/` as needed), a node-class registry (controller, workstation, helper app), tests, ASSUMPTIONS.md.

Add the node classes and refuse at routing time: unlabelled or mixed content never goes to a helper app; private content goes to a workstation the box installed or the controller; cloud, frontier and owner-model-server routes keep CAP-9, CAP-11, CAP-13 and REV-5. Taint on mixing; the owner's shareable marks are journaled, revocable and pre-allowable.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. A private-labelled item sent to a helper-app node is refused.
2. A mixed item (private plus cleared) sent to a helper-app node is refused.
3. A cleared item is accepted, and an unlabelled item is treated as private.

Failure path: Private content reaches a cleared-only node.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 80k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
