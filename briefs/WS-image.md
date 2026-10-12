# WS-image: Workstation image: the signed image installs on a dedicated machine and loads GPU drivers under Secure Boot

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-9, HW-11, HW-5
**Acceptance:** A1.
**Dependencies:** CTRL-uki, NET-seg

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. HW-9 and HW-11 allow a workstation that runs the same signed image on its own disk, installed from a stick with the owner's approval. NVIDIA drivers are not distribution-signed, so Secure Boot may refuse them.

## Scope and intended change

`image/` (workstation profile, installer, driver packaging and signing), `tools/hostcheck.py` workstation case, tests, ASSUMPTIONS.md.

A workstation profile of the image: a stick-run installer that wipes and installs after a phone approval (tier 4, CH-3), enrols the node with the controller, and loads GPU drivers under Secure Boot (signed modules with an enrolled key, or a vendor-signed path). Record the chosen route in ASSUMPTIONS.md.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. The signed image loads the GPU driver under Secure Boot and serves one model call from the controller.
2. The install does not start without the phone approval.
3. A workstation not installed by this box is not treated as one (ROUTE-1 node class).

Failure path: The driver does not load under Secure Boot; the fallback is the helper app, cleared content only (HELPER-b), and the workstation row is rescoped.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 100k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
