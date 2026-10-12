# HELPER-a: Adding a helper: tier-4 'add helper' action, enrolment and the plain-words page

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** ONB-10, HW-11, CH-3
**Acceptance:** A1.
**Dependencies:** ROUTE-1, NET-seg

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. ONB-10 gives about 3 touches to add a workstation or helper app: a link from the phone, an install, a phone approval, and for a gaming PC, Wake-on-LAN once in firmware.

## Scope and intended change

`broker/helpers/` (new), `broker/localui/` add-helper page and link, the owner command surface, the controller's Wake-on-LAN sender, tests, ASSUMPTIONS.md.

The controller side: the link the phone gives, the tier-4 approval, node enrolment with a short-lived key (NET-seg), the node-class label (ROUTE-1), Wake-on-LAN when work is queued and power-down when idle, and the page's plain wording ('Gaming PC: helps with cleared work only', 'Workstation: will see your private data'). Revocation.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. Adding a helper needs the phone approval; without it the node is not enrolled.
2. The page names what each node class will see, in the wording above.
3. A queued job wakes a powered-off helper by Wake-on-LAN and the node is released when idle.

Failure path: A helper is enrolled without an approval, or described as seeing less than it will.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 100k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
