# HELPER-c: Helper app for macOS: same service and pause rules on a Mac

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier B (predicted; run tools/risk_tier.py).
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-11, HW-7, HW-8
**Acceptance:** A1.
**Dependencies:** HELPER-b

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. HW-7 says a Mac runs the helper app (not a boot target or a virtual machine). HELPER-b covers Windows only.

## Scope and intended change

`helper/macos/` (new), packaging and notarization steps, tests, ASSUMPTIONS.md.

Port the service to macOS: a launch daemon that accepts the controller only, cleared work only, pause on full-screen or game start, resume when idle, Wake-on-LAN where the Mac supports it. State what macOS cannot do (a Mac asleep on battery) in the page wording.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. A full-screen app start pauses inference within the frozen time.
2. The daemon refuses a private-labelled task.
3. The install leaves the Mac as it was apart from the app (HW-8 disclosed list).

Failure path: Inference runs on a busy Mac, or the daemon accepts a non-controller peer.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 80k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
