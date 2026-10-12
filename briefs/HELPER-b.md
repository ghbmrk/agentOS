# HELPER-b: Helper app for Windows: background service, Wake-on-LAN start without a login, GPU pause when a game starts

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier B (predicted; run tools/risk_tier.py).
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-11, HW-8
**Acceptance:** A1.
**Dependencies:** HELPER-a

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. HW-11 defines the helper app: cleared content only, a background service that starts after Wake-on-LAN without a login, uses the GPU only while the PC is idle, and pauses at once when a game starts.

## Scope and intended change

`helper/windows/` (new), packaging and signing steps, tests, ASSUMPTIONS.md. Predicted B (the app holds no private data and its output is untrusted); run `tools/risk_tier.py` before opening the PR and hand off if it prints A.

A Windows service plus installer that accepts the controller only (NET-seg mTLS), runs cleared work, pauses inference when a full-screen app or game starts, resumes when idle, and leaves the PC as it was apart from its install (HW-8). Output is untrusted: it never acts.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. A full-screen game start pauses inference within a frozen time (set in the brief's first commit, from a measured baseline).
2. After Wake-on-LAN with no login, the service starts and answers the controller.
3. The app refuses a private-labelled task even if the controller sends one.

Failure path: A game stutters, or the service never starts after wake.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 100k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
