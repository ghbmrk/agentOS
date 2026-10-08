# CRED-5f: CRED-5 fallback when no API key is granted

Board section: Phase 0: harness and risk spikes.

Source: L3 point 2 (release) on #328. CRED-5 says an unconfirmed broker-held route "falls back to its API key" (CAP-9), which assumes the owner granted one. Specify the case where none is granted, e.g.: "falls back to the provider's API key route if granted, otherwise CAP-9 routes the task to other granted routes, and the owner is told."

This is an L1 spec-diff (SPEC.md changes need Mark's approval), plus a test that routing with the plan route withdrawn and no API key goes to another granted route and notifies the owner.

**Requirements:** CRED-5, CAP-9

**Needs:** #328 merged
