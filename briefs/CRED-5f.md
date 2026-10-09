# CRED-5f: CRED-5 fallback when no API key is granted

Board section: Phase 0: harness and risk spikes.

Source: L3 point 2 (release) on #328. CRED-5 says an unconfirmed broker-held route "falls back to its API key" (CAP-9), which assumes the owner granted one. Specify the case where none is granted, e.g.: "falls back to the provider's API key route if granted, otherwise CAP-9 routes the task to other granted routes, and the owner is told."

This is an L1 spec-diff (SPEC.md changes need Mark's approval), plus a test that routing with the plan route withdrawn and no API key goes to another granted route and notifies the owner.

**Requirements:** CRED-5, CAP-9

**Needs:** #328 merged

## Added scope: model line for STATUS (release, from #525)

Source: L3 R1, Security finding 2 and Potency point 2 on #525 (OP9-status-a). Today `agentos-egress` opens `model.sock` at serve start, whatever the grants and while the vault is locked, so STATUS (OP-9 capability C2) shows no Model line for a box with no grant, a locked vault or a stale socket. A11's "no model grant or route" cause is unmet until this lands; #525's ASSUMPTIONS S8 and S12 defer it here.

**Requirements:** OP-9, A11 (no-grant cause), CRED-5

**Intended change:** `modelroute` (which may dial the vault socket under ARC-2; agentosd still may not) exposes a state: granted or not, vault locked or not, reachable or not. The state carries no secret. C2 in the agentosd registry reads it.

**Acceptance:** with induced conditions, STATUS holds one owner-worded line with a fix clause for each of: no grant ("no AI plan or key is connected; ..."), a locked vault, and a stale socket (file present, nothing answering). Each line clears when the condition does. A11's no-grant cause gets a passing test. ARC-2 tests (`TestAgentosdLinksNoInference`, `TestARC2ControlPathCannotReachInference`) stay green.
