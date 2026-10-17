# NETGUARD-hold-cancel-log: a held dial ended by its own context is not journalled as a refusal, and the hold refusal names the network's router

**Owner:** primary lane (dispatch S12, 2026-10-17).
**Priority:** later. **Class:** later. **Implementation risk:** tier A.
**Board section:** Security and architecture review (2026-10-08).
**Requirements:** DEV-2
**Issues:** #1540 (NETGUARD-hold-cancel-log), #1555 (NETGUARD-hold-wording).
**Acceptance tests:** `TestHeldDialEndedByCallerIsNotJournalled` and `TestHoldRefusalNamesTheNetworksRouter` in `broker/netguard/netguard_test.go`.

## Finding

From the #1537 UX review (R4) and the #1550 UX review. `Policy.Check` holds a dial on a never-seen gateway until the router's external address is learned, `externalHold` passes, or the dial's context ends. Both endings went through one deny path, so a caller's own cancellation or deadline was journalled as a netguard refusal (#1540). The refusal reason said "on this gateway", which reads as wrong when only the router behind an unchanged address is new (#1555).

## Scope and intended change

`broker/netguard/policy.go`, `broker/netguard/netguard_test.go`, this brief.

When the dial's context ends first, return an error that matches both `ErrDenied` (nothing is dialled, callers keep failing closed) and `ctx.Err()`, and do not call `OnDeny`. The hold-bound expiry still returns a plain `DeniedError` and is journalled. Both reasons say "this network's router".

`ASSUMPTIONS.md` N9 stays accurate and is not edited (open PR #2039 touches it). Do not edit SPEC.md.

## Acceptance tests

1. A held dial whose context is cancelled, or whose deadline passes, before `externalHold` returns an error matching `ErrDenied` and the context's error, with no deny-journal entry.
2. The hold-bound expiry returns `ErrDenied`, not a context error, and journals exactly one refusal.
3. Both refusal messages and the journal reason contain "this network's router" and not "on this gateway".

Failure path: a cancelled hold dials the destination, or an expired hold is not journalled.

Synthetic addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 40k tokens, an estimate rather than a ceiling.
