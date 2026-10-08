# ARCH1-2: Qualify one effect contract from approval to remote receipt

**Owner:** primary coordinator routes to existing owners; unclaimed advisory extension.
**Class:** release design/acceptance extension. **Requirements / gates:** REV-2/3, OP-1–7, ADP-8/9/14, CRED-6; A4/A13.
**Needs:** Existing journal/grants/adapter owners; SR3-2/3/5/7; POT-P2/P3 result/task contracts.
**Record:** [Holistic architecture review](../reviews/combined/2026-10-08-holistic-architecture.md), source `3c9f9e711be3d394537cb9e6aedc5b4ee394e2c0`.

## Basis and scope

The generic journal Intent/Executor and grants.Verified interfaces delegate material-field binding to adapters. Mail rereads source/recipients and egress canonicalizes requests, which are useful patterns. Known mail M9 distinguishes conditional remote compensation from snapshot rollback. This item generalizes cross-route acceptance, not a claim that existing interfaces necessarily allow a bypass.

## Acceptance

1. Document an operation contract for one existing adapter: operation/schema version, account, resource/version, destination/recipients, payload binding, authority-relevant fields, permitted request sequence, attempt/reconciliation identity, receipt and qualified inverse.
2. Prove approval/pre-allowance, final authority/resource revalidation, serialization, accounting and outcome refer to the same bound effect. Dynamic auth/CSRF fields cannot change material fields. Do not let a route or task-ID change discard an unresolved attempt.
3. Use a synthetic service that records actual received effects. Change recipient, payload, amount, source version, method, encoding and operation after preparation; no mismatch reaches that service. Race STOP/revocation at the final boundary.
4. Inject crash/lost acknowledgment across durable transitions. Reconcile or preserve unknown/fenced state without unintended duplicate effects. Test concurrent owner edits during compensation; do not call an inverse fully undoable if service semantics cannot support that claim.
5. Apply the same conformance contract to a second qualified route before extracting shared types. Avoid a universal transaction rewrite, a second ledger or a false exactly-once remote guarantee.
6. Demonstrate one bounded standing rule across qualified routes with unchanged effects and fewer or equal routine prompts. Reuse structured receipts for POT-P3 rather than accepting agent prose as the execution oracle.

## Delivery, potency and safety

Release acceptance extension attached to A4/A13 and existing owners. Start with a small contract/test slice; runtime changes retain tier-A strongest L3/threat, Security and lens gates. External semantics remain qualified assumptions, not inferred from method/verb names.

Claim/split in the owning lane before implementation. Proposed checkpoint: 20k tokens for the first bounded slice, not a ceiling; hardware studies and runtime refactors are separate packages. Intake does not close this work or change the specification.
