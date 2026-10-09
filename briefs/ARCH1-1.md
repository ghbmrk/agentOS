# ARCH1-1: State and qualify the credential/data guarantee contract

**Owner:** primary coordinator routes to existing owners; unclaimed advisory extension.
**Class:** release design/acceptance extension. **Requirements / gates:** CRED-1/2/3/5/10, REV-5, OSS-1/2/6/7, CH-20; A5/A12/A14.
**Needs:** CRED-4b/S5, S8-W1/S8-live/CRED-5t, publication wiring, CH-20 delivery; L1 for normative claim/policy changes.
**Record:** [Holistic architecture review](../reviews/combined/2026-10-08-holistic-architecture.md), source `3c9f9e711be3d394537cb9e6aedc5b4ee394e2c0`.

## Basis and scope

Browser/protocol.go calls the driver untrusted while Gate relies on driver output. Credential-reading compromise is not contained by finite output scans. SPEC publication wording says content leakage is structurally zero, while hint H9/K1 explicitly defines a bounded, broker-derived hint channel. SMS summary filtering checks known secret shapes, not all private facts. CRED-2 defines an intentionally trusted base; CRED-5 has distinct custody modes. These are claim/qualification questions, not newly demonstrated production leaks.

## Acceptance

1. Produce a component/claim matrix: which process can read each reusable secret; who controls its output; trust assumptions; ordinary guest, broker-held provider and worker-held provider guarantees; qualification evidence and unresolved prerequisites.
2. Reconcile browser untrusted-input handling with the credential-reader threat model. Do not claim compromised-reader containment from regexes, screenshots, a VM or passed canaries. Prefer structural exclusion where feasible; explicit scoped exceptions remain under existing CRED-5/L1 authority.
3. Inventory intentional disclosures by source, recipient, producer and bound: model input, phone preview, research/link selection, publication hints. Distinguish no direct store access from no private-derived information. Preserve K1 broker derivation, fixed schemas and current limits; combined-observer analysis must not imply that a byte budget alone gives semantic permission.
4. Prepare any necessary L1 spec-diff for publication/trust wording; do not change defaults here. Sensitive SMS receipt-only policy requires a functioning alternate destination first and owner/L1 policy, with ordinary useful text retained where authorized.
5. State source deletion versus whole-task FORGET implementation limits. CAP-3 already requires affected adopted skills/procedures to be rebuilt from remaining evidence and requalified, removed only if they no longer qualify, with owner-visible impact before confirmation. Reuse P3-3b/current learning and FORGET owners; this is existing release work (correcting ARCH1-L2's former later classification). Stronger project/inference policy remains ARCH1-L1; do not promise retraction from external recipients or erasure of arbitrary historical influence.
6. Explain source, processor, effect destination and credential-custody roles independently for each enrolled resource. State which data leave the box on a compute host or output device, the observable audience, pinned identity versus integrity, and revocation/deletion limits. Treat data from authenticated accounts as untrusted content, preserving deliberate owner-authorized combination. Reuse CAP-12/13; generic new resource roles remain later.
7. Bind later activation evidence to actual credential mode/runtime/version, including tools, parent proc/memory, refresh, downloads, crash output and account switching. Each test names the adversary it actually models.

## Delivery, potency and safety

Design/qualification extension; first slice is documentation and a concrete L1 proposal, not runtime behavior. Preserve CRED-4b ownership; no new permission prompts. Runtime follow-ups require tier-A review and Security sign-off. No broader custody/data guarantee may be advertised until its stated qualification passes.

Claim/split in the owning lane before implementation. Proposed checkpoint: 20k tokens for the first bounded slice, not a ceiling; hardware studies and runtime refactors are separate packages. Intake does not close this work or change the specification.
