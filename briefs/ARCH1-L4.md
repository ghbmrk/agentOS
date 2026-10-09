# ARCH1-L4: Bounded jobs on heterogeneous owner hardware

**Owner:** primary coordinator; unclaimed later proposal. **Class:** later; L1 decision before promotion.
**Basis:** [cross-silo architecture review](../reviews/combined/2026-10-08-cross-silo-architecture.md). CAP-13 currently specifies inference-host routes/passes; it does not authorize a general remote CPU/GPU/storage or worker fabric.

## Proposed boundary

Choose one bounded job kind such as compiling or rendering approved artifacts. Reuse CAP-12 resource discovery, POT-P2 task/artifact identity, admission/budgets and owner control. Device source, processing and actuation permissions remain independent. Do not use broad privileged SSH as the abstraction or build a generic cluster before a useful job justifies it. Existing CAP-13/POT-P8 inference integration proceeds without this extension.

## Promotion and acceptance proposal

1. L1 states the job/runtime, qualified endpoint and threat model, data/residency/retention expectations and which remote isolation controls are actually enforceable. Pinned identity is not attestation of host integrity. A host receiving plaintext may retain it; stronger guarantees require separate evidence.
2. Bind task, input digests, output provenance, runtime/job version, resource limits, deadline and attempt. Hold admission for actual execution, not discovery. Results remain untrusted and cannot grant effects or certify their own correctness.
3. Positive runs combine useful private inputs, eligible hardware and separately authorized output. Compare floor-only and extra-host variants; include transfer, warmup, verification, failures, owner maintenance and disruption to the host's own foreground work.
4. Wrong identity/model, a public-only host, host loss or exhausted resources never route private data to an ineligible fallback. Keep policy through all passes/retries and label inherited outputs.
5. Exercise queued/running/completed/cancel-requested/cancel-confirmed/lost/expired states, revoked authority, replaced hosts and late/out-of-order duplicate results. STOP blocks future dispatch and reports unresolved remote work; it cannot retract data or assert termination without evidence.
6. Promote only on measured accepted-task value at unchanged authority/data policy. Generic remote workers, specialized accelerators and distributed-model execution are separate capabilities, not inferred from an endpoint list.

This intake performs no runtime implementation or live-host use. Any implementation retains tier-A security and lens gates plus explicit qualification of the new remote trust boundary.
