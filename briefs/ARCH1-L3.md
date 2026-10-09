# ARCH1-L3: Cross-service delegation and qualified device control

**Owner:** primary coordinator; unclaimed later proposal. **Class:** later; L1 decision before promotion.
**Basis:** [cross-silo architecture review](../reviews/combined/2026-10-08-cross-silo-architecture.md). Existing OP-1–7, CAP-2/4, CRED-11 and ADP-9 are foundations, not claims that the broader contract is already required or implemented.

## Proposed boundary

First choose a concrete owner task and, for actuation, one qualified device/operation. A workflow may use broad authorized context while its effects remain within deterministic owner-chosen bounds. Aggregate constraints across accounts/devices are optional stronger delegation semantics; existing permitted sequences do not acquire a new approval requirement. Natural-language purpose and model confidence cannot enforce these bounds.

Separate task dependency/recovery integration, already in ARCH1-2/3 and POT-P2/P3, from new aggregate policy and physical control. Reuse existing grants, reservations, intent IDs, event bus and receipts. No universal transaction system, new permission store, or ambient LAN authority.

## Promotion and acceptance proposal

1. L1 defines the chosen aggregate limits, identity, expiry, source-writer trust and necessary observed preconditions. The same task/account/action vocabulary drives owner wording and deterministic evaluation. Broker-generated references are not bearer grants.
2. Positive cross-source runs finish with existing standing authority and fewer or equal owner interventions. A task handles partial completion, keeps useful artifacts and permits unrelated tasks to progress.
3. Where an aggregate limit is adopted, splitting across accounts/workers/request IDs cannot evade it. Unknown outcomes block dependent commitments and do not create false completion. Source fields written by an agent cannot become fresh owner authority via another connector.
4. Device qualification names command acceptance versus observed state, bounds, stale/offline behavior, supported cancellation/compensation and local safety interlocks. An inverse command is not evidence that elapsed physical consequences reverse. High-risk device classes need separate qualification.
5. Exercise identity replacement, stale telemetry, lost acknowledgments, event echo, STOP/revocation and network partitions in a simulator before separately authorized real-device trials. Bound feedback without suppressing legitimate observed progress; never claim remote STOP is instantaneous while partitioned.
6. State the accepted trust/failure limits and measure useful cross-device benefit before broadening the profile. A new fixed verb or default policy requires the normal L1 SPEC path.

This intake performs no runtime implementation, device enrollment or action. Security review and relevant tier-A/lens gates remain required for any implementation.
