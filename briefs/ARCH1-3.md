# ARCH1-3: Qualify the composed production profile and one useful workflow

**Owner:** primary coordinator routes to existing owners; unclaimed advisory extension.
**Class:** release design/acceptance extension. **Requirements / gates:** ARC-1–7, DEP-1–4, ONB-1–3, CAP-3–6, OP-7, RES-1–4, UPD-1/8, REC-2, HW-5a; A1/A2/A4/A5/A7/A8/A9/A10/A14.
**Needs:** P2-1/c4, existing INT-A/H6/W7-A proposals, POT-P1/P2/P3a, actual adapter/output integration.
**Record:** [Holistic architecture review](../reviews/combined/2026-10-08-holistic-architecture.md), source `3c9f9e711be3d394537cb9e6aedc5b4ee394e2c0`.

## Basis and scope

Current canary targets cover guest-socket/vault/egress and drive-at-rest; the former manually composes a synthetic label/provider rig. Offline daemon tests substitute an unlocked owner and omit model-egress. Separate Linux guest tests are valuable but not a full configured product proof. Main has pending mailbox/native-output/local-inference integration. These known seams must remain explicit when qualifying a composed OS.

## Acceptance

1. Extend existing integration/acceptance documents with a claim-to-evidence ledger per production profile: process identities/sandboxing, actual constructors/configuration, credential mode, input/output authority, qualified versions, failure behavior and exact test artifacts.
2. Keep unit/synthetic evidence distinct from production-equivalent Linux service composition and physical/owner qualification. An omitted optional capability is visibly unavailable; independent owner control and recovery remain available.
3. Implement the existing INT-A/POT-P1 vertical slice with actual service identities, qualified guest/worker, one source and usable native output destination. A worker file or SMS assertion is not the delivered artifact. No new integration framework.
4. Exercise read/transform/draft then bounded approved send, owner-side version edits, STOP, unavailable models, restart, revoked authority, lost remote acknowledgment and delayed reply. Preserve task/artifact/receipt identity and truthful unknown states.
5. After acceptance/correction, compare first and repeated work against matched baseline tasks. Include declines, failures, recovery effort, cost, quality and approval burden; freeze targets before qualification. Automatic-learning eligibility is distinct from useful task completion.
6. Run relevant canaries through the exact constructed profile, including credential modes and output surfaces actually enabled. Keep the existing per-package tests; no clean result may silently stand for components absent from its fixture. Hardware/real-account work is recorded pending until actually performed.
7. Under existing A2/A7/A8 owners, test update/fallback/restore against revoked grants, spent budgets, deletions and known effects; include stale-clock and TPM-policy transitions. Saturate guest memory/processes/I/O/disk and verify foreground control/journal reserves. State offline freshness/revocation limits and keep floor-hardware qualification distinct.

## Delivery, potency and safety

Release acceptance extension, not a duplicate runtime package or a demand to complete all hardware in this documentation PR. Existing INT-A/H6/A1 owners retain execution. Minimize authority-bearing trusted code and unsafe configurations without blanket process splitting or restricting guest reasoning. No claimed productivity gain until measured.

Claim/split in the owning lane before implementation. Proposed checkpoint: 20k tokens for the first bounded slice, not a ceiling; hardware studies and runtime refactors are separate packages. Intake does not close this work or change the specification.
