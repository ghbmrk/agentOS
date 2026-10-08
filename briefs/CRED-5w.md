# CRED-5w: Owner pause and withdrawal notice for broker-held routes

Board section: Phase 0: harness and risk spikes.

Source: L3 point 4 (release) on #328. Withdrawal of an unconfirmed broker-held route happens only by release, so between a provider's prohibition and the next release the route keeps running against the owner's account.

- Let the owner pause (and withdraw consent for) a broker-held route themselves; the provider then uses its fallback (CAP-9).
- A release that withdraws a route tells affected owners why.
- Tie both to §17 risk 3's re-read of terms at each CLI qualification.

Spec wording goes through an L1 spec-diff.

**Requirements:** CRED-5, CAP-9

**Needs:** #328 merged
