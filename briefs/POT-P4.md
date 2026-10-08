# POT-P4: Bound and progressively fetch scoped recall

**Owner:** primary, unclaimed. **Class:** later unless a measured A10 failure justifies promotion. **Tier:** A when guest/label/forget plumbing changes.
**Requirements if promoted:** CAP-3, REV-5, ARC-7.
**Needs:** workload evidence from POT-P1; reconcile existing result stand-ins [#196](https://github.com/ghbmrk/agentOS/pull/196) and lossless compaction [#199](https://github.com/ghbmrk/agentOS/pull/199).

The index already has full text, vectors and structured facts. This proposal extends `broker/recall/` and `broker/recalltool/`, not a new retrieval framework. Declare exact paths and a measured target in an implementation brief only after promotion.

Add narrowing account/time filters, bounded excerpts and a broker-held source-version handle for progressive fetch. Filters cannot widen caller access or avoid label raising. Excerpts carry provenance and untrusted-content marking. Missing/deleted/stale handles fail closed. No hidden model pass may read additional recall.

Acceptance: frozen workload measures recall quality, bytes and accepted-task latency; public-only queries show no private existence/timing/count signal; source mutation invalidates stale handles; FORGET revokes excerpts, handles and derivatives; narrowing filters cannot name another account's data. Include Unicode/large-document and budget-boundary cases. Tests first, appropriate risk reviews. Initial checkpoint after promotion: 20k tokens for one query/fetch slice.
