# RECALL-prov-owner: the owner renews a lineage that has read as much as it may

Board section: Phase 3: compounding.

**Requirement IDs:** CAP-3 (recall provenance and limits).

**Origin.** L3 review of #1050 (RECALL-prov-L1): `Reach.Renew` exists, but no owner-channel command calls it (W7), so a lineage at its read cap stays at it at release.

**Scope:** the owner channel's command handling, `broker/recalltool` glue for `ReadsFull` and `Renew`, tests, ASSUMPTIONS.md, this brief. Needs the owner channel (W7) wired.

**Acceptance.**
1. The owner asks which agents have read as much as they may; the answer is `Provenance.ReadsFull`, by agent name, never a guest-controlled string. Test: a listed lineage appears; an unlisted one does not.
2. `Reach.Renew` runs only on the authenticated owner's YES for that lineage. Failure path (test): a guest-plane request, an unauthenticated owner-channel request, and a NO each leave the lineage's reads and machines untouched.
3. The renewal and its cost (work since the first read is lost) are named in the question the owner answers, as in W10.

**Not in scope.** Aged storage for reads; changing `Renew` itself.

**Usage estimate:** 60k tokens (tier A).

**Built** (RECALL-prov-owner PR): owner command RENEW / RENEW n in `broker/cmd/agentosd/renew.go`; `Reach.Full`, `AskRenew` and the renew path of `Execute` in `broker/recalltool/renew.go`. Assumptions: recalltool RN1-RN3, agentosd RW1-RW2.
