# S10 spike: assumptions

What RESULT.md rests on. A change to any row reopens the decision.

| # | Assumption | Rests on | Revisit when |
|---|---|---|---|
| S10-1 | PACT 1.0 is `docs/spec.md` at openpactprotocol/openpactprotocol commit `838c6bd` (2026-10-06). The rendered site openpactprotocol.org was not reachable; the repository says it renders the same `docs/`. | RESULT §1 | A PACT version above 1.0, or a spec change to §3.1/§3.2 |
| S10-2 | SPEC §2's forbidden "public domain or certificate" covers an HTTPS origin the box must keep serving so that third parties can verify it, whoever's server hosts it. If Mark rules that a public-key file on the owner's existing third-party account is an Optional dependency, RESULT §4 option A opens. | RESULT §3, §4 | Mark rules on the question in RESULT §7 |
| S10-3 | The Meta/Sierra Personal Agent Protocol has no published spec as of 2026-10-08. This rests on secondary reports only, because sierra.ai was blocked by egress. | RESULT §5 | PAP v0.1 is published (reported as due later in October 2026) |
| S10-4 | No AgentOS feature depends on PACT, so stopping costs nothing now. The owner's path to a business stays the credentialed browser or an adapter (CRED-4, §10A). | RESULT §8 | Before any package plans to use PACT |
