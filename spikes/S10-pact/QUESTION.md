# S10: personal-agent protocols (PACT, PAP)

**Question.** Can one AgentOS box act as its own personal-agent platform (a self-issued signing key, no registration with a platform registry, no JWKS hosted on a domain) and still be accepted by a conforming business host under PACT, and under the Meta/Sierra Personal Agent Protocol if its spec is published, without breaking SPEC §2 (no project-run server, no AgentOS account, no vendor activation, no public domain or certificate), DEP-2 or ID-2?

**Kill/pivot rule (brief S10).** If conformance needs a registered platform identity, a project-run issuer, or a domain the box publishes, the result is "not adoptable as specified" plus what the protocol would have to change, and the package stops after this spike: no spec diff, no prototype, no broker brief.

**Origin.** Owner request, 2026-10-08, in a coordinator session. Not release-critical (class `later`); started on that explicit request.

**Time box.** One session, cloud only, primary sources only, no accounts and no credentials.
