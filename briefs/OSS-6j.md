# OSS-6j: Spec: what the repository's pull job is

Board section: Backlog refill (2026-10-05).

Release finding 2 of the L3 review on #330. OSS-6 says "no AgentOS-run service is involved" next to "a scheduled job in the public repository", which is project-operated automation. An L1 spec diff states, per OSS-11, that the job is repository automation that runs on any git host, is never a box dependency (DEP-2, DEP-3), and has no authority under OSS-9. Requirement IDs: OSS-6, OSS-9, OSS-11, DEP-2.

**Needs:** #330 merged

**Gate:** L1 spec diff (Mark), L3
