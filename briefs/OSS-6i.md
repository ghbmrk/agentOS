# OSS-6i: Fresh Tor circuit per batch and signing key

Board section: Backlog refill (2026-10-05).

Release finding 3 of the L3 review on #330. With a shared Tor circuit, a relay can link batches signed under an old and a new key, which defeats rotation. An L1 clause in OSS-6 requires stream isolation: a fresh circuit per batch and never one circuit across signing keys. OSS-6s then carries a test that two batches, and two keys, never share a circuit (isolation credentials per batch). Requirement IDs: OSS-6.

**Needs:** #330 merged; test lands in OSS-6s

**Gate:** L1 spec diff (Mark); lenses (security, privacy) on the test
