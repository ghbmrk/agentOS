# OSS-6s-b: Tor transport to Nostr relays, and the pull job

Board section: Backlog refill (2026-10-05). Split from OSS-6s on #325.

Part b of the publication sender. It implements OSS-6s-a's `Transport` over Tor, using Ubuntu `tor` through SOCKS, to third-party Nostr relays at onion addresses (D-062, SPEC OSS-6). There is no direct fallback: if Tor is unreachable, frames wait (OSS-6s-a a9). It also carries OSS-6i's test that two batches, or two signing keys, never share a circuit (isolation credentials per batch), and the repository's scheduled pull, verify and append job, once OSS-6j settles what that job is. Relay count, the delivery rule, the queue bound and the relay list source come from OSS-6p. Requirement IDs: OSS-6.

**Needs:** OSS-6s-a, OSS-6p, OSS-6i (clause), OSS-6j

**Gate:** lenses (security, privacy); tier A
