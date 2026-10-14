# DEV-net-b: Home-network boundary on the remaining dialers and inbound

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A (egress).
**Board section:** Local devices (D-069).
**Requirements:** DEV-2, REV-5, ARC-6
**Acceptance:** A14.
**Dependencies:** DEV-net-a merged.

## Finding

DEV-net-a adds the address policy and wires the egress proxy. The other broker-side dialers still dial unchecked, and nothing drops connections the home network opens to the box (DEV-2 In).

## Scope and intended change

`broker/browser`, `broker/modelroute`, `broker/mail/imapsmtp`, `broker/smsapi`, `broker/sipsign`, `broker/bridgeclient`, the host firewall rule set, the DEV-net-a CI allowlist, tests, and ASSUMPTIONS.md.

- Set the `broker/netguard` hook on each dialer above (the browser executor's network path, the model router, and the adapters' declared hosts), and empty the CI allowlist DEV-net-a left for them.
- Inbound: a host firewall rule set (nftables, a mature component) that drops connections initiated from the uplink to any box port; CH-9's existing rules stay and established replies pass. Leave a per-device allow hook for a connected device's pinned address (DEV-2 In) and the passive-discovery listener ports (mDNS, SSDP, Matter) for DEV-1, both empty at release.

Do not edit SPEC.md. If the cited contract cannot decide a design choice, raise an L1 spec-diff proposal before implementation.

## Acceptance tests

1. Each wired dialer refuses a private address and a rebinding answer, using DEV-net-a's resolver stub.
2. A redirect to a private address from the browser executor is refused.
3. A LAN host opening a connection to any box port is dropped; CH-9's rules still hold.
4. The CI check passes with an empty allowlist.

Synthetic addresses only. Run affected Go packages and race tests on Linux, a fresh strongest-model L3 with an explicit threat check, and the tier-A lens screen.

## Handoff and estimate

Initial checkpoint: 60k tokens, an estimate rather than a ceiling; continue only while tests make progress (docs/OPERATING.md §5).
