# DEV-net-c: Wire the egress process to the address guard

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A (egress).
**Board section:** Local devices (D-069).
**Requirements:** DEV-2, REV-5, ARC-6
**Acceptance:** A14.
**Dependencies:** DEV-net-a merged.

## Finding

Found in PR #1049's L3. DEV-net-a builds `broker/netguard` and hooks the egress proxy library, but the process does not use it.

- R1: `broker/cmd/agentos-egress/main.go` builds the proxy with no `Guard`, and nothing calls `Learn`, `Watch` or `ExternalAddr`, so the box never learns the home network: only the static special-purpose ranges apply (the uplink prefix, gateway and router external address are never refused).
- R2: `net.DefaultResolver` dials the resolv.conf servers with an unhooked dialer, and no dial carries `PurposeDNS`, so DEV-2's "names resolve only through the broker" is not met.

## Scope and intended change

`broker/cmd/agentos-egress/`, `broker/netguard/` (learning sources only), tests, and ASSUMPTIONS.md.

- Build one `netguard.Policy` in the egress process and pass it as `Config.Guard`.
- Wire learning sources: netlink for prefixes and gateway, DHCP and RA for the resolver, NAT-PMP for the external address; call `Watch` so changes replace the learned set.
- Resolve names through a `Resolver` whose dials carry `PurposeDNS` and reach only the learned resolver, so the system resolver is not used.
- Pin entry (backup target, hosted route) from owner settings, empty by default.

Do not edit SPEC.md. If the cited contract cannot decide a design choice, raise an L1 spec-diff proposal before implementation.

## Acceptance tests

1. The process refuses an address inside the learned uplink prefix, the gateway and the external address (stub sources).
2. A name resolves only through the learned resolver; a dial to any other port-53 address is refused and journaled.
3. A changed learned network replaces the old set within one `Watch` interval.
4. `tools/netguardcheck.py` still passes.

Synthetic addresses only. Run affected Go packages and race tests on Linux, a fresh strongest-model L3 with an explicit threat check, and the tier-A lens screen.

## Handoff and estimate

Initial checkpoint: 60k tokens, an estimate rather than a ceiling; continue only while tests make progress (docs/OPERATING.md §5).
