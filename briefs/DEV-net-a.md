# DEV-net-a: Home-network address policy and egress proxy

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A (egress).
**Board section:** Local devices (D-069).
**Requirements:** DEV-2, REV-5, ARC-6, CAP-2, CAP-13
**Acceptance:** A14.
**Dependencies:** P1-3 merged; the L1 spec diff for D-069 (PR #403) merged.

## Finding

REV-5 left `public` machines' uncredentialed egress "open", which on a home network includes the router's admin page, printers, NAS shares, cameras, and any LAN service without authentication. DEV-2 closes it for every component. Nothing serves ARC-6 (d) yet (`broker/guest/plane.go`, ASSUMPTIONS G6), so the hole is latent; this package and DEV-net-b must land before anything serves (d) or adds a dialer.

## Scope and intended change

`broker/netguard/` (new), `broker/egress/`, a CI check under `tools/` and its workflow step, tests, and ASSUMPTIONS.md.

- One small address policy (`broker/netguard`) that every outbound dialer uses as its `net.Dialer.Control` hook, so the check runs on the address actually connected, after resolution, and again on each redirect and CONNECT.
- Deny: non-global addresses per the IANA IPv4 and IPv6 special-purpose registries (Go's `netip` predicates cover only part; table-test each registry entry), IPv4-mapped and NAT64-embedded (64:ff9b::/96) forms, the uplink's and the access point's prefixes (global IPv6 widened to the enclosing /56), the learned gateway, and the router's external address where NAT-PMP or PCP reports it. Learned prefixes refresh on address and route changes.
- Allow exactly four exceptions (DEV-2), each matched as stated: the broker's resolver to the currently assigned resolver (DHCP or RDNSS; learned, not pinned, so a rogue DHCP or RA can move it), UDP/TCP 53 and DNS messages only, every answer still checked at connect time; a compute host's declared endpoint through the egress proxy (CAP-13), on its pinned key; and, as hooks only, a device executor's own devices (DEV-1; none exist yet) and an owner-pinned backup target or private hosted route (BAK-1, CAP-9), matched on the pinned address or name *and* its TLS or key pin, so a rebound name fails at the handshake. An agent reaches a pinned hosted route only as a routed model call to its declared inference operations. The host's own DHCP and router/neighbour discovery, and the broker's single NAT-PMP or PCP external-address query to the learned gateway, are not connections under the rule; nothing uses UPnP or SSDP M-SEARCH.
- Wire it into the egress proxy (`broker/egress/proxy.go`, which today dials unchecked).
- Add a CI check that fails on a dialer outside `vendor/` that doesn't set the hook, with an explicit allowlist of the dialers DEV-net-b wires, which that package empties.

Do not edit SPEC.md. If the cited contract cannot decide a design choice, raise an L1 spec-diff proposal before implementation.

## Acceptance tests

1. A resolver stub that answers a public address and then a private one (rebinding) is refused on the second answer.
2. Every registry range, a v4-mapped and a NAT64-embedded private address, and a global IPv6 address inside the uplink /56 are refused.
3. A redirect or CONNECT to a private address through the egress proxy is refused.
4. The four allowed exceptions pass only as matched above; an agent machine reaches neither the assigned resolver nor a pinned backup endpoint, and reaches a pinned hosted endpoint only through a routed model call. A rogue resolver (assigned by a stub DHCP/RA) that answers a private address is refused at connect time.
5. The CI check fails on a new unhooked dialer.

Synthetic addresses only. Run affected Go packages and race tests on Linux, a fresh strongest-model L3 with an explicit threat check, and the tier-A lens screen.

## Handoff and estimate

Initial checkpoint: 60k tokens, an estimate rather than a ceiling; continue only while tests make progress (docs/OPERATING.md §5).
