# DEV-net-e: Load the inbound rules, owner pin entry, SIP guard hardening

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A (firewall, egress, owner command).
**Board section:** Local devices (D-069).
**Requirements:** DEV-2, CAP-13, BAK-1
**Acceptance:** A14.
**Dependencies:** DEV-net-d merged.

## Finding

Found in PR #1052's L3 and lens review (release findings 2a, 2b, 2c). DEV-net-b stays not-done until 2a lands.

- 2a: nothing loads `agentos_inbound`, so no box drops a LAN connection (A14: a home-network host cannot open a connection to any box port).
- 2b: nothing writes `netpin:<label>` entries, so A14's pinned backup, hosted and compute clauses cannot pass. The gap fails closed.
- 2c: `sipline.Config.Guard` is optional and only TCP and TLS are replaced. Failure path: the P2-3c wiring calls `sipline.Open` without `Guard` and CI still passes, so signalling dials unguarded.

## Scope and intended change

`broker/netguard/`, `broker/cmd/agentos-egress/`, the owner command surface, `broker/modem/sipline/`, `tools/netguardcheck.py`, the image's firewall loader (with P2-1's `agentos_ap` loader), tests, ASSUMPTIONS.md.

- 2a: load `agentos_inbound` at boot before any listener; fail closed if the load fails; test it on the image. Also: (i) render a default drop for every interface except loopback, the access point and the agent-machine links (or derive the uplink list from every interface carrying a default route), so a USB tether, second NIC or renamed link is filtered; (ii) admit `nd-neighbor-solicit` and `nd-neighbor-advert` with `ip6 hoplimit 255` from any source, since RFC 4861 allows a global source.
- 2b: the tier-4 owner command that writes `netpin:<label>` entries, and its re-pin flow. Keep N12: never through `custody.put` from the local page. Owner wording lives in this row.
- 2c: `sipline.Open` refuses a nil `Guard` (tests pass a policy whose `Connect` reaches sipsim), or `netguardcheck` requires it at the call site; the UDP, WS and WSS transports get the guard or a refusing transport.

Do not edit SPEC.md.

## Acceptance tests

1. On the image, a home-network host cannot open a connection to any box port, including on an unlisted interface; the box still gets IPv6 from the router (2a).
2. A pinned backup endpoint and a pinned hosted endpoint are reachable; a compute host with a wrong key is refused (2b).
3. `sipline.Open` without a guard fails; no SIP transport dials outside the guard (2c).

Synthetic addresses only. Run affected Go packages with race tests on Linux, a fresh strongest-model L3 with an explicit threat check, and the tier-A lens screen.

## Handoff and estimate

Initial checkpoint: 80k tokens, an estimate rather than a ceiling. If 2a to 2c exceed one PR, split by letter.
