# DEV-net: Home-network boundary on every outbound path

Board section: Security and architecture review (2026-10-08).

Source: L1 spec diff for local devices (D-069). REV-5 left `public` machines' uncredentialed egress "open", which on a home network includes the router's admin page, printers, NAS shares, cameras, and any LAN service without authentication. DEV-2 closes it for every component. Nothing serves ARC-6 (d) yet (`broker/guest/plane.go`, ASSUMPTIONS G6), so the hole is latent; this package must land before anything serves (d) or adds a dialer.

- One small address policy (e.g. `broker/netguard`) that every outbound dialer uses as its `net.Dialer.Control` hook, so the check runs on the address actually connected, after resolution, and again on each redirect and CONNECT.
- Deny: non-global addresses per the IANA IPv4 and IPv6 special-purpose registries (Go's `netip` predicates cover only part; table-test each registry entry), IPv4-mapped and NAT64-embedded (64:ff9b::/96) forms, the uplink's and the access point's prefixes (global IPv6 widened to the enclosing /56), the learned gateway, and the router's external address where NAT-PMP, PCP, or UPnP reports it. Learned prefixes refresh on address and route changes.
- Allow lists exactly two exceptions, each bound to a pinned endpoint: a compute host's declared endpoint through the egress proxy (CAP-13), and a device executor's own devices (DEV-1; none exist yet, so only the hook).
- Wire it into every broker-side dialer outside `vendor/`: the egress proxy (`broker/egress/proxy.go`, which today dials unchecked), the browser executor's network path (`broker/browser`), the model router (`broker/modelroute`), and the adapters' declared hosts (`broker/mail/imapsmtp`, `broker/smsapi`, `broker/sipsign`, `broker/bridgeclient`). Add a CI check that fails on a new dialer outside `vendor/` that doesn't set the hook. Any later package serving ARC-6 (d) uses the same hook.
- Inbound: a host firewall rule set (nftables, a mature component) that drops connections initiated from the uplink to any box port; CH-9's existing rules stay.
- Tests: a resolver stub that answers a public address and then a private one (rebinding); every registry range; a v4-mapped and a NAT64-embedded private address; a global IPv6 address inside the uplink /56; a redirect to a private address; the two allowed exceptions; a LAN host opening a connection to the box. Synthetic addresses only.

Tier A (egress).

**Requirements:** DEV-2, REV-5, ARC-6, CAP-2, CAP-13

**Needs:** P1-3 merged, the L1 spec diff for D-069 merged
