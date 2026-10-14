# DEV-net-d: Inbound rules, owner pins, event refresh, SIP dialer

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A (egress, firewall).
**Board section:** Local devices (D-069).
**Requirements:** DEV-2
**Acceptance:** A14.
**Dependencies:** DEV-net-b and DEV-net-c merged.

## Finding

Found in PR #1051's L3. That PR hooks the three allowlisted dialers and wires the egress process; four items remain. DEV-net-b stays not-done until R1 lands.

- R1: the inbound nftables rule set (DEV-net-b acceptance 3) does not exist.
- R2: `agentos-egress` calls `SetPins(nil)`; pins (backup target, hosted route, compute host) are never read from owner settings.
- R3: the home network is polled every 10 s, so for up to 10 s a new /64, gateway or external address is allowed. Failure path: a new prefix appears at t0 and a dial to an address inside it succeeds until the next poll.
- R4: `broker/modem/sipline` SIP signalling uses sipgo's own dialer (`vendor/.../sip/transport_tls.go:66`), outside the guard, and `tools/netguardcheck.py` passes it.

## Scope and intended change

`broker/cmd/agentos-egress/`, `broker/netguard/`, `broker/modem/sipline/`, the host firewall rules, `tools/netguardcheck.py`, tests, ASSUMPTIONS.md.

- R1: inbound rule set that admits only the agreed services from the home network and drops the rest, with a test that parses the rendered rules.
- R2: read pins from owner settings; empty by default.
- R3: trigger `Refresh` from netlink address and route events; keep the poll as a backstop.
- R4: give sipgo a guarded dialer (or wrap its transport) and make `netguardcheck` fail on a SIP client built without one.

Do not edit SPEC.md.

## Acceptance tests

1. The rendered inbound rules drop an unlisted source and port (R1).
2. A pin from owner settings reaches only its endpoint and key (R2).
3. A new prefix is refused within one event, not one poll (R3).
4. A SIP dial to a private address is refused and journaled; `netguardcheck` fails an unguarded SIP dialer (R4).

Synthetic addresses only. Run affected Go packages with race tests on Linux, a fresh strongest-model L3 with an explicit threat check, and the tier-A lens screen.

## Handoff and estimate

Initial checkpoint: 80k tokens, an estimate rather than a ceiling; continue only while tests make progress (docs/OPERATING.md §5).
