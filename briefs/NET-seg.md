# NET-seg: Private workstation segment on port 2 and mutual TLS between the controller and every helper

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-12, HW-11
**Acceptance:** A14.
**Dependencies:** DEV-net-e, ROUTE-1

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. HW-12 gives port 2 (or USB4) to workstations only, with no internet except through the broker. HW-11 says a helper accepts only the controller over mTLS with short-lived keys from the vault.

## Scope and intended change

`broker/netguard/`, `broker/cmd/agentos-egress/`, `image/` network and firewall units, the vault's short-lived key issuer, tests, ASSUMPTIONS.md.

Render the port 2 segment (DHCP or static, no forward to port 1 except through the egress process), issue short-lived client and server certificates from the vault, and make helpers and the controller refuse peers without them. Extends DEV-net-e's inbound loader; do not duplicate it.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. A workstation on port 2 cannot reach the internet except through the broker.
2. A helper refuses a non-controller peer and an expired certificate.
3. Revoking a helper stops the controller from sending it work.

Failure path: Direct egress from the segment, or a foreign peer accepted.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 100k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
