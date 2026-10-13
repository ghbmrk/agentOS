# CTRL-claim-ap: Pre-claim access point: the Wi-Fi a phone joins before the Owner Card exists

**Owner:** primary lane.
**Priority:** release (G1). **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-10, CH-7, HW-1
**Acceptance:** A1 (G1: the first M6 Ultra, D-104).
**Dependencies:** CTRL-claim-wire, CTRL-spike
**Source:** SELLER-prep-1 (#1099) release finding, issue #1160.

## Finding

The sticker QR opens `http://10.42.0.1/claim` on the box's own Wi-Fi, but `localui.APConfig` takes the network name and password from the Owner Card, which a preloaded box does not have before the claim (HW-1: the card is made only after the claim). No phone can reach the claim page.

## Options

- **Sticker password (built; recommended).** The seller seals a per-box setup network (name `agentOS-Setup-XXXX`, an 80-bit password in the claim code's format) beside the claim state and prints it on the sticker with a Wi-Fi QR. WPA3-SAE (CH-7) with the box's client isolation; nobody without the sticker joins. About two more touches (scan the Wi-Fi QR, join).
- **Open setup network.** An open network that serves only the claim and setup pages. No extra touches, but anyone in range reaches the claim page and can burn the shared lockout count (the reserve, claim K9, still lets the sticker holder in), and the setup traffic is unencrypted over the air.

Mark decides; the safer option is built meanwhile.

## Scope and intended change

`broker/claim/` (`SetupNet`, `SetupNetPath`), `broker/cmd/agentos-seller/` (seal it, print it), `broker/firstboot/` (`BoxConfig.SetupNet`, `FirstBoot.Network`, routing, burn), tests, ASSUMPTIONS.md, this brief. Not in scope: the access point loader (P2-1) that brings the radio up, applying a rotated card Wi-Fi password to the running access point (#1172), and SPEC.md (a spec-diff goes on the Findings line).

## Acceptance tests

1. `prep` seals exactly two new files, the claim state and the setup network, root 0600; the setup file parses; the sticker carries its name, password and Wi-Fi QR; the password is not the code and is not in the claim state. `prep` refuses an image that already holds a setup network (HW-10, CH-7).
2. firstboot serves the setup network before the claim and until the card confirm, then none, and burns the file; a confirmed box burns any setup file at start; a setup file without claim state routes to reinstall; a bad or unreadable setup file stops the start (HW-10, HW-1).

Failure path: the sticker QR opens a claim page no phone can reach, or the sticker's password still opens a network on a box that has an owner.

Synthetic canaries only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 100k tokens, an estimate rather than a ceiling.
