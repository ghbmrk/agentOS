# DRONE-dock: the drone dock controller

Board section: Devices, hardware and image (SPEC §13-14). Work item #3518. D-190, SPEC NET-2 (Drones: "its dock has no vendor cloud"), DEV-3. Tier A, strongest model. Later: waits on DRONE-enforcer; live tests need the dock hardware.

## The gap

The drone lands in a dock that opens its hatch, charges it by contact and carries a precision-landing beacon. A dock that opens on anyone's word exposes the aircraft and the camera; one that stays shut on a lost link crashes the return.

- **Failure path:** an unsigned or replayed command opens the hatch; a forged dock event tells the enforcer the drone is docked or charged when it is not; or the hatch stays shut for a returning drone because the link dropped.

## Threat and properties

The attacker is anything on the dock's network segment, a rooted core, and a replay of a captured command. Properties, each tested:

- **K1. The hatch moves only on a signed command.** The dock accepts open and close only as Ed25519-signed commands from the enforcer's dock key, each with a strictly increasing counter and a short validity window; anything else is refused and counted.
- **K2. Its events are verified (DEV-3).** The dock signs every state event (hatch, battery, charging, drone present) with its own device key, generated on the dock and pinned by the enforcer at pairing; an unsigned or mispinned event is refused and logged, and the dock is treated as off (KRN-7) until the owner re-pins it.
- **K3. It fails safe for landing.** If the enforcer reports the drone returning and the dock's link to the enforcer is then lost, or the link is lost for longer than the policy's lost-link timeout while a flight is open, the hatch opens and stays open until the link returns and a signed close arrives. The open-hatch state is reported once the link returns.
- **K4. No vendor cloud.** The dock makes no outbound connection but to the enforcer, and its firmware has no remote update path except signed images from the enforcer.

## Decisions

1. **Commodity parts.** A small microcontroller with a wired link (Ethernet or RS-485 to the enforcer, never Wi-Fi), a hobby-grade linear actuator or servo for the hatch with limit switches, contact charging pads and an IR beacon of the kind ArduPilot's precision landing supports. The builder names concrete parts in ASSUMPTIONS with their datasheet links; no custom boards or optics.
2. **One portable verifier.** The command and event code is one portable C module using Monocypher (the library ArduPilot's secure bootloader uses), compiled for the host in CI and for the microcontroller on hardware, so the logic CI tests is the logic that ships. The enforcer side is a small Go client in `broker/drone/dock*.go`.
3. **Counter survives power loss.** The last accepted counter is written to flash before the hatch moves; a command at or below it is refused after a reboot.

## Scope

`firmware/drone-dock/` (new: the C module, a host test runner, the microcontroller build, `ASSUMPTIONS.md`), `broker/drone/dock.go` and its tests, `NOTICE` (Monocypher's licence), and the guard file below.

**Requirement IDs:** NET-2 (Drones), DEV-3.

**Guard files:** `tools/risk_tier.py`: `firmware/` in `TIER_A_PREFIXES` (pre-approved; it is a gate file, so the PR needs the separate Security accept), and a D-198 `exempt-pr` companion in `tools/g1_scope_g2.txt` if the G2 freeze still holds.

## Acceptance tests

1. K1: `firmware/drone-dock/test_commands.c::unsigned_or_replayed_hatch_refused`. Table: unsigned, wrong key, stale counter, counter replayed after reboot, expired window, truncated, oversized; each leaves the hatch unmoved. Catches an open on anyone's word.
2. K2, DEV-3: `broker/drone/dock_test.go::TestDockEventsAreVerified`. An event signed by the pinned dock key is accepted; one unsigned, from another key or replayed is refused and logged and marks the dock off. Catches a forged "docked".
3. K3: `::TestLostLinkReturnLands`. With the enforcer's link cut during a return (simulated dock against DRONE-sim's SITL return), the hatch opens and the SITL landing completes at the dock. Catches a shut hatch on a lost link.
4. K4: `firmware/drone-dock/test_net.c::only_enforcer_destination`. The firmware's network config names one peer; any other destination is refused at build time by a static check. Catches a vendor cloud.

## Usage

One session, about 110k, strongest model, after DRONE-enforcer merges. Hardware runs are later and separate.

## Dependencies

DRONE-enforcer (#3517). Dock hardware (later).
