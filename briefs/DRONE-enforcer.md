# DRONE-enforcer: the enforcer side of the drone

Board section: Devices, hardware and image (SPEC §13-14). Work item #3517. D-190, SPEC NET-2 (Drones, Safety devices), NET-4, NET-6, A18. Tier A, strongest model. Blocked: see Dependencies.

## The gap

DRONE-sim (#3516) proves the flight guarantees with a stand-in key-holder and a test owner key. On the enforcer, the owner's own passkey must sign the policy and each flight, at home only, and the enforcer's channel must carry only return to dock. Without this row the drone either flies from a test key or not at all.

- **Failure path:** the core, a planner output or someone away from home starts a flight, widens a limit or adds a route; a core-proposed zone becomes a flight the owner did not see; or a lying core suppresses a return.

## Threat and properties

The attacker is a rooted core (it holds the channel and every camera's video) and anyone off the Owner network. Properties, each tested:

- **E1. Flights start only from a home-only owner signature (NET-6).** A flight record is created only on the enforcer's own page, served only to the Owner network and the wired admin port, from a passkey assertion with user verification over the rendered flight (route or zone, animal kinds, expiry). No key covers a drone's start.
- **E2. Widening is a loosening (NET-4).** Adding a route or zone, widening the boundary or ceiling, removing a no-fly zone, lowering the low-battery threshold, lengthening the lost-link timeout or updating flight firmware goes through the enforcer's loosening flow: true diff on the enforcer's screen, assertion, 10-minute wait, cancelable. Narrowing a limit is not on the closed tightening list and so also counts as a loosening, unless SPEC adds it.
- **E3. The core proposes, the owner disposes.** The core's camera tracks may propose a zone (as data on a proposal link); the enforcer renders the zone itself on its own page, from its own map of the signed boundary, and the flight is signed over what the enforcer rendered. A proposed zone outside the boundary or inside a no-fly zone is refused before it is shown.
- **E4. The channel's one drone command is return to dock.** The enforcer's channel parser maps exactly one drone message to the signed return; every other drone message on the channel is refused and logged.
- **E5. The core cannot hold back a return.** The aircraft's own failsafes (DRONE-sim P3) need no core. The GPS/camera check (if kept, #3516 question 3) can only trigger a return.

## Decisions

1. **Reuse `broker/drone` unchanged where possible.** The enforcer image runs `agentos-drone` as its own service under its own user; the key file is readable only by it. This row adds only the enforcer-side adapters: the flight-tap page, the loosening hook and the channel mapping. Changes to `broker/drone` itself are limited to replacing the test owner key with the enforcer's passkey verifier interface.
2. **The page and loosening flow are the enforcer rows'.** This row calls the enforcer's existing page, passkey and loosening machinery (NET-4, NET-6) and adds only the drone's screens and diff rendering. It builds none of that machinery.
3. **Acceptance runs SITL as the aircraft.** The A18 drone clauses run against the enforcer image in a VM, with SITL on a host the enforcer reaches as it would reach the drone. A live run needs the enforcer hardware; the firmware clause (DRONE-sim decision 11) runs on the aircraft hardware.

## Scope

`broker/drone/` (adapter interface only), the enforcer image's drone service unit and page templates in whatever directory the enforcer rows create, the enforcer's channel parser (drone message only), tests beside each, `ASSUMPTIONS.md` of each touched package. Paths follow briefs/ENF.md's code layout: the page templates under `broker/enforcer/page/`, the channel mapping in `broker/enforcer/channel/`, the service in `image/enforcer/`.

**Requirement IDs:** NET-2 (Drones; Safety devices: the drone's return-to-dock exception), NET-4, NET-6, A18 (Channel and Approvals clauses as they apply to the drone).

**Guard files:** none new beyond the enforcer rows' own (`broker/drone` is classed by DRONE-sim). A systemd unit is tier A and a gate path; the PR needs the separate Security accept.

## Acceptance tests

1. NET-6: `flight-tap`: a flight assertion from the Owner network flies; the same request from Household, Guests, Devices, either agentOS box's segment or with no user verification is refused, and a replayed assertion is refused. Catches a flight started off the Owner network.
2. NET-4: `drone-loosening`: adding a route applies only after its assertion plus 10 minutes, is cancelable in that window, shows the true diff when the core sends a false one, and an older policy version is refused. Catches a silent widening.
3. E3: `zone-proposal`: a core-proposed zone inside the boundary renders on the enforcer's page from the enforcer's own map and, once signed, flies; a zone outside the boundary or in a no-fly zone is refused before display; the signed record names the rendered zone, not the proposal bytes. Catches a core steering the flight through its proposal. (Waits on #3516 question 2.)
4. A18, E4: `channel-drone`: on the channel, return to dock is relayed and lands; a waypoint, a mode, a parameter, a firmware or a raw MAVLink frame is refused and logged. Catches channel widening.
5. A18: DRONE-sim tests 1, 7, 8 and 9 rerun with the enforcer image as the key-holder. Catches a regression in the move.
6. A18, firmware: on the aircraft hardware, an unsigned firmware image is refused by the bootloader and the flight controller keeps the old one. Catches the one clause SITL cannot run.

## Usage

One session, about 130k, strongest model, once the dependencies exist. If the enforcer rows land as several packages, split this row along the same lines before starting.

## Dependencies

DRONE-sim parts a and b merged. The enforcer rows in briefs/ENF.md: at least ENF-b #3659 (page and passkey), ENF-d #3660 (channel), ENF-l #3670 (daemon) and ENF-m #3671 (image); the drone's adapters live beside them under `broker/enforcer/`. Live tests need the enforcer hardware and the aircraft.
