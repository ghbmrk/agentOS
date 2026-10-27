# DRONE-sim: the drone flight stack in simulation first

Board section: Devices, hardware and image (SPEC §13-14). Work item #3516. D-190, SPEC NET-2 (Drones), NET-4, NET-6, A18 (Channel: the drone clauses), risk 43. Tier A, strongest model. Built in two sessions, part a then part b, each its own PR; the row stays `state:building` through both.

## The gap

D-190 adds a docked drone: a camera that flies, whose open flight firmware holds the enforcer's owner-signed limits, whose command link only the enforcer can sign, and which the core can neither fly nor reconfigure. Nothing on main flies, signs MAVLink or holds a flight policy, and no enforcer code exists yet. This row proves those guarantees against ArduPilot SITL before any aircraft is bought; DRONE-enforcer (#3517) later runs the same package on the enforcer image.

- **Failure path:** a process without the key (the core, a planner output, anyone on the network) arms the drone, adds a waypoint, widens a limit or loads firmware; or a breach, low battery or lost link leaves the drone flying.

## Threat and properties

The attacker is anything off the key-holder process: a rooted core, a guest's output, a device on the network, a replayed capture of a signed frame. State each check as the property it gives, and test the property, not a flag (security lens, recurring kinds):

- **P1. Nothing unsigned changes the aircraft.** No command, parameter write, mission, fence or rally upload, mode change, file write (MAVLink FTP, scripts) or firmware reaches effect on any MAVLink channel the aircraft exposes unless it carries a valid MAVLink 2 signature under the policy's key. A replayed signed frame is refused.
- **P2. Only one process holds the key.** The 32-byte signing secret exists in the key-holder process and the aircraft's own storage only: never in a log, an error, an environment variable, a command-line argument, a test golden file or a struct that is printed. (The flight controller verifies with the same symmetric secret; that is inherent to MAVLink 2 signing and is recorded in ASSUMPTIONS.)
- **P3. The limits are the aircraft's own.** Boundary, height ceiling, no-fly zones, return on breach, low battery and lost link are flight-controller parameters, fences and rally points, so they hold with the key-holder dead. The key-holder reads them back after every load and at every boot, compares them with the signed policy, and refuses to arm on any mismatch or unreadable value (fail closed: a missing, zero or out-of-range parameter is a mismatch).
- **P4. A flight is one signed record.** The key-holder starts a flight only from an owner-signed flight record naming one route of the signed policy, used once, before its expiry. No other input arms the aircraft or uploads a mission.
- **P5. The core has one command.** The only thing the core side can send is return to dock. A waypoint, a mode other than return, a parameter or a raw frame from the core side is refused and logged, and the aircraft's mission, mode and parameters are unchanged after it.

## Decisions

1. **One package, enforcer-only imports.** The key-holder and policy code is a new Go package `broker/drone` with a stand-in main `broker/cmd/agentos-drone`. It lives in the broker module only to reuse its vendoring, vulnerability check and import gate; it is enforcer code, so its ARC-2 rule is that it imports nothing from agentOS (no kernel, clerk, old-core or daemon package), only the standard library and the MAVLink library. DRONE-enforcer (#3517) builds the same package into the enforcer image.
2. **Reuse a mature MAVLink library.** Use `github.com/bluenviron/gomavlib` (MIT), vendored at a pinned version, for framing and MAVLink 2 signing. [Inference] It validates incoming and signs outgoing frames with a v2 key; the builder confirms this against the pinned version before writing code, and if it cannot sign, stops and says so in the PR rather than hand-rolling the signature. `acato/drone_hass` (Apache-2.0) is read as a reference for its signing and SITL setup only, never imported or copied.
3. **ArduPilot Copter SITL, pinned by commit.** The harness builds `arducopter` for the `sitl` board from the newest Copter stable tag at build time, pinned by commit hash in one file, and caches the binary by that hash. The build runs in a new nightly workflow, `.github/workflows/drone-sitl.yml`, and on a PR that touches `broker/drone/` or the pin; normal CI runs the package's unit tests without SITL. The SITL tests carry the `sitl` build tag; they never skip silently: without the binary under that tag they fail.
4. **Close every unsigned path, including channel 0.** [Inference, verify at the pinned commit] ArduPilot accepts unsigned frames on MAVLink channel 0 (its USB port, TCP 5760 in SITL) as a "secure channel", and accepts unsigned RADIO_STATUS on every channel. So after provisioning the key the harness configures channel 0 as not-MAVLink (in SITL and on the aircraft), and a test connects unsigned to every serial port SITL exposes and finds nothing changed. Scripting is off (`SCR_ENABLE` 0) and is part of the read-back set. There is no RC receiver: RC is an unsigned control path, so the parameter set has none, and the arming checks are set for flight without one. If channel 0 cannot be closed at the pinned commit, the builder stops and raises it on #3516: that is a SPEC conflict (NET-2: the controller refuses an unsigned command), not a residual to accept.
5. **The signed policy is a record, the parameters are derived.** The flight policy is a canonical JSON record (boundary polygon, ceiling, no-fly polygons, named routes, dock position, low-battery threshold, lost-link timeout, the GPS/camera disagreement bound, a version) signed with Ed25519 by an owner key. In this row the owner key is a test key in the test only; DRONE-enforcer replaces it with the NET-4 passkey flow. `broker/drone` derives the parameter set, the inclusion and exclusion fences and the dock rally point from the record by one pure function, and refuses at load a policy whose route leaves the boundary, enters a no-fly zone or exceeds the ceiling, or whose version is older than the loaded one. [Inference] Parameter names (`FENCE_ENABLE`, `FENCE_TYPE`, `FENCE_ACTION`, `FENCE_ALT_MAX`, `BATT_FS_LOW_ACT`, `BATT_LOW_VOLT`, `FS_GCS_ENABLE`, `FS_EKF_ACTION`, `SCR_ENABLE`) are checked against the pinned commit's parameter docs.
6. **A flight record, used once.** Fields: flight id, route name (or, if #3516's question 2 is answered yes, a zone), allowed animal kinds (may be empty), not-after time, signature. The key-holder keeps the set of used ids durably (a file it alone writes, replaced atomically) and refuses a used, expired, malformed or unsigned record, or one whose route the loaded policy does not name.
7. **The core-side channel is typed, not MAVLink.** The stand-in exposes one local socket for the core side that accepts exactly one message, `return_to_dock`, and answers every other input with a refusal it logs. On `return_to_dock` it sends the signed return command. A burst of messages is rate-limited.
8. **Return to dock is the aircraft's return.** Return is ArduPilot's RTL to the rally point at the dock; the test asserts landing within the policy's dock radius and disarm.
9. **Follow is bounded by the fence, not by the vision.** In this row the onboard vision is a test stand-in that feeds target positions on a non-MAVLink onboard serial path (#3516 question 1 settles the real path); a target that walks out of the boundary leads the aircraft to the fence, and the breach returns it.
10. **The GPS/camera check can only return.** The key-holder takes camera fixes from the core side (untrusted), compares each with the aircraft's reported position, and after N consecutive disagreements beyond the policy's bound sends return. A lying core can therefore only cause a return, the secure direction. This check waits on #3516 question 3; if the answer is to drop it, part b drops its test and says so.
11. **Firmware refusal is proved on hardware.** SITL has no bootloader, so the "unsigned firmware is refused" clause cannot run here. [Inference] ArduPilot's secure bootloader refuses an image not signed by a key it was built with (`Tools/scripts/signing/`). This row covers the in-flight paths that can load code (MAVLink FTP, scripts) and records the bootloader clause in ASSUMPTIONS as owed by DRONE-enforcer's hardware run (#3516 question 4).

## Parts

- **Part a (one session, about 130k): harness, key and refusals.** The pin and the SITL build, the workflow, `broker/drone` key handling, policy record, derivation, load, read-back and refuse-to-arm, the unsigned and replay refusals, channel 0 closed. Acceptance tests 1 to 6 below.
- **Part b (one session, about 130k): flights and returns.** Flight records, mission upload, arm and AUTO, the core-side channel, returns on breach, low battery and lost link, follow bounded by the fence, the GPS/camera check. Acceptance tests 7 to 12. Starts after part a merges.

## Scope

- `broker/drone/` (new, with its own `ASSUMPTIONS.md`), `broker/cmd/agentos-drone/` (new).
- `broker/drone/sitl/` holds the pin file and the harness helpers (starting SITL with a fixed home and instance number, port discovery, teardown).
- `broker/vendor/` and `broker/go.mod`, `broker/go.sum`: gomavlib and its dependencies only (part a).
- `.github/workflows/drone-sitl.yml` (new, part a).
- `NOTICE` (gomavlib's notice; ArduPilot is GPL-3.0 and is built and run in CI only, never shipped or linked, which the NOTICE line says).
- Guard files below. Not touched: anything else under `broker/`, `image/`, `SPEC.md`, the process docs.

**Requirement IDs:** NET-2 (Drones), NET-4 (adding a route or widening a limit is a loosening; here: the policy's version rule), NET-6 (a flight is a turn-on the owner signs; here: the flight record), A18 (Channel: "a drone refuses an unsigned command, setting or firmware and flies only from a signed link"; "a camera ... gets no command except a drone's return to dock").

**Guard files:** `tools/risk_tier.py` (`drone` in `TIER_A_BROKER`; `tests/test_risk_tier.py` pins it), `broker/daemon/arc2_test.go` (the import rule of decision 1), and a one-line `exempt-pr N` companion PR in `tools/g1_scope_g2.txt` under D-198 for each part, since the G2 freeze (D-128) does not list `broker/drone/`. All pre-approved here. `tools/risk_tier.py`, `tools/g1_scope_g2.txt` and the workflow are gate files: each PR and the companion need the separate Security accept (OPERATING §7).

## Acceptance tests

Part a (`broker/drone/`, SITL tests tagged `sitl`):

1. NET-2, A18: `refusal_sitl_test.go::TestUnsignedFramesChangeNothing`. Table over a command (arm, mode change, `MAV_CMD_DO_FENCE_ENABLE` off), a parameter write (`FENCE_ENABLE` 0), a mission, fence and rally upload, and a MAVLink FTP write, each sent unsigned and with a wrong key on every serial port SITL exposes; after each, the parameter set, fences, mission and mode read back (signed) unchanged and the aircraft is disarmed. Catches any open unsigned path, channel 0 and a wrong-key acceptance included.
2. NET-2: `::TestReplayedSignedFrameIsRefused`. A captured signed parameter write replayed after a later signed frame is refused. Catches a timestamp check that is off.
3. NET-2, P3: `policy_sitl_test.go::TestLoadedPolicyReadsBack`. A signed policy loads, its derived parameters, fences and rally point read back equal; then a value changed out of band (by the test, signed with the key) makes the key-holder refuse to arm and log the mismatch. Catches a key-holder that trusts its own upload.
4. NET-2, NET-4: `policy_test.go::TestPolicyLoadFailsClosed` (no SITL). Table: unsigned, wrong key, older version, a route crossing the boundary, a route inside a no-fly zone, a route above the ceiling, a missing or zero or negative threshold, malformed JSON; each refused with nothing derived. Catches a guard that fails open (security lens, recurring kinds).
5. P2: `key_test.go::TestKeyNeverLeaves`. A canary key loaded through every path (file, provisioning) never appears in logs, errors, `%v`/`%+v` of any exported type, or the process environment; the key file is refused unless mode 0600 and owned by the process user. Catches key spill.
6. NET-2: `refusal_sitl_test.go::TestScriptingAndRCAreOff`. `SCR_ENABLE` reads back 0 and no RC input changes the mode. Catches the Lua and RC side doors.

Part b:

7. NET-6: `flight_sitl_test.go::TestFlightOnlyFromOneSignedRecord`. A valid record flies its named route and returns; the same record again, an expired one, an unsigned one and one naming a route the policy lacks are refused and the aircraft stays disarmed. Catches replay of an owner turn-on.
8. NET-2, A18: `channel_sitl_test.go::TestCoreGetsOnlyReturnToDock`. Mid-flight, the core-side socket gets a waypoint, a mode change, a parameter and a raw MAVLink frame: each refused and logged, mission and mode unchanged; then `return_to_dock` is accepted and the aircraft lands within the dock radius. Catches core steering.
9. NET-2: `returns_sitl_test.go::TestBreachLowBatteryLostLinkReturn`. Three cases: the follow stand-in leads past the boundary (breach), the simulated battery falls below the threshold, the key-holder's heartbeat stops; each ends landed at the dock and disarmed, with the key-holder killed in the lost-link case. Catches a return that depends on the key-holder.
10. NET-2: `follow_sitl_test.go::TestFollowStaysInsideBoundary`. A target moving inside the boundary is followed off the route; the aircraft's track never leaves the boundary polygon by more than the fence margin. Catches follow bounded by vision alone.
11. Question 3: `gpscheck_sitl_test.go::TestGPSCameraDisagreementReturns`. A GPS glitch injected in SITL against steady camera fixes past the bound for N fixes returns the aircraft; a single outlier fix does not. Catches the check missing or tripping on noise.
12. P5: `channel_test.go::TestChannelRefusesAllButReturn` (no SITL). Fuzzed inputs to the core-side parser; only the exact `return_to_dock` message yields a command, and a burst past the rate pauses. Catches a parser that accepts near-misses.

## Usage

Two sessions, about 130k each, strongest model. The SITL build is minutes, not tokens: cache it. Checkpoint at 100k: continue if SITL tests are moving toward green.

## Dependencies

None to start part a. The questions on #3516 (onboard vision path, zone flights, the GPS/camera check, firmware) shape part b and DRONE-enforcer; part a does not wait on them.
