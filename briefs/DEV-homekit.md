# DEV-homekit: HomeKit (HAP) device clerk, first target the owner's T10 Pro thermostats

Board section: Devices, hardware and image (SPEC §13-14). Work item #3291; SPEC DEV-1, DEV-3, DEV-4, DEV-5, DEV-8, DEV-10, CLK-1, NET-2, A16; decision D-182 (Mark, card cmsg_01R63S2yrPkq32thy8WQCuvDDCxSzupzfgaKfFJHWNSbun, 2026-10-26 16:11:10Z). Tier A (a device credential, a hostile-traffic parser in the trusted base, risk 19).

## Why

Mark's four Honeywell T10 Pro thermostats are cloud-only today (Resideo). They speak HomeKit (Menu → Connect HomeKit; Installer Options → Reset → HomeKit, password = the date code under Thermostat Information). HomeKit pairing is local: once the box is the controller, the enforcer blocks Resideo and the thermostats keep their schedules on the device. D-182 made HomeKit (HAP) a device stack; this row builds it.

## Protocol, as the spec now words it

- **Connect (DEV-10):** the box pairs "HomeKit by its HomeKit code", typed on the local page at tier 4 (CH-3, CH-6). The code is the accessory's 8-digit code, never sent by text.
- **Identity (DEV-3):** the device is pinned by "a HomeKit accessory key": the accessory's Ed25519 long-term public key (AccessoryLTPK) received at pair-setup. Every session starts with pair-verify, which proves that key; a mismatch is refused and logged, the device goes off with a KRN-7 line, and only the owner re-pins it.
- **Custody (DEV-4, CLK-1):** the box's controller long-term key (iOSDeviceLTSK, Ed25519) is one of the "fabric, operational and HomeKit keys": sealed store, used only inside the clerk.
- **Operations (DEV-4):** wire shapes are service and characteristic (type UUID, `aid`/`iid` resolved at connection from `/accessories`). The class table maps the HomeKit Thermostat service (current and target temperature, current and target heating/cooling state, display units, heating/cooling thresholds): reads are `read`; a target temperature inside the owner's confirmed bounds is `actuate` with the prior value as inverse; a value outside the bounds, and any target state that turns heat off, is `actuate-physical` under DEV-5's floor rule. Unmapped services follow DEV-4's conservative default.
- **Canary (A16):** "a fabric or HomeKit key": the canary controller key never reaches a planner or guest.

HAP facts the code rests on (HAP non-commercial spec, R2+): pair-setup is SRP-6a (3072-bit group, SHA-512, user "Pair-Setup") over TLV8, then Ed25519 long-term key exchange under ChaCha20-Poly1305 with HKDF-SHA-512 keys; pair-verify is X25519 plus Ed25519 signatures; the session is HTTP/1.1 framed in ChaCha20-Poly1305 blocks of at most 1024 bytes. Discovery is passive mDNS `_hap._tcp` (DEV-2); the TXT `sf` flag says whether the accessory is unpaired.

## Design points settled here (flagged for the reviews)

1. **Reuse.** No maintained Go HAP *controller* is known [Inference; the builder confirms before writing one]: `aiohomekit` (Python) is the reference, `brutella/hap` (Go) is accessory-side only. The clerk is a small controller on the standard library (`crypto/ed25519`, `crypto/ecdh` X25519, `crypto/hkdf`, `crypto/sha512`) plus `golang.org/x/crypto/chacha20poly1305` (vendor it; `x/crypto` is already a dependency). SRP-6a with the RFC 5054 3072-bit group is the one hand-written primitive; test it against RFC 5054's test vectors (adapted to the 3072-bit group and SHA-512 by an independent implementation, e.g. aiohomekit's). `brutella/hap` serves as the synthetic accessory in tests only (check its licence; test-only import).
2. **Bounded parsing.** TLV8, HTTP framing and JSON from the accessory are hostile input (risk 19): fixed maximum sizes, no redirects, no chunked bodies beyond a cap, one fuzz target per parser.
3. **No multi-admin.** The box is the only admin. It never runs add-pairing for another controller and never lists pairings to a planner; `remove-pairing` is `delete-remote`, adding a controller is `reveal-or-create-secret` (DEV-4).
4. **Unknown brand.** HAP has no attested vendor ID, so under DEV-2 the device lists as "unknown brand"; the owner guide says so.
5. **Reach.** Only the pinned accessory's address and port; no internet; the enforcer drops the thermostats' Resideo traffic once each is paired (enforcer rules row, not this one).

## Split

- **(a)** Protocol package `broker/clerk/homekit/`: TLV8 codec, SRP-6a, pair-setup and pair-verify against an injected key holder, the encrypted session, `/accessories` and `/characteristics` read and write, the thermostat class table, fuzz targets. Synthetic accessory in tests.
- **(b)** Core-side clerk: controller key in the sealed store (STO-2, CLK-1), the tier-4 local-page connect step taking the HomeKit code, pinning, bounds confirmation, events onto the bus. Needs STO-2 and the device-clerk host.
- **(c)** Live: pair the four T10 Pros behind the enforcer and confirm they hold schedules with Resideo blocked. Needs the enforcer (Protectli V1410, not arrived).

## Acceptance tests

Part (a), in `broker/clerk/homekit/`:

- `TestSRPVectors`: SRP-6a matches the reference vectors named above.
- `TestPairSetupAndVerifyWithSyntheticAccessory`: pair-setup with the right code pins the accessory key; pair-verify succeeds on reconnect.
- `TestWrongAccessoryKeyIsRefused`: an accessory proving a different long-term key fails pair-verify, and nothing is read or written.
- `TestControllerKeyNeverLeaves`: the canary controller key appears in no log line, error, event or written frame (A16).
- `TestThermostatClasses`: in-bounds target temperature is `actuate` with its inverse; out-of-bounds and heat-off are `actuate-physical`; unmapped characteristics write as `actuate-physical`.
- `TestOnlyDeclaredWrites`: a write to an undeclared `aid`/`iid` is refused before the session is written.
- `FuzzTLV8`, `FuzzSessionFrame`: no panic, bounded buffers.

Failure path: the controller key leaks, a spoofed accessory gets commands, or the heat is turned off without the owner's code.

## Scope

`broker/clerk/homekit/` (its own `ASSUMPTIONS.md`), `broker/vendor/golang.org/x/crypto/chacha20poly1305` and its `modules.txt` line, `NOTICE`, this brief.

## Estimate

Part (a): one session, about 130k tokens, strongest model.
