# DEV-withings-ble: read-only Withings Body Smart reader

Board section: Devices, hardware and image (SPEC §13-14). Work item #3272; SPEC DEV-1, DEV-3, DEV-4, DEV-8, DEV-12, NET-2, CLK-1, STO-2. Tier A (a credential, a radio and untrusted radio input). Authority: Mark, 2026-10-26T19:16:21Z (cmsg_01R63S2yrPkq32thy8WQCuvD9WTWQETwR14NEGejGkSv2o).

## Why

Mark's Body Smart scale sends readings to the Withings cloud. A local Bluetooth reader makes the box the reader, so the cloud copy can be turned off once the local one is good enough. DEV-12 covers working out the protocol; the product is an ordinary read-only declaration (DEV-1, DEV-4).

## Protocol source, checked

`github.com/pierosavi/withings-local` (MIT, read at `eab5a03`, 2026-10-24), `docs/protocol.md` and `src/withings_wpp/`. Messages are `0x01 | cmd:u16 | len:u16 | TLV*`, TLV `type:u16 | len:u16 | value`, big-endian; bit `0x4000` marks a request from the scale. One GATT characteristic carries writes and notifications; replies arrive fragmented to the MTU and are joined by the header length.

The source's client sends exactly these, and nothing else: PROBE (257, fixed `APP_PROBE` and `APP_PROBE_OS_VERSION`), PROBE_CHALLENGE (296, our answer `SHA1(challenge ‖ mac ‖ kl)` plus our own 16-byte challenge), BATTERY (261, empty), CONNECT_REASON (273, empty), STORED_MEASURE (271, action 0 or 1 only), SYNC_OK (277, empty), DISCONNECT (272, empty); and to a request from the scale, either the SYNC_OK echo (`277|0x4000`) or ERROR (`256|0x4000`, `CMD_ERROR` naming the request's command with −3, unsupported).

**Checked against the never-send list.** The doc's list (308 ASSOCIATION_KEYS_SET, 275 SETUP_OK, 269 SCALE_SESSION, 328 BeamO acknowledge, 274 user/units, Wi-Fi, firmware update, factory reset, 271 action 2) matches the code's comments, but it is open: Wi-Fi, firmware and factory reset have no opcode in the source, and TIME_SET (1281), which writes the scale's clock, is on neither list. A denylist therefore cannot be complete, so the reader's hard deny is a **closed allowlist of whole message shapes** (command, TLV types in order, value lengths and values), not of opcodes: the nine shapes above. SYNC_OK stays on it: two independent projects report it neither deletes nor hides readings (source `docs/recon.md`, observed), and without it the scale may ignore the next connection.

## Design points settled here (recommendations, flagged for the reviews)

1. **`kl` never enters the session.** The session asks a `Prover` for the challenge answer and for the check of the scale's answer. The sealed-store prover (part b) holds `kl`; the enforcer side (part c) can then run the session with no `kl`, which NET-2's "share no secret" needs.
2. **DEV-3.** The scale offers no public-key identity: only the MAC string plus the mutual `kl` proof, which anyone holding `kl` (Withings included) can pass. Treat it as **unverified** (DEV-3): its readings are marked unverified, so no owner rule treats them as urgent. A scale that fails to prove `kl` gets no further command, only DISCONNECT.
3. **Readings carry no device text.** The probe's name, MAC string and manufacturer ID are never returned; a reading is a time, a measure code from a closed table, a decimal value and the scale's user slot number. Other household members weigh on the same scale, so part b decides which slots are the owner's; all are private (PLN-3).
4. **Spec text.** SPEC DEV-1 says box radios are reached through a hub, and the DEV-5 tracker line says trackers are reached through the vendor cloud. The enforcer's radio (NET-2) is the hub here, and its channel carries reads; the challenge answer crossing the channel is a new message kind. Part (s) is an L1 spec-diff row for the tracker sentence and that channel message.

## Split

- **(a) this PR.** `broker/clerk/withings/`: codec and reassembler, the allowlist at the one write path, the read session over a `Link` and a `Prover`, the measure parser, the DEV-12 declaration (one operation, verb `read`), a synthetic scale, a fuzz target.
- **(b)** Core-side clerk: `kl` in the sealed store (STO-2, CLK-1), the `Prover`, readings onto the bus as private, untrusted, unverified events (DEV-8), rate-limited. Needs STO-2 and the device clerk host.
- **(c)** Enforcer-side BLE service on the enforcer's radio (BlueZ, confined radio stack, NET-2), and its channel messages. Needs the enforcer (Protectli V1410) and (s).
- **(d)** One-time fetch of `kl` from Mark's Withings account (CLK-3 account clerk, CLK-1 custody).
- **(e)** One-time export of the cloud history as private data on the core's store, after the first good local read.
- **(s)** L1 spec-diff row, point 4.

## Acceptance tests

Part (a); DEV-4, DEV-12, DEV-3, DEV-8, CLK-1, in `broker/clerk/withings/`:
- `TestSyntheticScaleReadingsParse`: a synthetic scale's weigh-ins come back as typed readings, merged by time and type, marked unverified.
- `TestEveryShapeOffTheAllowlistIsRefused`: every command off the allowlist, every STORED_MEASURE action but 0 and 1, and any changed TLV is refused before the link is written, and the refusal is logged by command number only.
- `TestScaleRequestsGetOnlyAllowedReplies`: requests from the scale (308, 275, 1281, a malformed one) get only the ERROR reply, and SYNC_OK only its echo.
- `TestUnprovenScaleGetsNoCommand`: a scale that fails the `kl` proof gets DISCONNECT and nothing else.
- `TestKlNeverLeaves`: the canary `kl` appears in no log line, error, reading or written frame.
- `TestDeclarationIsReadOnly`: every declared operation maps to `read`.
- `FuzzReassemble`: no panic and bounded buffers on any notification stream.

Failure path: a write or delete reaches the scale (a reading lost before the cloud gets it, the scale re-keyed or reset), or `kl` leaks.

**Guard files:** none. `broker/clerk/` is on the G2 list, `tools/risk_tier.py` classes an unnamed broker package tier A, and the package imports only the standard library and `broker/kernel/key`.

## Scope

`broker/clerk/withings/` (its own `ASSUMPTIONS.md` included), `NOTICE`, this brief.

## Estimate

One session, about 120k tokens, strongest model.
