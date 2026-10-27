# CAM-clerk: the core's camera clerk

Board section: Devices, hardware and image (SPEC §13-14). Work item #3514; SPEC DEV-1, DEV-2, DEV-3, DEV-7, DEV-8, DEV-10, CLK-1, KRN-7, NET-2 (Cameras and microphones), LOG-4, A16. Tier A (a client credential, a parser of hostile streams in the trusted base, raw capture). Authority: Mark's row, 2026-10-27. Node side: CAM-node (#3513, `briefs/CAM-node.md`), whose part (a) `broker/camwire` this row uses for framing.

## Why

NET-2: camera video goes "straight to the core on connections it starts to their stream port, decoded in a sandbox". This row is that core side: it opens the node's pinned stream, keeps raw capture under DEV-7, decodes only in a sandbox, and raises an event when a node goes silent or changes key. VIS-core (#3515) consumes its decoded frames; that row, and live view or images by text (D-143), are consumers, not part of this one.

## Open questions (asked on #3514; the brief builds on the recommendation)

1. **Retention of continuous capture.** DEV-7 deletes capture "at task end unless the owner set a retention", but continuous capture has no task. Recommended: with no owner-set retention, continuous capture is held in memory only (a bounded ring for consumers and live view) and nothing is written; with a retention, encrypted segments are kept for that long. On-request capture belongs to its task and is deleted at its end. Changes (c).
2. **Process, given the device-clerk host (#3321).** The row depends on the device host, but a video stream does not fit its model (bounded frames, readings, one sandboxed process per operation). Recommended: the camera clerk is its own clerk process, `cmd/agentos-camera`, under its own uid (CLK-1), reusing `devhost`'s per-source DEV-8 rate limit and the device-report kernel entry of DEVSLOT b3 (#3321), not running as a driver. Changes (d).
3. **"Turned off" on a spoofed node.** Isolating a safety-list device at the enforcer needs a passkey (NET-4), so the clerk cannot do it alone. Recommended: the clerk stops dialing the node, marks it off with a KRN-7 line, and raises the tamper event; the owner re-pins at tier 4 or isolates it on the enforcer's page.
4. **Where the core learns a node.** A node offers no discovery (one port, CAM-node). Recommended: the enforcer's channel lists the node's address and key fingerprint once the owner pairs it there; the owner connects it on the local page at tier 4 (DEV-10, capture turn-on), comparing the first 8 characters of the fingerprint with the case label. The core's client public key goes back to the enforcer for the node's next owner-signed bundle (CAM-node question 2).

## Design points settled here (flagged for the reviews)

1. **Credential.** The core's camera client key (P-256) is the clerk's credential under CLK-1: in the sealed store, lent only to `agentos-camera` like `clerk.Secrets.DeviceKey`, never in a log, event or error. It is the A16 canary for cameras ("a camera password"); there is no stream URL, so none can embed it.
2. **Dial and pin.** The clerk dials only the pinned node's address on the home network (DEV-2, through the same dial guard as other device clerks), TLS 1.3, its client key presented, and checks the node's leaf public key against the pin by SPKI hash; no certificate chain, no name check. A mismatch is refused before any frame is read, logged, and turns the node off (question 3).
3. **What the core parses.** Only `camwire` frame headers and the fixed status frame run in the clerk. H.264 and thermal payloads go unparsed, as bytes, to the decoder sandbox. The clerk never interprets a NAL unit.
4. **Decoder sandbox.** One long-running gVisor container per streaming camera (`broker/vm/gvisor`, as `photo` uses one-shot runs): no network, read-only root, memory and CPU caps, its own uid. Inside, `agentos-camdecode` decodes H.264 with libavcodec built with only the H.264 decoder (mature; OSS-Fuzz covers it), and parses thermal frames itself. It emits raw frames of a fixed declared size (dimensions from the node's bundle, never from the stream) over a pipe; the clerk checks each frame's header and length against that size, as `photo` checks dimensions, and drops the sandbox on any mismatch, a stall past the deadline, or the cap. A crash restarts the container with a backoff and a counted DEV-8 event.
5. **Capture gate.** Until the owner's tier-4 turn-on (DEV-7, DEV-10), the clerk opens no stream for that node. The turn-on record states continuous or on request; on request opens a stream only within a task whose plan step names the camera (`read` is capture, as the clerk reads the response type).
6. **Not in recall or the log.** No frame, crop or payload byte enters recall (LOG-4), the log, events or STATUS. The log and events carry only the camera's id, the time, the segment id and counts. Derived content (VIS-core's) is ordinary private data and not this row's.
7. **Tamper events.** A node silent past its expected frame interval (owner-settable, default 30 s), a refused key, a decoder fault, and a recovery each raise a device event (DEV-8): private, untrusted, rate-limited per camera, and verified (the node has a cryptographic key, DEV-3), so an owner rule may make "camera silent" urgent. No device text enters the event.
8. **Bounded resources.** Per camera: one connection, one sandbox, a frame ring of fixed size, a segment write rate cap; the clerk refuses a new camera when admission (RES-2) says no and logs it.

## Lifecycle matrix (integration owner: d, which wires the process, the page step, the enforcer list and the end-to-end test)

| Stage | Outcome | Part and test |
|---|---|---|
| Node listed by the enforcer, not connected | STATUS line; no dial | d |
| Connected, capture off | no stream opened | a, d |
| Capture turned on (tier 4) | stream opened; frames decoded in the sandbox | a, b, d |
| Node presents another key | refused before any frame; off; KRN-7 line; tamper event | a |
| Node silent past the interval | event; redial with backoff; event on recovery | a |
| Hostile stream (bad frame header, oversize, malformed NAL) | header errors end the connection in the clerk; payload faults end the sandbox; neither reaches the clerk's memory beyond caps | a, b |
| Retention set | encrypted segments kept, deleted at expiry | c |
| No retention | memory ring only; nothing on disk | c |
| On-request capture | stream only in its task; deleted at task end | a, c |
| Restart of the core | pin, turn-on and retention reloaded; streams resume; no frame from before survives without retention | c, d |
| Re-pin (tier 4) | new key pinned; old one refused | a, d |
| Disconnect (text) | pin, turn-on and segments erased; no dial | c, d |
| STOP (KRN-7) | streams closed with every clerk step | d |

## Split

- **(a) CAM-clerk-lib (one session, about 100k; after CAM-node a).** `broker/clerk/camera/` (+tests, `ASSUMPTIONS.md`): the dial, the pin, the client key holder over the sealed store's lending, the frame reader on `camwire`, the capture gate, silence detection, tamper events through an injected sink with `devhost`'s DEV-8 limiter, and a synthetic node in tests (built on `camwire`, its key in memory).
- **(b) CAM-decode (one session, about 100k; after a).** `broker/cmd/agentos-camdecode` (the sandbox's program), the decoder's sandbox image entry and its pinned libavcodec build, `broker/clerk/camera/decode.go` (start, feed, check, restart). If the libavcodec build is the larger half, cut at (b1) thermal and the sandbox plumbing, (b2) H.264.
- **(c) CAM-retain (one session, about 70k; after a and question 1).** `broker/clerk/camera/store.go`: encrypted segments under a sealed-store key, the retention sweep, erase on disconnect, the memory ring.
- **(d) CAM-clerk-host (one session, about 100k; after a to c, CAM-node a, and DEVSLOT b3 #3321).** `broker/cmd/agentos-camera` and its unit and user, the tier-4 local-page connect and turn-on step, the enforcer list read, the kernel device-report wiring, STATUS lines, and one end-to-end test (`broker/e2e`) against a synthetic node through connect, turn-on, a key swap, silence, restart and disconnect. Serial with the agentosd chain only if it edits `cmd/agentosd` (D-111); it should not.

## Acceptance tests

Part (a), `broker/clerk/camera`:
- `TestSpoofedNodeRefused`: a node with another key is refused at the handshake, nothing is read, the node is off, a KRN-7 line and one tamper event are emitted, and it is not dialed again until re-pinned.
- `TestNoStreamBeforeTurnOn`: with capture off no connection is opened; on request opens only within a task naming the camera.
- `TestClientKeyNeverLeaves`: the canary client key appears in no log line, error, event or frame (A16).
- `TestOnlyPinnedAddressDialed`: other addresses, and any address off the home network, are refused by the dial guard.
- `TestSilenceRaisesEvent`, `TestEventsRateLimited` (a flapping node coalesces to one counted event per window).
- `TestFrameHeaderFaultsEndConnection`: unknown type, over-cap length, a settings-type frame from the node.
- `TestCaptureNotInLogOrEvents`: after a run, no payload byte (a marker pattern in the synthetic stream) is in the log, events, STATUS or recall.
- `FuzzStatusFrame`.

Part (b):
- `TestDecoderHasNoNetwork`, `TestDecoderOutputMustMatchDeclaredSize` (a wrong size ends the sandbox), `TestDecoderStallKilled`, `TestDecoderCrashRestartsWithBackoff`.
- `FuzzThermalFrame` (in `agentos-camdecode`), `FuzzH264Feed` (malformed NAL units and oversized frames through the sandbox entry; no escape of caps, no clerk panic).

Part (c):
- `TestNoRetentionWritesNothing`, `TestRetentionSweepDeletes`, `TestSegmentsEncrypted` (no marker bytes on disk), `TestDisconnectErases`, `TestOnRequestDeletedAtTaskEnd`.

Part (d): the matrix rows marked d, each a test, and the end-to-end test.

Failure path: a spoofed node feeds the core, the client key leaks, a hostile stream escapes the decoder, or capture is kept, logged or recalled against DEV-7.

## Scope

(a) `broker/clerk/camera/`. (b) `broker/cmd/agentos-camdecode/`, the decoder sandbox image files, `broker/clerk/camera/decode.go`, vendored or pinned libavcodec and `NOTICE`. (c) `broker/clerk/camera/store.go`. (d) `broker/cmd/agentos-camera/`, its unit and sysusers line, the local-page step in `broker/localui`, `broker/e2e`. Guard files: `tools/trusted_base_parsers.txt` (`parser .../broker/clerk/camera -- frame headers and status from camera nodes`; `agentos-camdecode` runs in the sandbox), `broker/core/core.txt` (`wiring cmd/agentos-camera`), each with its PR body line. Each part runs `python3 tools/premerge.py --needs-mark`; where it prints `mark`, the part owes the separate Security accept (D-137).

## Estimate

(a) 100k, (b) 100k, (c) 70k, (d) 100k; strongest model, one session each.
