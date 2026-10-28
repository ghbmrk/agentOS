# CAM-node: the camera node image

Board section: Devices, hardware and image (SPEC §13-14). Work item #3513; SPEC DEV-2, DEV-3, DEV-7, NET-2 (Cameras and microphones, Safety devices), NET-4, NET-7, KRN-2, A16. Tier A (a device key, a stream that carries raw capture, an image that boots only when signed). Authority: Mark's row, 2026-10-27. Core side: CAM-clerk (#3514), which shares part (a).

## Why

NET-2 admits only cameras that work offline: settings go only through the enforcer, and video goes straight to the core on a connection the core starts to the camera's stream port. Off-the-shelf cameras run vendor code that cannot be verified (DEV-3) and often reach their cloud. CAM-node is our own minimal firmware on commodity parts, so a camera is verified, offline and inspectable.

Parts (from the row; the owner buys a prototype after this brief): a Raspberry Pi CM4-class board (libcamera, hardware H.264, signed boot), a Sony IMX462-class low-light sensor with 850 nm IR, an optional thermal core (FLIR Lepton or Boson class), and a secure element holding the device key, which never leaves it.

## Open questions (asked on #3513; the brief builds on the recommendation, and a different answer changes only the part named)

1. **How settings and updates reach a node with no outbound connection and one port.** Recommended: the one TLS 1.3 port with mutual authentication. A client presenting the core's pinned key gets the stream only; a client presenting the enforcer's pinned key gets the settings and update channel only; any other client is refused at the handshake. A port scan from anywhere shows one port. Changes (a), (b).
2. **The node authenticates its client.** The row says only that the core pins the node. The home network is untrusted (DEV-2), so without client authentication any host on it gets the video. Recommended: as point 1; the node holds the core's and the enforcer's public keys from an owner-signed bundle.
3. **What "signed by the owner's key" means on the node.** Recommended: the node verifies the owner's passkey assertion itself (WebAuthn, ES256, the enforcer's relying-party name, user verification set), whose challenge commits to the hash of the bundle (NET-4: "each challenge commits to the change"), against the owner credential's public key pinned at provisioning. A compromised enforcer then cannot loosen a camera. Turning a camera off already needs a passkey (NET-4 Tightening, safety list), so every node setting needs one, which keeps the node to one rule. Changes (a).
4. **Who signs the boot image, and does an update need the owner.** A passkey cannot sign a boot image. Recommended: the project's release signer (HW-10) signs the image and its key hash is fused into the board's one-time memory; installing an image also needs the owner's passkey assertion over its manifest hash, since cameras are on the safety list and NET-7's automatic apply covers only devices without a safety role. Changes (a), (c).
5. **First provisioning.** A fresh node has no owner key, so whoever reaches it first could provision it. Recommended: the node accepts its first bundle only while a button on the board is held at power-on (physical presence), and only once; its key fingerprint is printed on the case for the owner to compare on the enforcer's page. A full reset needs the button again and erases the bundle.
6. **Secure element.** Recommended: Infineon OPTIGA Trust M class over the row's ATECC608: its datasheet and host library (MIT) are public, where the ATECC608's full command reference is not [Inference: from the vendors' sites; the builder confirms before (b) starts]. Both give a P-256 key generated inside, a locked slot and monotonic counters. Affects the purchase.

## SPEC change owed (if Mark takes question 4's recommendation)

HW-10 names one signed image, serving controller install, the edge, recovery and workstations. A release-signed camera-node image is a second one, so a one-line L1 spec-diff naming the node image is owed before (c) merges (L3 release finding on #3526).

## Design points settled here (flagged for the reviews)

1. **One wire, shared with the core.** Part (a) is a pure Go package used by both the node and CAM-clerk, so both sides frame and verify the same way. No RTSP: one fixed framing keeps the core's parsing to frame headers (CAM-clerk decodes the payload in a sandbox). Frames: `type (1 byte) | length (4 bytes, big-endian) | payload`, with per-type caps: H.264 access unit (Annex B, cap 2 MiB), thermal frame (fixed shape per declared core, 16-bit samples, header with width, height, frame counter), node status (fixed fields: uptime, image hash, settings counter, temperature), and settings and update messages on the enforcer's channel only. Any other type or an over-cap length ends the connection.
2. **Settings bundle.** Canonical encoding (deterministic CBOR or fixed-field binary; no JSON) of: node key fingerprint, counter, the core's and the enforcer's client public keys, sensor settings (resolution, frame rate, bitrate, IR mode, thermal on or off) within declared ranges, and the stream's on or off state. The node applies a bundle only if the assertion verifies, the fingerprint is its own, and the counter is above the secure element's monotonic counter, which it then increments: no replay, no rollback.
3. **Image updates.** A/B root slots. The enforcer streams an image whose manifest (image hash, version, counter) carries the owner's assertion (question 4). The node writes the inactive slot, checks the hash, sets one-shot boot to it, and marks it good only after the stream server starts and the image's counter is above the counter in the secure element; otherwise the bootloader returns to the old slot. An image older than the counter is refused.
4. **Keys.** The device key is generated inside the secure element at provisioning and its slot is locked; the TLS server signs through a `crypto.Signer` that sends the element's sign command. TLS 1.3 only, ECDSA P-256; the core pins the key, not a certificate chain, so the node needs no clock and no certificate authority.
5. **Minimal image.** Buildroot (mature, small, read-only rootfs) with dm-verity whose root hash is inside the signed boot image. One service, the stream server, as a static binary under its own uid with the camera and secure-element devices only. No shell, getty, SSH, debug UART console, package manager, DHCP server, mDNS or NTP. A DHCP client and an nftables input policy that accepts the stream port only and drops everything outbound except replies are the rest. `rpicam-vid` (libcamera apps, BSD-2) produces H.264 from the hardware encoder into a pipe the server reads [Inference: the CM4's encoder is reached through V4L2 M2M; the builder confirms on the board in (d)]. The Lepton is read over SPI (VoSPI) by the server; a Boson over USB UVC.
6. **Public and generic.** Nothing about one household is in git: models, addresses, placement and keys are owner data (the bundle, the enforcer, the sealed store). Fixtures use synthetic keys and generated video.
7. **No audio.** The node has no microphone and the wire has no audio type. Adding one is a new row.

## Lifecycle matrix (integration owner: c, which wires the server into the image and runs the end-to-end test in QEMU)

| Stage | Outcome | Part and test |
|---|---|---|
| Unsigned or altered boot image, or altered root | does not boot | c (QEMU: verity), d (board: signed boot) |
| First boot, no bundle, button not held | port open; every client refused; nothing streamed | b, c |
| First boot, button held | first bundle accepted once; counter set; window closes | b, c |
| Normal start | server up; one port; stream only to the pinned core key | b, c |
| Client with another key, or core key on the settings channel | refused at the handshake or on the first frame | b |
| Bundle without a valid assertion, for another node, or with an old counter | refused; settings unchanged | a, b |
| Update signed and approved | written to the inactive slot; boots; marked good; counter raised | a, b, c |
| Update that fails to start, or older than the counter | old slot boots; refused | b, c |
| Internet cut | streams unchanged | c (QEMU, no route), d |
| Restart | same key, bundle and counter; streams again | b, c |
| Reset with the button | bundle erased; back to first boot; device key kept | b |
| Removal (owner decommissions) | the core drops the pin (CAM-clerk); the enforcer drops the device | none here |

## Split

- **(a) CAM-wire (one session, about 70k).** New package `broker/camwire` (+tests, fuzz, `ASSUMPTIONS.md`): the frame codec, the bundle and manifest encodings, and their verification (the WebAuthn assertion check: authenticator data flags, relying-party hash, client data type, origin and challenge, and an ES256 signature in strict DER over the pinned public key). No I/O, no imports outside the standard library. Its `ASSUMPTIONS.md` records the accepted residual of NET-4's loosening wait: the node applies a verified bundle at once and has no clock, so the 10-minute cancel window rests on the enforcer alone; a compromised enforcer can skip the wait but cannot forge the owner's assertion.
- **(b) CAM-server (one session, about 120k; after a).** New `broker/camnode/` (the server library, the secure-element driver `broker/camnode/se`, the sources behind interfaces) and `broker/cmd/agentos-camnode` (the static binary). If it nears 150k, cut at (b1) the element driver, TLS, roles, bundle apply and counters, and (b2) the sources, framing out, update staging. Tests use a fake element (P-256 in memory, behind the same interface) and generated video fixtures.
- **(c) CAM-image (one session, about 100k; after b).** `image/camnode/` (Buildroot external tree, board config, signed boot image, verity, A/B slots, units, nftables) and a QEMU aarch64 end-to-end test (`image/camnode/e2e/`), run in CI on a cached build, with the matrix rows marked c. The core image must not contain the node binary (a test in `image/` checks the core manifest).
- **(d) CAM-live (on the prototype; after c and the purchase).** Fuse the release key hash, provision, run the matrix on the board, scan from the core, cut the internet. Records results in `image/camnode/LIVE.md`. Needs Mark's hands for the fuse step (irreversible).

## Acceptance tests

Part (a), `broker/camwire`:
- `TestFrameCaps`: each type over its cap, an unknown type, a truncated header and a zero-length access unit end the read with an error; nothing beyond the header is buffered for an over-cap length.
- `TestBundleVerifies`: a bundle with a valid synthetic passkey assertion verifies; a flipped bundle byte, a wrong relying-party hash, user verification unset, a wrong origin, a challenge for another bundle, a wrong key and a non-DER signature each fail.
- `TestBundleForAnotherNodeRefused`, `TestCounterMustRise` (equal or lower refused).
- `TestManifestVerifies`: release signature and owner assertion both required; either missing fails.
- `TestCanonicalEncoding`: two encodings of the same bundle differ only if a field differs; a non-canonical encoding is refused.
- `FuzzFrame`, `FuzzBundle`, `FuzzManifest`: no panic, bounded allocation.

Part (b), `broker/camnode`:
- `TestOnlyPinnedClients`: a client with no certificate, an unknown key, or the enforcer's key asking for the stream is refused; the core key gets frames, the enforcer key gets the settings channel only.
- `TestFirstBundleNeedsButton`: without the button no bundle is taken; with it, exactly one.
- `TestReplayedBundleRefused`, `TestSettingsWithinDeclaredRanges` (an out-of-range bitrate or frame rate refused before it reaches the source).
- `TestUpdateStagesAndRollsBack`: a good image is marked good only after the server starts; a failed start and an older counter return to the old slot.
- `TestDeviceKeyNeverExported`: the element interface has no export, and the canary key appears in no log line, error or frame (A16).
- `TestNoOutboundDial`: the server package imports no dialer (link test), and the binary opens no socket other than its listener (run under a seccomp or network-namespace test).
- `TestElementCommandFraming`: CRC and length checks against recorded element transcripts; a malformed reply is refused.

Part (c), `image/camnode/e2e/` in QEMU:
- `test_only_stream_port`: a TCP and UDP scan from the host shows only the stream port.
- `test_no_shell`: no shell, getty, sshd or console login exists in the root; the root is read-only.
- `test_altered_root_does_not_boot`: one flipped byte in the root fails verity.
- `test_unsigned_settings_refused`, `test_update_rollback`, `test_streams_without_internet`.

Part (d): the issue's acceptance list on the board, results recorded.

Failure path: a node streams to an unauthenticated host, takes settings or an image that the owner did not sign, boots altered code, or reaches the internet.

## Scope

(a) `broker/camwire/`, `broker/loops/plainname.go` (a line per fuzz target; `TestThePlainNameMapCoversEveryLoop7Subject` fails a `Fuzz*` without one). (b) `broker/camnode/`, `broker/cmd/agentos-camnode/`, any vendored element host code and `NOTICE`; `broker/loops/plainname.go` too if (b) adds a fuzz target. The plain-name file is shared with CAM-clerk (a) and (b), so parts that edit it run serially (D-111). (c) `image/camnode/`, the core image's manifest test. (d) `image/camnode/LIVE.md`. Guard files: `tools/trusted_base_parsers.txt` for `camwire` (a `parser` line; the core links it through CAM-clerk), with a `Trusted-base: parsers --` line in (a)'s PR. New `broker/` paths are tier A by default (`risk_tier.py`, unlisted broker path), so no tier-file edit is needed. Each part runs `python3 tools/premerge.py --needs-mark`; where it prints `mark`, the part owes the separate Security accept (D-137).

## Estimate

(a) 70k, (b) 120k, (c) 100k, strongest model, one session each. (d) is a live session with Mark.
