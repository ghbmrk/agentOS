# CH-photo-a: confined photo decoder

Board section: Backlog refill (2026-10-17). Part of CH-photo-upload (briefs/CH-photo-upload.md), work item #2146; SPEC CH-23, ARC-5. Tier A.

The broker never decodes a photo in its own process. This package adds the decoder binary and the one-shot confined run, and nothing that stores or delivers photos.

**Needs:** none. **Gate:** G1 freeze off, or a Mark-merged amend adding the two new paths to `tools/g1_scope.txt`; lenses L3 and Security on the strongest model.

## Change

1. **`broker/cmd/agentos-photo` (new, static, no cgo).** Reads at most 20 MB from stdin (more is refused). Identifies JPEG or PNG by magic bytes; anything else exits with code `type`. Reads the dimensions with `image.DecodeConfig` and refuses over 50,000,000 pixels before any pixel decode. Decodes with `image/jpeg` or `image/png`; a decode error is refused. Reads the EXIF orientation (APP1, tag 0x0112 only, bounded parse) and applies it. Resizes so the long side is at most 4096 px (a library scaler if its memory fits under the cap, otherwise a bounded box filter; the PR says which and why), and makes a thumbnail of at most 320 px. Encodes a new JPEG (quality 90) for JPEG input and a new PNG for PNG input, from decoded pixels only, so EXIF, GPS, XMP, ICC, comments and embedded thumbnails cannot survive. Writes one frame to stdout: a JSON header line `{"format","width","height","bytes","thumb_bytes"}` then the image then the thumbnail. Exit codes and one-word stderr reasons: `type`, `size`, `pixels`, `decode`. No network, file or environment access beyond stdin and stdout.
2. **`vm/gvisor` one-shot run (new method, e.g. `RunOnce`).** Runs a given binary as a fresh runsc container: `--network=none`, a read-only rootfs holding only that binary, no mounts of broker state, no devices, a memory limit sized on the costliest accepted file, measured on a 50 MP baseline JPEG and a 50 MP 16-bit PNG (the PNG is the larger, about 400 MB decoded), recorded in `broker/photo/ASSUMPTIONS.md`, a wall-clock timeout (30 s), stdin capped by the caller and stdout capped (image plus thumbnail plus header: a 4096-pixel PNG that compresses badly, about 80 MiB). The container is deleted on every exit path, and a container left by a crash is killed at the next start like the existing stale kills. It reuses the package's runsc argv, platform choice, kill and capped writer; `vm/gvisor` stays the only package that executes runsc.
3. **`broker/photo` decode client (new package, decode file only).** `Decode(ctx, raw []byte) (Result, error)` runs the binary through the one-shot method, parses the frame, checks the header against the output (JPEG or PNG magic, byte counts, both sides at most 4096, thumbnail at most 320), and returns typed refusals. It drops `raw` on return; nothing is written to disk. It never calls an `image` decoder itself; a lint test enforces that `broker/photo` imports no `image/*` decoding package.
4. **Image build.** `image/build.sh` installs `agentos-photo` and its read-only rootfs directory.

## Requirements and acceptance

**Acceptance tests:**
- CH-23 (limits, types): `TestDecodeRefusesTypes` (GIF, WebP, MP4, a vCard, a PDF, HEIC until CH-photo-heic: refused `type`), `TestDecodeRefusesOver50MP` (a synthetic PNG header claiming 8000x7000 is refused `pixels` before decoding), `TestDecodeRefusesOver20MB` (`broker/cmd/agentos-photo/photo_test.go`).
- CH-23 (re-encode, orientation, metadata): `TestDecodeStripsMetadata` (a synthetic JPEG with EXIF GPS, a comment, an embedded thumbnail and an XMP block comes out with none of those byte markers and with the synthetic canary strings absent), `TestDecodeAppliesOrientation` (orientation 6 swaps width and height and rotates a marked pixel), `TestDecodeBoundsLongSide` (6000x3000 in, 4096x2048 out), `TestDecodeRefusesCorrupt` (truncated and fuzzed inputs are refused, never echoed).
- CH-23 (never decodes in the broker): `TestPhotoImportsNoDecoder` (`broker/photo/lint_test.go`).
- ARC-5 (confinement): `TestRunOnceNoNetwork`, `TestRunOnceReadOnlyRoot`, `TestRunOnceMemoryCap`, `TestRunOnceTimeoutKills` (`broker/vm/gvisor/runonce_test.go`; run as root with `AGENTOS_RUNSC` in the integration job, skipped elsewhere like the package's other runsc tests), and `TestDecodeRejectsLyingHeader` (a fake runner returns a header that disagrees with the bytes; refused).
- A fuzz target `FuzzDecode` over the binary's input path (no panic, every output re-checked); add it to `image/fuzz-targets.json`.

Failure path: a photo carrying GPS coordinates reaches a guest or a hosted model with its location, or a crafted image crashes or takes over the broker process.

**Guard files:** `tools/risk_tier.py` (`photo` in `TIER_A_BROKER`, criterion (c), parses owner-channel input), `broker/daemon/arc2_test.go` (allowlist entry for `photo`: imports `vm`, `vm/gvisor`; denies `net`, `net/http`, `os/exec`, `unsafe`, `C`), `tools/g1_scope.txt` (`allow broker/photo/`, `allow broker/cmd/agentos-photo/` while the freeze holds). Pre-approved in scope; the PR is still tier A and Mark-only to merge (D-125).

## Scope

`broker/cmd/agentos-photo/` (new), `broker/photo/decode.go` and its tests (new), `broker/vm/gvisor/` (the one-shot method, its tests, ASSUMPTIONS.md rows), `broker/vendor/golang.org/x/image/` and `broker/go.mod`, `broker/go.sum`, `image/build.sh`, `image/fuzz-targets.json`, the guard files above, `broker/photo/ASSUMPTIONS.md`.

## Estimate

One session, about 120k tokens, strongest model (tier A).
