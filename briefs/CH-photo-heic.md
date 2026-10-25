# CH-photo-heic: HEIC and HEIF in the confined decoder

Board section: Backlog refill (2026-10-17). Part of CH-photo-upload (briefs/CH-photo-upload.md), work item #3115 (under #2146); SPEC CH-23. Tier A.

**Needs:** CH-photo-a. **Gate:** dependency choice accepted by the L3 and Security review before the build; lenses L3 and Security.

## Why

CH-23 accepts HEIC/HEIF. iPhone Safari transcodes to JPEG for the upload page, but an Android phone set to HEIF, or a desktop browser handing over a `.heic` file, sends HEIC bytes, which until now are refused with the CH-27 text. Picture texts (a later row) may also carry HEIF. The owner never converts anything (Mark's direction), so the box must decode it.

## Change

`agentos-photo` (its decoder, `broker/photo/decoder`) decodes HEIC/HEIF (the primary image of the file, with its `irot`/`imir` transforms applied) and re-encodes it as JPEG under the same limits and metadata removal as CH-photo-a. The decoder must keep the binary static with no cgo and run unchanged inside the runsc one-shot. Candidates, in order: a pure-Go HEIF/HEVC decoder if one is mature enough; otherwise libheif compiled to WebAssembly run by a pure-Go runtime (for example `gen2brain/heic` on wazero). The PR states which, its licence (NOTICE; for an LGPL library compiled to WebAssembly, how the wasm blob is rebuilt and replaced), its maintenance, its fuzz result, and the time and memory of a 48 MP HEIC under CH-photo-a's caps. The upload page adds `image/heic,image/heif` to its accept list when CH-photo-c builds it.

**Acceptance tests:** CH-23: `TestDecodeHEICToJPEG`, `TestDecodeHEICAppliesRotation`, `TestDecodeHEICStripsMetadata` (synthetic HEIC with an EXIF GPS canary), `TestDecodeHEICOver50MPRefused` (`broker/cmd/agentos-photo/heic_test.go`); `FuzzDecodeHEIC` (`broker/photo/decoder`) added to the soak workflow's fuzz targets; the broker's pre-check passes a HEIC to the sandbox (`broker/photo` `TestDecodeRefusals`).

Failure path: a HEIC photo from an Android phone is refused although the spec accepts it, or the new decoder lets a crafted file escape its limits.

**Guard files:** none (no new broker package).

## Scope

`broker/photo/decoder/`, `broker/cmd/agentos-photo/`, the type pre-check in `broker/photo/decode.go` and its test, `broker/photo/ASSUMPTIONS.md`, `broker/vendor/` and `broker/go.mod`, `broker/go.sum`, `NOTICE`, `.github/workflows/soak.yml`'s fuzz list. (Refreshed at build: the decoder moved to `broker/photo/decoder` and the fuzz list to the soak workflow after this brief was written; `broker/localui/photo.go` does not exist until CH-photo-c.)

## Estimate

One session, about 100k tokens, strongest model.
