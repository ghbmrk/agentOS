# Patched h265 v0.2.3 (CH-photo-heic-tiles, #3131)

Upstream github.com/gen2brain/h265 v0.2.3 (h1:+fEP2Xf1CoZ21SxA2YpqnPZb6Y/hAEkcgjU1gMsOhrk=), the `heic` and `hevc` packages without tests or testdata; LICENSE and go.mod are upstream's. broker/go.mod replaces the module with this directory. Edits are marked `agentos:`, in heic/grid.go and heic/heic.go only:

- `decodeTiles` bounds each grid tile's coded frames by `tileLimit`: the one size every tile's `ispe` must name, plus one 64-sample coding tree block each way, instead of the whole image's `FrameSizeLimit`. `tileLimit` refuses tiles with no `ispe` or with differing ones (`ErrInvalid`), a size past 65536 (`ErrUnsupported`), and tiles that do not cover the grid's output or leave a row or column of tiles wholly past it (`ErrInvalid`). The tiles decoding at once are at most the file's limit divided by `tileLimit` (and at least one), so together they code no more than the declared picture.
- `itemDecoder` gains `limit`, which, when set, is the frame limit `decodeItem` gives the decoder in place of the file's.
- `decodeItem` returns the first picture an item codes and releases each later one as it comes out, instead of holding all of them until the item ends.

Re-vendor recipe: to move to a new upstream release, copy its `heic` and `hevc` packages (no `_test.go`, no testdata), LICENSE and go.mod here, re-apply the `agentos:` edits, run `go mod vendor` in broker/, and run `go test ./cmd/agentos-photo/ ./photo/...`. Drop the replace when upstream bounds grid tiles by their own size and stops holding an item's later pictures. See broker/photo/ASSUMPTIONS.md CH-photo-heic-5.
