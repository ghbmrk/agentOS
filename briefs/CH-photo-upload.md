# CH-photo-upload: photos from the owner over the Wi-Fi page (parent brief)

Work item: #2146 (release, tier A). Spec: SPEC §6.4 CH-22 to CH-27 (merged in #2148, briefs/CH-photo-spec.md), with ARC-3, ARC-5, ARC-6, REV-5, REV-6, OP-11, CAP-3, RES-4, CH-7, CH-12, CH-15.

This parent brief is not built. It fixes the design, splits the row into six packages that each finish under 150k tokens, and names the integration owner and its lifecycle matrix. Each package has its own brief, acceptance tests and scope.

**Acceptance tests:** none: design and split only; each sub-brief (CH-photo-a to e, CH-photo-heic) names its tests, and CH-photo-e owns the lifecycle matrix test below.

**Guard files:** none here; each sub-brief that adds a broker package names its own.

## The owner's direction

Mark (relayed 2026-10-17): the owner just attaches a photo to a text, as to a friend; any behind-the-scenes route is fine as long as it does not sacrifice security needlessly, and the owner never sees or touches the conversion. So: nothing in this row asks the owner to pick a format, convert, resize or strip anything. Every conversion (HEIC to JPEG on the phone, decoding, orientation, resizing, metadata removal) is automatic and invisible; the owner sees a photo go in and the agent answer.

## What #2146 covers and what it does not

Covered: the Wi-Fi upload path (CH-22 (2)), the intake checks that apply to it (CH-23), delivery (CH-24), storage and erase (CH-26) and the owner texts (CH-27). Not covered: picture texts (CH-22 (1)), which wait on HW-2 qualification of the modem's MMS receive path and bearer and get their own row once HW-2 is met; they reuse CH-photo-a, b, d and e unchanged, adding only the modem fetch and the CH-14 hold. The silent-drop notice for picture texts is the separate fix CH-22 names.

## Design

1. **Upload (CH-photo-c).** A signed-in, unlocked local UI session (CH-3, CH-7) posts one to 10 files and an optional caption to a "Send a photo" page. There is no chat view on the local UI on main (checked: no task-chat handler in `broker/localui`, `localapi` or `localsrv`), so the page stands on its own in the signed-in section; the agent answers by text as for any task chat (CH-15). The file input uses `accept="image/jpeg,image/png,image/heic,image/heif"`; until CH-photo-heic lands it omits the HEIC types, so iPhone Safari hands over JPEG (iOS transcodes HEIC on the phone when the page does not accept HEIC; an assumption c verifies on a device and records). The body is read in memory under `http.MaxBytesReader` (10 x 20 MB plus the caption), never spooled to disk, as `localui/scan.go` does for the vault photo. Types are checked by magic bytes, not by the client's Content-Type.
2. **Confined decode (CH-photo-a).** The broker never decodes in its own process (CH-23). A new static binary `agentos-photo` reads one image on stdin and writes a framed result on stdout: a JSON header (format, width, height), the re-encoded image, and a thumbnail. It checks the pixel count from the header before decoding (refuses over 50 MP), decodes JPEG or PNG with the Go standard library, applies the EXIF orientation, resizes to at most 4096 px on the long side, and encodes a new JPEG (from JPEG) or PNG (from PNG), so no metadata survives by construction. It runs once per photo under runsc with no network, a read-only root holding only the binary, no mounts of broker state, and memory, CPU-time and output caps. The runsc call is a new one-shot method on `vm/gvisor`, so `vm/gvisor` stays the only package that executes runsc (arc2 rule, `TestOnlyRunscIsExecuted`). The broker reads the header and checks the output's magic bytes and dimensions against it; it does not decode the result.
3. **Store (CH-photo-b).** A new `broker/photo` package keeps re-encoded photos by SHA-256 as an OP-11 content store, with receipt, delivery and deletion as journal records, the 200-a-day cap, expiry after the owner-set days (default 30, as CH-19), RES-4 accounting, and deletion as a CAP-3 erase.
4. **Guest delivery (CH-photo-d).** The owner message in `guest/owner.go` gains photo lines (ID, source, time, pixel size) written by the broker. The guest bridge attaches the image as an `image_url` data part only when the guest's declaration says its inbound API takes images (a new `images` field in `guest/openclaw/launch.json`, false until S4 qualifies it), and every guest gets a `photo_read` MCP tool in `guest/mcp.go`. The owner inbox already raises the machine to `private` before handing a message out (`inbox.needsRaise`); photo messages ride that path.
5. **Image routes and wiring (CH-photo-e, integration owner).** `route` forwards an image part only to a route and model the broker records as image-qualified and allowed private content, and only as a `data:` URL; any other image part is refused, never sent. With no such route, the photo is still kept and delivered with its line marked unreadable, and the owner gets the CH-27 text once until a route is added. `agentosd` wires decoder, store, upload, delivery and routes, and owns the lifecycle matrix.
6. **HEIC (CH-photo-heic).** HEIC/HEIF decoding inside `agentos-photo`. Android phones and desktops can hand over HEIC files the browser does not transcode, and CH-23 accepts HEIC; until this lands they get the CH-27 refusal. Candidate: a pure-Go or WebAssembly HEIF decoder (no cgo, so the binary stays static); the dependency choice is the package's first review point.

## Why reuse and not new code

The upload reuses localui's in-memory multipart reading (`scan.go`, `vault.go`); confinement reuses `vm/gvisor`'s runsc arguments, kill and capped-output code; the store reuses the journal and the durable store registry; delivery reuses the owner inbox and its private raise; routes reuse `route`'s existing `image_url` parsing (`route/chat.go`). New code is the decoder binary, the photo store and the glue. Image resizing reuses `golang.org/x/image/draw` (Go project, vendored) rather than a new resampler.

## Order and gates

| Package | Needs | Shared files (D-111) | Estimate |
|---|---|---|---|
| CH-photo-a decoder | none | none (new files, `vm/gvisor`) | 120k |
| CH-photo-b store | a | none (new package) | 120k |
| CH-photo-c upload | b | `broker/localui/*` (open in #2132, #2134) | 110k |
| CH-photo-d delivery | b | `broker/guest/*`, guest bridge | 100k |
| CH-photo-e routes, wiring | b, c, d | `broker/cmd/agentosd/main.go` (open in #2044, #2015), `broker/route/route.go` | 130k |
| CH-photo-heic | a | `broker/cmd/agentos-photo/` | 100k |

**G1 freeze (tools/g1_scope.txt, `freeze on`).** `broker/photo/` and `broker/cmd/agentos-photo/` are not on the allow list, and the freeze check reads the base commit's list, so CH-photo-a and b cannot pass `g1-freeze` until the freeze is lifted or a Mark-merged amend adds them (D-125). The other packages touch listed paths but need a and b first. Photos are not G1 work, so the recommendation is to build after freeze-off.

## Lifecycle matrix (owner: CH-photo-e)

| Stage | Outcome required | Test (in CH-photo-e) |
|---|---|---|
| First boot | Store created empty; upload page works; no photo text sent | `TestPhotoLifecycleFirstBoot` |
| Upload accepted | Decoded, stored, journaled, delivered once; original bytes gone | `TestPhotoLifecycleAccepted` |
| Upload refused (type, size, count, daily cap, decode failure, store full) | Nothing kept in part; one CH-27 text; page shows why | `TestPhotoLifecycleRefused` |
| Restart mid-decode | Stale runsc container killed at boot; no partial file; owner told once | `TestPhotoLifecycleRestartMidDecode` |
| Restart after store, before delivery | Delivered exactly once after boot | `TestPhotoLifecycleRestartUndelivered` |
| Expiry | Deleted by time only on a trusted clock, never early; survives restart | `TestPhotoLifecycleExpiryAfterRestart` |
| Owner erase | CAP-3 erase; confirmation names a running machine that holds a copy | `TestPhotoLifecycleErase` |
| No image route | Kept; delivered marked unreadable; owner told once until a route is added | `TestPhotoLifecycleNoImageRoute` |
| Update and rollback | Store kept across update; after a rollback to before a photo, the store follows OP-11's content-store row | `TestPhotoLifecycleRollback` |

## Assumptions to record (in the packages' ASSUMPTIONS.md)

- iOS Safari transcodes HEIC to JPEG for a file input that does not accept HEIC (c verifies on a device).
- No image-qualified route exists at first (S4 has qualified none), so until one is recorded every photo is delivered as unreadable plus the `photo_read` tool; the feature is visible but useless without such a route (CH-24 [Risk]).
- 50 MP decoding fits the decoder's memory cap at the HW-4 floor (a measures it).
