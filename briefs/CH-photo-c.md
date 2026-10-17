# CH-photo-c: "Send a photo" on the Wi-Fi page

Board section: Backlog refill (2026-10-17). Part of CH-photo-upload (briefs/CH-photo-upload.md), work item #2146; SPEC CH-22 (2), CH-23, CH-25, CH-26, CH-27, CH-3, CH-7. Tier A.

**Needs:** CH-photo-b. **Gate:** #2132 and #2134 merged (both touch `broker/localui`, D-111); lenses L3, Security and UX.

## Change

1. **Page.** In the signed-in section (CH-7 sign-in, unlocked session per CH-3), a "Send a photo" page: a file input (`multiple`, `accept="image/jpeg,image/png"`, plus `image/heic,image/heif` once CH-photo-heic lands), an optional caption, and a Send button. Mark's direction: the owner never chooses or sees a format or conversion; the accept list is what makes iPhone Safari transcode HEIC to JPEG on the phone. No `capture` attribute, so the phone offers both camera and library. The page says once, in plain words, not to send photos of the Owner Card (CH-25). There is no chat view on the local UI on main; the page stands alone and the agent answers by text (CH-15).
2. **Intake.** The handler reads the multipart body in memory under `http.MaxBytesReader` (10 x 20 MB plus 4 KB of caption), never to a temporary file (as `scan.go`), checks each part's magic bytes, and passes the files to the daemon through `localapi`; the daemon calls `photo.Decode` then the store. Refusals (type, size, count, daily cap, decode, store full) keep nothing and show the reason on the page; the CH-27 text goes to the owner's phone as well. The caption is task chat only, never a control word or a code (CH-23, CH-25).
3. **List.** A photos page listing each kept photo with its thumbnail, ID, the task it went to and its expiry, with Delete and Delete all (each a CAP-3 erase through the store; the confirmation lists a running machine that holds a copy and any backup).

**Acceptance tests:**
- CH-22 / CH-3 (signed-in, unlocked only): `TestPhotoUploadNeedsSignIn`, `TestPhotoUploadNeedsUnlocked` (`broker/localui/photo_test.go`).
- CH-23 (owner-only intake, types, limits, in memory): `TestPhotoUploadSniffsType` (a PNG named `.jpg` with Content-Type `image/gif` is judged by bytes), `TestPhotoUploadElevenRefused`, `TestPhotoUploadOver20MBRefused`, `TestPhotoUploadNoTempFile`.
- CH-25 (caption is task chat, not a control): `TestPhotoCaptionNotControlWord` (caption "STOP" and "YES 4821" pass as task chat).
- CH-26 (list and delete): `TestPhotoListShowsExpiry`, `TestPhotoDeleteAll`.
- CH-27 (page shows what was sent and why not): `TestPhotoPageShowsIDs`, `TestPhotoRefusalText` (the fixed text with the upload's time).
- UX: `TestPhotoPageAcceptList` (the accept attribute omits HEIC until CH-photo-heic and never offers a format choice).

Failure path: someone on the box's Wi-Fi without a sign-in gets a photo to the agent, or a large upload fills the drive with a temporary file.

**Guard files:** none (no new package).

## Scope

`broker/localui/` (new `photo.go`, its page templates, tests, ASSUMPTIONS.md rows), `broker/localapi/` (the photo calls), their ASSUMPTIONS.md.

## Estimate

One session, about 110k tokens, strongest model. Record on a real iPhone (or note as unverified) that a HEIC library photo arrives as JPEG.
