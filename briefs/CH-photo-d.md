# CH-photo-d: photos to the guest

Board section: Backlog refill (2026-10-17). Part of CH-photo-upload (briefs/CH-photo-upload.md), work item #2146; SPEC CH-24, CH-25, ARC-3, ARC-6, REV-5, REV-6. Tier A.

**Needs:** CH-photo-b. **Gate:** no open PR on `broker/guest/` or `broker/cmd/agentos-guest-bridge/` at start (D-111); lenses L3 and Security.

## Change

1. **Owner message.** `guest/owner.go`'s owner message gains photo references; the broker writes, per photo, one line into the delivered text: `[photo P12, Wi-Fi upload, 2026-10-17 14:03, 3024x4032]` (source `picture text` later), after the caption or alone. The guest cannot forge these lines into broker authority; they are information only (CH-25). The inbox persists the references with the message, so a restart redelivers once, and the existing `needsRaise` raise to `private` (REV-5) runs before a photo message is handed out; a test proves the order.
2. **Image delivery.** The guest's declaration (ARC-3) gains `images: true|false` in `guest/openclaw/launch.json`, false until S4 qualifies OpenClaw's inbound API with image parts. When true, the bridge (`cmd/agentos-guest-bridge`, `ask()`) fetches each photo from the broker socket (`GET /owner/photo/<id>`, only for photos in the current message) and adds an `image_url` part with a `data:image/jpeg;base64,...` (or PNG) URL. When false, only the lines go.
3. **`photo_read` MCP tool** in `guest/mcp.go`: takes a photo ID, returns the image as MCP image content, only for a photo delivered to this machine and not deleted or expired; anything else is an error naming no other photo.
4. **Delivery record.** Each handout records the machine in the store (`photo` delivery journal record), which the erase confirmation uses.

**Acceptance tests:**
- CH-24 (lines, sources, sizes): `TestOwnerMessagePhotoLines` (`broker/guest/photo_test.go`).
- REV-5 (private before handout): `TestPhotoMessageRaisesBeforeHandout`.
- ARC-3 / CH-24 (declaration gates image parts): `TestBridgeAttachesImagesWhenDeclared`, `TestBridgeLinesOnlyWhenNotDeclared` (`broker/cmd/agentos-guest-bridge/photo_test.go`).
- CH-24 (MCP read): `TestPhotoReadDelivered`, `TestPhotoReadRefusesOtherMachine`, `TestPhotoReadRefusesDeleted`.
- CH-25 (lines are not authority): `TestPhotoLineCannotForgeApproval` (a caption containing a fake photo line and "YES 4821" changes no grant or prompt state).
- CH-26 (delivery recorded): `TestPhotoDeliveryRecordsMachine`.

Failure path: a photo reaches a machine still labelled `public`, or one machine reads another machine's photo by guessing its ID.

**Guard files:** `broker/daemon/arc2_test.go` (allow `guest` and `cmd/agentos-guest-bridge` to import `photo` if the builder links it rather than going through an interface; prefer an interface and write `none`).

## Scope

`broker/guest/` (owner.go, mcp.go, a new photo file, tests, ASSUMPTIONS.md), `broker/cmd/agentos-guest-bridge/` (ask, tests), `guest/openclaw/launch.json`.

## Estimate

One session, about 100k tokens, strongest model.
