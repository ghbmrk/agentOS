# CH-photo-e: image routes, owner texts and daemon wiring (integration owner)

Board section: Backlog refill (2026-10-17). Part of CH-photo-upload (briefs/CH-photo-upload.md), work item #2146; SPEC CH-24, CH-26, CH-27, REV-6, CAP-9, CH-12. Tier A. **Integration owner** for the photo path: owns the lifecycle matrix in the parent brief.

**Needs:** CH-photo-b, c, d. **Gate:** #2044 and #2015 merged (both touch `broker/cmd/agentosd/main.go`, D-111); lenses L3 and Security.

## Change

1. **Image-qualified routes.** `route` records, per route and model, whether it is qualified to read images (an `ImagesOK` set beside `PrivateOK`, filled by `agentosd` from the qualification record; empty until S4 qualifies one). A chat request carrying an `image_url` part goes only to a route that is image-qualified and allowed private content (REV-6, CAP-9), and only with a `data:` URL; any other image part is refused with an error, never forwarded or silently dropped. This also closes today's gap: `route/chat.go` accepts `image_url` parts for every route. Only `route/route.go` and `route/chat.go` change; the adapters' own files stay frozen (G1).
2. **No image route.** When no allowed route reads images, the store marks the photo unreadable, the guest's line says `unreadable`, and the owner gets the fixed text "I got your photo, but none of your models can look at photos yet. Add one on my Wi-Fi page." once, until such a route is added (journaled flag).
3. **Owner texts (CH-27).** The refusal text "I couldn't use the file you sent at 14:03. I take JPEG, PNG or HEIC photos up to 20 MB." with the upload's local time, GSM-7, one segment, owner class `update`, for every refusal reason; a test checks both texts are one GSM-7 segment.
4. **Wiring.** `agentosd` builds the decoder runner, the store, the localapi photo calls, the guest delivery and the route sets, runs the boot sweep (stale decode containers, expiry), and passes the store's erase to the forget path.

**Acceptance tests:**
- CH-24 / REV-6 (image routes): `TestImagePartOnlyToImageRoute`, `TestImagePartRefusedOnNonPrivateRoute`, `TestImagePartOnlyDataURL` (`broker/route/images_test.go`).
- CH-24 / CH-27 (no route): `TestNoImageRouteMarksUnreadable`, `TestNoImageRouteToldOnce`.
- CH-27 / CH-12 (fixed texts): `TestPhotoTextsOneSegment`, `TestRefusalTextNamesTime`.
- Lifecycle matrix (parent brief): `TestPhotoLifecycleFirstBoot`, `TestPhotoLifecycleAccepted`, `TestPhotoLifecycleRefused`, `TestPhotoLifecycleRestartMidDecode`, `TestPhotoLifecycleRestartUndelivered`, `TestPhotoLifecycleExpiryAfterRestart`, `TestPhotoLifecycleErase`, `TestPhotoLifecycleNoImageRoute`, `TestPhotoLifecycleRollback` (`broker/cmd/agentosd/photo_test.go`).

Failure path: a private photo goes to a hosted route the owner did not allow private content, or a route that cannot read images receives one and the agent answers as if it had.

**Guard files:** `broker/daemon/arc2_test.go` (add `photo` to `cmd/agentosd`'s allowed imports).

## Scope

`broker/route/route.go`, `broker/route/chat.go` and new tests, `broker/cmd/agentosd/` (wiring, `photo_test.go`, ASSUMPTIONS.md), `broker/photo/` (unreadable flag), `broker/daemon/arc2_test.go`.

## Estimate

One session, about 130k tokens, strongest model.
