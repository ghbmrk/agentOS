# CH12-mms: a picture texted to the box is answered, journaled and counted, never silently dropped

Board row: none; a defect fix on merged code (the P2-3 driver, P2-3w bridge) asked for in the project chat (Mark: "There are many cases where taking a photo and sending it to the box is extremely high leverage"). Class: blocker for CH-12 on the owner line. Tier: A (`broker/modem`, `broker/modemlink`, `broker/journal`, `broker/cmd`). Builder: strongest model. Usage estimate: 120k tokens, checkpoint at 90k. Needs nothing. The photo-input path (fetching and reading the picture) is specced in another thread and builds on this one.

**What happens on main (81e3120).** A picture or file texted to the box arrives as an MMS notice: an SMS-DELIVER with 8-bit TP-DCS, a UDH addressing WAP-push port 2948, and a WSP push whose content type is `application/vnd.wap.mms-message`. `alphabet` (`broker/modem/at/pdu.go`) refuses 8-bit, so `decode` returns `ErrPDU` and `receive` (`broker/modem/at/driver.go`) deletes it and counts it in `Dropped`. The owner hears nothing, STATUS shows nothing and the journal holds nothing, which breaks CH-12's "every text that reports a problem or a wait says what the owner can do" from the owner's side: the picture vanished with no word.

## Requirements (local IDs)

- **CH12-mms-a (recognise the notice).** `DecodeDeliver` reads an 8-bit PDU whose UDH addresses port 2948 (IEI 0x05) and whose WSP push (PDU type 0x06 or 0x07) names the MMS content type (well-known 0x3E, in short or general form, or as the text string) as `Deliver{Picture: true, Push: true}` with no text. A later part (sequence above 1) of a concatenated port-2948 push is `Push` without `Picture`. Any other 8-bit PDU, a port-2948 push of another content type (service indication, provisioning) included, stays `ErrPDU`.
- **CH12-mms-b (the modem never fetches it, and answers only the owner).** `receive` deletes a push as it is read, never keeps it, and never counts it in `Dropped`. A notice delivered once (the `seen` replay guard holds) goes to `Inbox` as `modem.SMS{Picture: true}` with no text, and is counted (`Pictures`). From the owner's number it gets the fixed `PictureText`, GSM-7, one segment, saying what the owner can do, at most once an hour (like `GarbledText`). From any other number, or an alphanumeric sender, it gets no reply, so the box is no oracle for who its owner is. A later part is deleted with no count and no reply. Nothing fetches the MMS.
- **CH12-mms-c (agentosd journals and counts it).** The bridge passes the notice as `bridgeproto.Inbound{Picture: true}` (`Valid` refuses a picture with text). `modemlink` takes it before the owner's rate limit and inbox, counts it once per ID, apart for the owner and for others, and calls `Config.Picture` with whether it came from the owner. agentosd's hook journals a `picture` record (`journal.PictureNote{From: "owner"|"other"}`, no number), and `PictureNote` gives STATUS's exception line while any arrived since start: `Pictures by text: N from you, M from others. Not opened yet.` `journal/check` knows the record type.
- **CH12-mms-d (record).** Update ASSUMPTIONS M2 (`broker/modem/at`) and add the modemlink and journal rows.

**Acceptance tests:**
- CH12-mms-a: `TestMMSNoticeDecodesAsAPicture` (`broker/modem/at/picture_test.go`).
- CH12-mms-b: `TestOwnersPictureGetsOneReplyAnHour` and `TestOthersPictureGetsNoReply` (same file); `TestAPictureTextedToTheBoxReachesAgentosd` (`broker/modem/bridge/bridge_test.go`).
- CH12-mms-c: `TestInboundPictureCarriesNoText` (`broker/bridgeproto/bridgeproto_test.go`); `TestPicturesAreCountedAndJournaledNeverInboxed` (`broker/modemlink/picture_test.go`); `TestPictureNote` (`broker/journal/picture_test.go`); `TestPictureRecordsNameNoIntent` (`broker/journal/check/check_test.go`); `TestPictureJournal` (`broker/cmd/agentosd/picture_test.go`).

Failing-test-first: each acceptance test fails at main; quote one message per ID in the PR.

## Scope

`broker/modem/at/pdu.go`, `broker/modem/at/driver.go`, `broker/modem/at/export_test.go`, `broker/modem/at/picture_test.go`, `broker/modem/at/ASSUMPTIONS.md`, `broker/modem/modem.go`, `broker/modem/bridge/bridge.go`, `broker/modem/bridge/bridge_test.go`, `broker/bridgeproto/bridgeproto.go`, `broker/bridgeproto/bridgeproto_test.go`, `broker/modemlink/modemlink.go`, `broker/modemlink/picture_test.go`, `broker/modemlink/ASSUMPTIONS.md`, `broker/journal/picture.go`, `broker/journal/picture_test.go`, `broker/journal/store.go`, `broker/journal/engine.go`, `broker/journal/ASSUMPTIONS.md`, `broker/journal/check/check.go`, `broker/journal/check/check_test.go`, `broker/cmd/agentosd/main.go`, `broker/cmd/agentosd/picture.go`, `broker/cmd/agentosd/picture_test.go`, `briefs/CH12-mms.md`.

## Out of scope

Fetching the MMS (WSP/HTTP GET of the content location), reading the picture, and pointing the owner at the Wi-Fi page's upload: the photo-input package. When that ships, `PictureText` changes to name where to send the picture. The second line's MMS (it has no owner reply by design).

## Done

CI green; every ID covered by its acceptance tests, which carry `REQ: CH12-mms-a` etc.
