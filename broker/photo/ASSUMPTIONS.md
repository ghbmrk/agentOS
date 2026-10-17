# photo: assumptions

What the photo client (`Decode`, CH-23) rests on.

- **P-1. 512 MiB covers the costliest accepted file.** Measured with the decoder's own peak: a 50-megapixel baseline JPEG at 134 MiB, a 50-megapixel 16-bit RGBA PNG at 432 MiB. `MemBytes` is 512 MiB and is the cgroup cap of the whole sandbox, which adds about 18 MiB of its own (gvisor V-photo-1); a progressive or CMYK 50-megapixel JPEG can need 750 to 950 MiB and is refused as `decode` until CH-photo-b revisits the cap; agentos-photo sets Go's soft limit to 448 MiB so the collector works before the cap. A file that needs more is refused as `decode`, not taken.
- **P-2. 80 MiB holds any output.** The re-encoded image is at most 4096 pixels a side; a PNG of noise at that size is about 64 MiB, the thumbnail well under 1 MiB. `MaxOutput` is 80 MiB; a truncated frame is refused as `decode`.
- **P-3. The frame's dimensions are read from the bytes.** The client trusts no field of the header line: it reads each part's width and height from the PNG IHDR or the JPEG SOFn and compares. A decoder that lies is refused (`TestDecodeRejectsLyingHeader`).
- **P-4. A hostile decoder can at most refuse or return a well-formed image.** It runs with no network, a read-only root, no broker state, a memory cap and a deadline (ARC-5); what it returns is a JPEG or PNG within the limits, which downstream code treats as untrusted bytes.

What the photo store (`Store`, CH-photo-b) rests on.

- **P-5. A receipt is a journal lifecycle, kind `photo.keep.`, not `photo.`.** The brief named `photo.` for keep, deliver and delete, but a lifecycle has one daily cap over every action under its kind, so deliveries and deletions would use up the 200 receipts. It is irreversible (a receipt is not undone, it is deleted), bound by the photo ID and hash, capped at 200 a day per box by `Lifecycle.DailyCount` in the box's time zone. A deleted or delivered photo still counts, so deleting frees no place that day. Delivery (`photo.deliver`) and deletion (`photo.delete`) are plain intents outside the lifecycle, so neither counts toward the cap.
- **P-6. The listing is a fold of the journal.** No index file exists beside the journal (OP-11); the bytes are content named by hash in `Dir`, and `Open` removes any file no live photo or unsettled receipt names.
- **P-7. The image's rename is the commit.** The thumbnail is renamed first, then the image; a crash before the image lands is reconciled as not applied and the thumbnail removed unless another photo holds the same hash.
- **P-8. Expiry is fixed at receipt.** It is the received time plus the owner's days setting read then; changing the setting later does not move a kept photo's expiry. The received time is the trusted clock's latest reading, or the box clock while it is untrusted.
- **P-9. Nothing expires on an untrusted clock.** The sweep reads the clock's earliest bound, and only when it is verified and not restricted, so no photo goes early (CH-26).
- **P-10. Same bytes are kept once.** Two photos with the same image share one file; a deletion removes the bytes only when no other live photo or unsettled receipt names the hash (the `last` param, fixed when the delete is submitted).
- **P-11. Hashes survive the journal's redactor.** A 64-hex-digit SHA-256 is assumed not to match a secret pattern; if a redactor ever scrubbed it, the store could not find a photo's bytes and would list it as corrupt, never serve other bytes.
- **P-12. Photo IDs are never reused.** The next ID is one past the highest ever submitted, erased ones included, since erasure keeps intent IDs.
