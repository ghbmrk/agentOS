# photo: assumptions

What the photo client (`Decode`, CH-23) rests on.

- **P-1. 512 MiB covers the costliest accepted file.** Measured with the decoder under RLIMIT_DATA: a 50-megapixel baseline JPEG peaked at 134 MiB, a 50-megapixel 16-bit RGBA PNG at 432 MiB. `MemBytes` is 512 MiB; agentos-photo sets Go's soft limit to 448 MiB so the collector works before the cap. A file that needs more is refused as `decode`, not taken.
- **P-2. 80 MiB holds any output.** The re-encoded image is at most 4096 pixels a side; a PNG of noise at that size is about 64 MiB, the thumbnail well under 1 MiB. `MaxOutput` is 80 MiB; a truncated frame is refused as `decode`.
- **P-3. The frame's dimensions are read from the bytes.** The client trusts no field of the header line: it reads each part's width and height from the PNG IHDR or the JPEG SOFn and compares. A decoder that lies is refused (`TestDecodeRejectsLyingHeader`).
- **P-4. A hostile decoder can at most refuse or return a well-formed image.** It runs with no network, a read-only root, no broker state and a deadline (ARC-5); what it returns is a JPEG or PNG within the limits, which downstream code treats as untrusted bytes.
