# SR2-3n: No runsc crash trace reaches the guest, and the guest cannot pick the logged part

Board section: Backlog refill (2026-10-05).

A guest's interleaved writes cannot hide a runsc panic (Security S2 on #391, from LATER SR2-3m f1). SR2-3m finds runsc's Go panic by a `panic:` or `fatal error:` marker followed by a `goroutine N [` header on stderr. The Go runtime writes the marker, the message and the header as separate writes, and the guest shares that stderr, so a guest writing in between can split the marker or the header. The trace is then not found, and runsc's text, which names host paths, reaches the guest as its own stderr. The fix must work without timing the guest's writes against a panic it does not control. For example, when runsc exits 2, look for the marker and the header each on their own, tolerating guest bytes inside and between them, and give no output when both are present, accepting that a guest which mimics them loses its own output. Test with the fake runsc writing guest bytes inside the marker, between the marker and the header, and inside the header, each with a canary host path in the trace.

Two more findings from the same review (Security on #391, B1 of its delta L3) belong to this package:

- **Signal form (S3).** A Go fatal signal prints `SIGxxx: …` and `PC=… m=… sigcode=…` with neither `panic:` nor `fatal error:`, then the `goroutine N [` header, and exits 2. SR2-3m does not detect it, so the trace reaches the guest. Detect that form too, with a canary test in the fake runsc. The preferred fix for this and the split case is to give the guest a stderr apart from runsc's fd 2, if runsc allows it; marker matching is then only a fallback.
- **Logged start (S4).** The exec log keeps the text from the *first* marker, so a guest that writes `panic: ` and 16 KiB of filler leaves only its own text in the log and pushes runsc's real trace out (L3 point 1 on #391). Nothing reaches the guest, but the operator loses the diagnosis. Keep the text from the marker that precedes the header found, or the last 16 KiB, and test that the real trace stays in `exec.log` after guest filler.

**Needs:** SR2-3m

**Gate:** security check (strongest tier: executor path)
