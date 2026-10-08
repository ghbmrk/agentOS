# SR2-3n: A guest's interleaved writes cannot hide a runsc panic

Board section: Backlog refill (2026-10-05).

A guest's interleaved writes cannot hide a runsc panic (Security S2 on #391, from LATER SR2-3m f1). SR2-3m finds runsc's Go panic by a `panic:` or `fatal error:` marker followed by a `goroutine N [` header on stderr. The Go runtime writes the marker, the message and the header as separate writes, and the guest shares that stderr, so a guest writing in between can split the marker or the header. The trace is then not found, and runsc's text, which names host paths, reaches the guest as its own stderr. The fix must work without timing the guest's writes against a panic it does not control. For example, when runsc exits 2, look for the marker and the header each on their own, tolerating guest bytes inside and between them, and give no output when both are present, accepting that a guest which mimics them loses its own output. Test with the fake runsc writing guest bytes inside the marker, between the marker and the header, and inside the header, each with a canary host path in the trace.

**Needs:** SR2-3m

**Gate:** security check (strongest tier: executor path)
