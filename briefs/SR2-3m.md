# SR2-3m: A runsc panic after the guest starts reaches no guest output

Board section: Backlog refill (2026-10-05).

A runsc panic after the guest starts reaches no guest output (release finding 362-1, Security on #362): a Go runtime panic in `runsc exec` after the guest started writes its trace to stderr with no `--log` line, so the guest reads it as its command's stderr. When runsc exits 2 and stderr's tail has Go's `goroutine N [` frame header after a `panic:` line, treat it as runsc's failure: no output, a ref. A guest that mimics it loses only its own output. Test with a fake runsc that prints a canary host path in a panic trailer.

**Needs:** RES-4, CAP-8, SR2-3h

**Gate:** security check (strongest tier: executor path)
