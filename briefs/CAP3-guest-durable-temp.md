# CAP3-guest-durable-temp: sweep crash-left `.durable-*` temps next to guest-inbox.json

Board section: Harness and operating model. Work item: #2373. Follow-up of PR #2367 Security review (comment 6250950877). **Tier A** (`broker/cmd/agentosd`, `broker/guest`).

**Why.** A crash between `durable.WriteFile`'s temp write and its rename leaves a `.durable-*` file holding the guest outbox, reply text included. No caller of `durable.SweepTemp` (`broker/durable/durable.go:215`) covers the `-guest-inbox` directory. Failure path: the owner forgets a guest's replies (CAP-3, DEL-1-f1a); the deletion reports done because `guest-inbox.json` is clean, while a temp from an earlier crash still holds the text.

**Requirements:**
- CAP3-T1: at agentosd start, before the guest store opens, the directory of the `-guest-inbox` path is swept with `durable.SweepTemp`, only when no other process can be writing there (SweepTemp's doc).
- CAP3-T2: if that directory is shared with stores that already sweep, one sweep at start is safe for all of them (the builder states the check in the PR).

**Acceptance tests:** (REQ: CAP3-T1, CAP3-T2)
- `broker/cmd/agentosd/guestinbox_sweep_test.go::TestStartSweepsGuestInboxTemps`: a `durable.TempPrefix` file with a synthetic canary sits beside the inbox path; after the start-up path opens the guest store the file is gone and the canary is in no file of the directory (mutant: skip the sweep).
- `::TestStartSweepKeepsInboxAndNeighbours`: `guest-inbox.json` and a non-temp neighbour stay (mutant: sweep by wrong prefix).

**Out of scope.** The write path of `durable`; other stores' sweeps.

**Scope:** `broker/cmd/agentosd` start-up and its test, `broker/guest` only if the sweep belongs in its open, this brief.

**Usage estimate:** 40k tokens.
