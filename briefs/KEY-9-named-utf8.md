# KEY-9-named-utf8: owner/kernelsock's Named refuses an invalid-UTF-8 label

Board section: Owner channel and approvals (SPEC §10). Work item #6322 (release item of #6305's Security review, comment 7034524848).

**Problem:** #6305 deleted `kernel/proc`'s test-only `Owner.Named`, the only client that refused a label that is not valid UTF-8. The production client, `broker/owner/kernelsock` `Owner.Named`, sends any label. JSON carries invalid UTF-8 as U+FFFD, so the kernel cannot tell, and the label can match one the owner did not type; an erase by name could then target the wrong subject.

**Requirements:** LOG-4.
1. `kernelsock.Owner.Named` refuses a label that is not valid UTF-8 with `kernel.ErrLabel` (whose words already say "valid UTF-8") before anything is sent.

**Scope:** `broker/owner/kernelsock/kernelsock.go`, a new test file there, `broker/owner/ASSUMPTIONS.md`, this brief.

**Acceptance tests:** `broker/owner/kernelsock`: `TestNamedRefusesInvalidUTF8AndSendsNothing` (three invalid labels against a listening socket give `kernel.ErrLabel`, no result and no connection); catches a client that sends the label.

**Dependencies:** #5732 (merged as #6305).

**Tier / gate:** tier A (owner channel): L3 on the strongest model, lens screen, separate Security accept if `premerge.py --needs-mark` prints `mark`.

**Usage estimate:** one short session, under 60k.
