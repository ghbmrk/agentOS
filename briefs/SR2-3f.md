# SR2-3f: Worker tools answer no raw vm error

Board section: Backlog refill (2026-10-05).

Worker tools answer no raw vm error (security R1 on #174, K20): one filter at the `workers` boundary keeps the known sentinels' fixed text (`ErrQuota`, `WorkerFull`, `ErrBusy`, `ErrState`, ...) and turns anything else into a fixed code with the detail in the broker's log; a test that no worker tool error names a host path

**Needs:** CAP-8c

**Gate:** security check

**State on the board before the 2026-10-08 index split:** in review (recall thread)
