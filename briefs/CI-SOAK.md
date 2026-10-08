# CI-SOAK: Unattended soak workflow

Board section: Backlog refill (2026-10-05).

Unattended soak workflow (`.github/workflows/soak.yml`): native Go fuzzing of 13 untrusted-input parsers (4 existing Fuzz funcs plus 9 minimal no-panic ones: owner reply, control, loops settings, mail, update attestation, recovery key, tpmseal, hint, attest), 3h each by default (up to 5h), at most 6 at once; a two-shard race/shuffle soak of the whole broker (`-race`, `-race -cpu 1`) for about 4.5h; a failing run uploads crashers and logs and opens or appends one "Soak failures" issue. Runs on dispatch and daily at 02:17Z. No mutation-testing tool is in the repo, so none is added

**Needs:** —

**Gate:** tooling

**State on the board before the 2026-10-08 index split:** in review
