# IMG-2: Reproducible initrd, blocking two-runner check

Board section: Backlog refill (2026-10-05).

Make the initrd reproducible, then make the two-runner initrd comparison in `image.yml` blocking (F4 on #41; today it is report-only) (UPD-1a, OSS-8)

**Needs:** P2-1

**Gate:** skip (tooling)

**State on the board before the 2026-10-08 index split:** queued

## Scope

`image/build.sh`, `image/mkosi/mkosi.conf`, `image/compare_manifests.py`, `.github/workflows/image.yml` (the initrd step around the report-only warning), `image/ASSUMPTIONS.md`. Tier A. Shares `image.yml` and `image/` with IMG-1, IMG-3, IMG-4: start one at a time.
