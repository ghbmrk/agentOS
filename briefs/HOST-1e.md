# HOST-1e: Host-untouched acceptance check

Board section: Backlog refill (2026-10-05).

Host-untouched acceptance check (A1, HW-8): a harness that hashes each internal disk raw before first boot and after task, restart, and shutdown, and diffs the RTC, persistent UEFI variables, and TPM NV indices against HW-8's list; runs in CI on a QEMU/OVMF/swtpm host with a Windows-like second disk, and on each S1 PC

**Needs:** HOST-1a, HOST-1b

**Gate:** skip (test)

**State on the board before the 2026-10-08 index split:** queued

**Part 1 (this package):** `tools/hostcheck.py` (snapshot, diff, qemu) with HW-8's list as rules (`tools/hostcheck_hw8.json`, pinned to `broker/hostchange`), the stand-in guest and Windows-like disk (`tools/hostcheck_standin.sh`), and the `hostcheck` CI job: two firmware-only boots for baseline and UEFI noise, then task and restart+shutdown phases, each with disk hashes, the OVMF varstore, the swtpm state and QMP `RTC_CHANGE` events; planted disk, UEFI, NV and RTC writes are flagged.

**Part 2 (HOST-1e2, needs P2-1):** a phases file for P2-1's image (`--image`, USB drive) run in CI; the S1 PC procedure (`snapshot --efivarfs` and `--tcti` from a third system, RTC offset against reference time); the pcrlock index if P2-1 pins one; HOST-1d's opted-in disk excluded by the owner's flag.
