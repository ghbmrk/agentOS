# HOST-1e: Host-untouched acceptance check

Board section: Backlog refill (2026-10-05).

Host-untouched acceptance check (A1, HW-8): a harness that hashes each internal disk raw before first boot and after task, restart, and shutdown, and diffs the RTC, persistent UEFI variables, and TPM NV indices against HW-8's list; runs in CI on a QEMU/OVMF/swtpm host with a Windows-like second disk, and on each S1 PC

**Needs:** HOST-1a, HOST-1b

**Gate:** skip (test)

**State on the board before the 2026-10-08 index split:** queued
