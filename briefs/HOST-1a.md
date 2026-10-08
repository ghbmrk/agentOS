# HOST-1a: No host disk is mounted or used

Board section: Backlog refill (2026-10-05).

No host disk is mounted or used (HW-8): udev rules and image config so internal disks are never auto-mounted, never swap, and are invisible to services, agent machines, and executors; read-only partition-table and volume-signature probe for the HW-8a disk list, opening no file system. Test in a VM with a second virtual disk. **Part 1 (this package):** `broker/hostdisk` read-only, bounded, fuzzed probe; drive found from the running root, cross-checked with systemd-boot; disk list with bus and removable flags and no labels or GUIDs; udev rules (`broker/hostdisk/udev/` 59, 64, 72) with drive/host/unknown classes; root-only `cmd/agentos-hostdisk` helper ([assumptions](../broker/hostdisk/ASSUMPTIONS.md); lens conditions Security H1-H7, Potency C1, R1, R2). **Part 2, for P2-1 (#41 or its follow-up):** install the three rules and helper, fstab and gpt-auto kept to the drive, `DevicePolicy=closed` or `PrivateDevices=yes` on every root unit with an image test listing each unit's policy, no mdadm, lvm2 or bcache in the initrd (or only with the helper and rules), the health item, and the VM test with a second internal disk plus a USB disk (H11); update and restore read USB drives through their own root-only read-only path (H12); also pin `bsg` and NVMe controller nodes root-only in the 72 file (Security, optional, on #172)

**Needs:** P2-1 image

**Gate:** lenses

**State on the board before the 2026-10-08 index split:** part 1 merged (#172); part 2 queued on P2-1
