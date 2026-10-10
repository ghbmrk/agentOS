# SR2-3i: Image side of SR2-3

Board section: Backlog refill (2026-10-05).

Image side of SR2-3 (RES-4): the P2-1 image puts the broker's machine state on a file system mounted `prjquota` (or on its own volume, so snapshot copies are off the journal's disk too) and runs `agentosd` with `-disk-quota=on`; a boot check fails closed if quotas are off, and quotas off is an owner-visible health item (security R2 on #152). The kernel must carry the quota format for the chosen file system (ext4 needs `quota_v2`; XFS has its own). Until the volume split, `snapshots/` stays on the state disk, held to the reserve by admission (vm V19a), not by the file system

**Needs:** SR2-3, P2-1

**Gate:** security check

**State on the board before the 2026-10-08 index split:** in review (recall thread): broker part (STATUS line; `overlay.Measure` by handles, security R4 on #166); the image part (security M1-M3) goes with #41, builder F
