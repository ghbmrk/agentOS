# SELLER-prep-1: Seller prep for one box: the main-built image on the M6 Ultra's SSD with a sealed claim code, and its sticker

**Owner:** primary lane.
**Priority:** release (G1). **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-10, HW-1
**Acceptance:** A1 (G1: the first M6 Ultra, D-104).
**Dependencies:** CTRL-claim-wire

## Finding

D-105 chose SPEC §8.1's preloaded path for the first M6 Ultra, with the project as the seller for that one box. The box side exists (`broker/claim`, `firstboot.Begin` routes a box holding a claim state to the claim screen; #1067, #1080), but nothing on the seller side writes that state: `claim.Seal` has no caller, and nobody makes the sticker.

## Scope and intended change

`broker/cmd/agentos-seller/` (new), `claim.StatePath` in `broker/claim/`, tests, ASSUMPTIONS.md, this brief and its BOARD row. One box only: no general seller or flasher product (D-104 keeps FLASH-1 and seller-to-others after G1).

- `agentos-seller prep -image agentos_V.raw -sums SHA256SUMS -out DIR`: checks the image against its SHA256SUMS line, finds the root partition with `hostdisk.Probe` (exactly one ext4 volume, the last partition, as `image/mkosi/mkosi.repart/30-root.conf` makes it), copies the image to `DIR/box.raw`, makes a code with `claim.NewCode`, seals it with `claim.Seal` and writes the state into the root file system at `claim.StatePath` (root:root 0600, under 0700 `/var/lib/agentos`) with `debugfs`, reads it back and opens it with `claim.Open` (unclaimed). It writes `DIR/SHA256SUMS` for `box.raw` and the sticker: `DIR/sticker.html` (the code, grouped, and a QR of `http://10.42.0.1/claim?code=CODE` the claim page prefills) and `DIR/sticker.txt`. It refuses an image that already holds a claim state.
- `agentos-seller write -image DIR/box.raw -sums DIR/SHA256SUMS -device /dev/X`: refuses a mounted or too small target, writes, syncs, and read-verifies every byte against the checksum (A1).

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. `prep` on an image whose checksum does not match, whose GPT has no single root ext4 volume, or that already holds a claim state, writes no box image and no sticker (HW-10).
2. After `prep`, the root file system holds exactly one new file, the claim state at `claim.StatePath`, root-owned 0600; `claim.Open` on it reports unclaimed and the sticker's code claims it; the state and the image hold no plaintext code (canary scan, HW-1).
3. The sticker's QR decodes to the claim page with the code; the code appears only in the sticker files, which are 0600.
4. `write` copies the image and read-verifies it; a target that differs after writing, is mounted, or is smaller than the image is refused (A1).

Failure path: the box ships with a claim state the box cannot open (the owner sees "reinstall me"), or a code outside the sticker reaches disk or logs.

Synthetic canaries only. Mark tests with `REQ:` comments.

## Owner checklist (Mark's hands; not code)

1. Take an image built by CI from a push to main (I8, C3) and its `SHA256SUMS`.
2. On a Linux PC with e2fsprogs (`debugfs`): `agentos-seller prep -image agentos_V.raw -sums SHA256SUMS -out box1`.
3. Take the M6 Ultra's M.2 SSD out into a USB enclosure (or boot the box from a Linux live stick), find its device with `lsblk`, and run `sudo agentos-seller write -image box1/box.raw -sums box1/SHA256SUMS -device /dev/sdX`.
4. Refit the SSD. Print `box1/sticker.html` at 100% and stick it on the box.
5. Delete `box1/` (`sticker.*` holds the code) once the sticker is on the box.

## Handoff and estimate

Initial checkpoint: 90k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split `write` into its own row and say so on BOARD.md.
