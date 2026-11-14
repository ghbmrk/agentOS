# IMG-keeper-reach-gen-doc: image/ASSUMPTIONS.md records the partition pin and the extra-unit/fstab.extra routes

Board section: Defects and later findings on surviving packages. Work item #5417 (release, D-250), from #5289 (IMG-keeper-reach-gen), raised by its builder; L3 6787023917 on the ESP point. Tier A (the issue's tier).

## The gap

#5289 added checks in `image/finish_image.py` that keep systemd's generators from adding units or mounts the tree check never reads, and `tests/test_image_gen.py` holds them. `image/ASSUMPTIONS.md` does not say why each pin is there.

- **Failure path:** a later change drops a partition-type pin or a credential refusal, and no assumption row says why it was there.

## What the rows must say

1. **I21** (the tree check's row): the built disk holds exactly `mkosi.repart`'s partitions, in order, and the repart definitions (`mkosi.repart` and `/usr/lib/repart.d`) name only `esp`, `usr`, `usr-verity` and `root` (`finish_image.partition_violations`), so systemd-gpt-auto-generator finds only the ESP and root; `/usr/lib/repart.d` is mkosi.extra's files byte for byte through plain directories only (`usr_repart_violations`, the /usr step check); the root partition's `/etc` and `/run` hold no `repart.d` (`root_repart_violations`).
2. **I21**: the command-line credential rule also stops `systemd.extra-unit.*` (debug-generator adds the unit) and `fstab.extra` (fstab-generator adds the mount), not only `sysctl.extra` and `tmpfiles.extra`; the ESP allowlist refuses every credential file whichever loader reads it: systemd-boot reads `loader/credentials/*.cred` for Type #1 entries too, not only systemd-stub (L3 6787023917).
3. **I22**: firmware credentials accepted include `systemd.extra-unit.*` and `fstab.extra` beside `sysctl.extra` and `tmpfiles.extra`.

## Scope

`image/ASSUMPTIONS.md` and this brief. No code.

**Requirement IDs:** STO-2, DEV-2, CH-9 (those `tests/test_image_gen.py` claims).

**Guard files:** none.

**Acceptance tests:** none: a documentation row. The invariant it explains is held by `tests/test_image_gen.py` (`CredentialRouteTest`, the partition tests), unchanged.
