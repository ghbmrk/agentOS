# P2-2w c4f s2: the booted image shows root project quotas active, and nothing passes -disk-quota off

Board section: P2-2w c4f; work item #1386. From #1302 Security S-R2 (release, narrowed in rounds 2 and 3). PR #1302 set `-Oquota,project` and `rootflags=prjquota` and finish_image.py checks both at build (image/ASSUMPTIONS.md I15). Nothing yet shows the booted box mounting root with project quotas, and nothing stops a later change from passing `-disk-quota off` to make agentosd start on a disk without them.

**Requirements:**
- RES-4: each agent machine writes under its own hard disk quota, enforced by the file system. On the image that needs root mounted with project quotas; agentosd's `-disk-quota on` (its default) keeps machines off otherwise.
- ARC-3: a guest is replaceable and untrusted to the broker, so its disk use is bounded by the file system, not by the guest.

**Acceptance:** A1 (the booted image, through CI's QEMU boot test). **Implementation risk:** tier A. **Needs:** PR #1302 (merged). **Gate:** lenses (security: strongest tier).

## Scope (files)

- `image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service`: pass `-disk-quota on` explicitly.
- `image/mkosi/mkosi.extra/usr/lib/agentos/boot-report`: one more console line, `agentos-quota: ...`, read from the root mount's options.
- `image/ci_boot.sh`: the first boot and the reboot each need `agentos-quota: root=ext4 prjquota`.
- A new `tests/test_image_quota.py`, kept apart from tests/test_image.py (open PRs edit it, D-111).

Not touched, because open PRs own them (D-111): `broker/cmd/agentosd/main.go` (#2081, #2074, #2044, #2015), `image/ASSUMPTIONS.md` (#2036), `image/build.sh` (#2054). The I15 "Check" line in image/ASSUMPTIONS.md gains the boot-test check in a follow-up once #2036 merges.

## What to build

1. **Unit.** agentosd.service passes `-disk-quota on`, so the value the image runs with is the reviewed one, not a default a later main.go change could flip.
2. **Boot report.** After its existing lines, boot-report prints `agentos-quota: root=ext4 prjquota flag=<f>` when `/` is ext4 and its mount options carry `prjquota`, otherwise `agentos-quota: off root=<fstype> flag=<f> (machines stay off)`. `flag=on` only when `systemctl show -P ExecStart agentosd.service` (the command systemd loaded, after every unit path and drop-in) is one command ending `-disk-quota on` and naming disk-quota nowhere else; `overridden` or `unknown` otherwise. One line, one write (I24). The existing first line is unchanged, since test_image.py pins it.
3. **Boot test.** ci_boot.sh needs the quota line with `flag=on` on the first boot and on the reboot.
4. **Guard.** A test fails if any shipped file under image/ passes `-disk-quota off` in any spelling Go's flag package accepts (`-`/`--`, space or `=`, quoted or not).

## Acceptance tests

**Acceptance tests:** RES-4, ARC-3: `tests/test_image_quota.py` (`NoQuotaOffTest`, `BootReportQuotaTest`, `BootTestReadsQuotaTest`), and the image workflow's QEMU boot test (`image/ci_boot.sh`) reading the quota line on both boots.

1. The scanner flags `-disk-quota off`, `--disk-quota=off`, `-disk-quota="off"` and `-disk-quota 'off'` in synthetic text, does not flag `-disk-quota on`, and finds none under image/.
2. Read the way systemd reads it (mkosi.finalize's `config_lines`: indented keys, continuations, comments), agentosd.service has one ExecStart= and no reset, whose words carry no quote, backslash, `%` or bare `$` (so splitting on spaces is systemd's word splitting), whose last argument is `-disk-quota on`, which names disk-quota in no other word, and whose only variable fills `-owner`, a string flag (Go takes the last value, so nothing before it can turn quotas off). It is the only `agentosd.service` under image/, and no `agentosd.service.d/` or `service.d/` drop-in directory ships there. Mutants of each bypass found in review are caught.
3. boot-report, with findmnt stubbed: ext4 with `prjquota` prints `agentos-quota: root=ext4 prjquota flag=on`, and with systemctl stubbed, a second command, a later or earlier disk-quota word, a missing flag or no answer each print another flag; ext4 without it, another file system, and a findmnt that fails each print the off form and never the on form; the first line keeps its exact text.
4. ci_boot.sh checks the on line with `flag=on` on console.log and console-reboot.log.

## Out of scope

Creating an agent machine on the booted image and showing its quota (needs a claimed box and agentosd's machine path; a follow-up of the G1 e2e run); the I15 Check line (above).

## Estimate

About 60k tokens for one session. The figure is a checkpoint, not a cap (docs/OPERATING.md §5).
