# IMG-exec-channels-2: the rest of the boot-code channels are held to exec.allow

A release finding from #2140's reviews, filed as #2176 (it supersedes #2151). SPEC rows: DEV-2, CH-9. Class release, tier A.

**Why one package.** One allowlist in `image/mkosi/mkosi.finalize` (#1556's `exec.allow`), widened to more directories, plus its tests and I21; about 250 lines.

**Today.** `exec.allow` holds udev rules, system and environment generators and `modules-load.d` to whole-file hashes. Other channels still run root code at boot and pass the tree check:
- `modprobe.d` `install <mod> <cmd>` runs a root shell whenever the module loads (libkmod, for systemd-modules-load and udev's kmod builtin). The check reads only the Bluetooth install lines.
- `sysctl.d` `kernel.modprobe=` and `kernel.hotplug=` set the kernel's usermode and uevent helpers. The check reads only the forwarding keys and `core_pattern`.
- `binfmt.d` registers interpreters the kernel runs for matching files.
- `systemd/system-shutdown` and `systemd/system-sleep` hold programs that systemd-shutdown and systemd-sleep run as root.
- The pinned `systemd-sysv-generator` and `systemd-rc-local-generator` turn `/etc/init.d/*`, `/etc/rc?.d` and `/etc/rc.local`, none of which are checked, into boot units.
- `TMPFILES_TARGETS` leaves out `udev/rules.d`, `modules-load.d`, `system-environment-generators` and their `/run` forms, so a tmpfiles line could plant a file there at boot.

**Requirement IMG-exec-channels-2.** No file in these channels ships unless it is listed:
- **The channels:** `modprobe.d` (`*.conf`, listed as kmod 34 lists it), `sysctl.d` (`*.conf`), `binfmt.d` (`*.conf`), `systemd/system-shutdown` and `systemd/system-sleep` (any name).
  - Each joins `EXEC_CHANNELS` under `etc`, `usr/local/lib`, `usr/lib` and `lib`, the same as #1556's channels.
  - Each file must be on `exec.allow` with its hash, or the build fails with the entry to review.
  - Anything under the same directories in `/run` is refused.
  - This is a superset of what each reader reads: systemd 257 runs shutdown and sleep hooks only from `/usr/lib/systemd/`.
- **Why hash all of `sysctl.d`:** whole-file hashes are the default over refusing `kernel.modprobe` and `kernel.hotplug` by name. A list of refused keys is a denylist. It would also need systemd-sysctl's key normalisation and globbing again, where a hash parses nothing. The existing forwarding and `core_pattern` key checks still run on top.
- **The two generators are removed** (`RemoveFiles=` in `mkosi.conf`), not their inputs hashed.
  - With them gone, nothing turns `/etc/init.d`, `/etc/rc?.d` or `/etc/rc.local` into units, so those inputs need no parser or link model (the `rc?.d` entries are links).
  - Removing them is safe because every service the image runs has a native unit: the image's own units, and each listed package's native unit.
  - `exec.allow` drops their entries. A build where either comes back fails, because it is not listed, and a test pins that neither is listed.
- **`TMPFILES_TARGETS`** gains every `EXEC_CHANNELS` directory, under each top and `/run`, and `/etc/modules`, which kmod's `modules-load.d/modules.conf` link reads.
- **I21** names what stays outside the model.

| ID | Test | Why it fails without the check |
|---|---|---|
| IMG-exec-channels-2 | `ExecAllowTest` (tests/test_image.py): #2176's failure paths each fail `check.violations` unless listed. Those are an `install tun` line running sysctl, `kernel.modprobe=`, a `binfmt.d` file, a shutdown hook and a sleep hook. A shipped sysv or rc-local generator fails too. `/run` forms are refused. The repository's `exec.allow` lists the image's own `modprobe.d` and `sysctl.d` files by hash and neither generator. `TmpfilesTest`: an `L` or `C` line into each new channel directory fails. | Without the new channels every such file passes; without the new targets the tmpfiles line passes the guarded-path check. |

**Acceptance tests:** ExecAllowTest, TmpfilesTest (tests/test_image.py)

**Controls that must keep passing.** All of tests/test_image.py and the image workflow's tree check on both builds. The CI boot (`ci_boot.sh`) shows the image still boots without the two generators.

**Threat check.** The attacker is a package update or an `mkosi.extra` edit that adds or changes code that runs as root at boot (DEV-2, CH-9; #2176's failure paths). Recurring kinds from the security lens that this must not repeat:
- a guard that fails open on a missing or unreadable value: a missing list, an unreadable file and a refused directory all fail;
- a check that follows a planted link: everything is read through `Conf`;
- a denylist where an allowlist fits: whole-file hashes.

**Out of scope, named in I21.**
- The programs a udev `RUN+=` or a unit `Exec` line names. They are ordinary package files, like every other binary.
- `depmod`'s `modules.softdep` and `modules.alias` under `/lib/modules`. These are kernel data: they load modules but run no commands.
- User generators.
- The initrd (IMG-2).

**Scope:**
- `image/mkosi/mkosi.finalize`
- `image/mkosi/exec.allow`
- `image/mkosi/mkosi.conf`
- `tests/test_image.py`
- `image/ASSUMPTIONS.md`
- `image/README.md`
- this brief

**Usage estimate:** 150k tokens, checkpoint at 150k. Builder model: strongest (tier A).
