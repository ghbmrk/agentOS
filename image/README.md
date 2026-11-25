# agentOS device image (P2-1)

The image that goes on the drive: Debian 13 packages, `/usr` read-only on dm-verity in A/B slots,
booted by Microsoft-signed shim, Debian-signed systemd-boot and kernel (S7), with boot counting.
It carries the broker (`agentosd`), gVisor's `runsc`, and the OpenClaw guest image.

Build with image.yml's own split (IMG-mkosi-run-bound, D-276; #6161, #6348): `build.sh` runs as root on one
host and the pinned mkosi on another where `build.sh` never ran, so the repository's root code cannot reach
mkosi, its config or its binary. Each host needs a checkout of the same commit with no changed, untracked or
ignored file, a user who can sudo, and network to the Debian mirrors (cloud agent sessions have none; CI does).
The stage host need not last: a disposable VM, thrown away once the tar is copied out, is a valid stage host.
Each half marks its host before it starts (`/var/lib/agentos-stage-host`, `/var/lib/agentos-build-host`) and
refuses a host holding the other's mark, so one host never plays both; a mark that cannot be read as root
stops the run. The marks hold an honest operator to the split: root code on a host (`build.sh` on the stage
host) can delete them.

The SHA-256 the stage prints binds the tar in transit only: it proves the build host got the bytes the stage
host packed, not that a hostile stage host packed an honest `/usr`.

On the build host, nothing a non-root process can write is read as root: after its checks the build copies
the commit and the tar into a root-only directory that `mktemp` makes in `/var/lib` (the commit's objects into
root's own repository there, checked against their ids, then checked out with no config or attributes of the
caller's, and refused unless the copy is exactly the commit's tree), and runs every later step there as root
with root's own `PATH`, so the tar hashed is the tar unpacked and the tree checked is the tree mkosi reads.
The image then moves to `DIR/out`.

1. On the stage host, with `build.sh`'s tools (image.yml's "Install staging tools" step):
   `image/local-build.sh stage DIR` marks the host as one that staged (`/var/lib/agentos-stage-host`), runs
   `image/build.sh` as image.yml's stage job does, packs the stage as `DIR/stage-COMMIT.tar` and prints the
   build command with the tar's SHA-256.
2. On the build host, which never staged, with the pinned mkosi v24.3 in `/opt/mkosi` (image.yml's
   "Install build and boot tools" step; the wrapper refuses any other commit, and any changed, untracked or
   ignored file there): `image/local-build.sh build TAR SHA256 DIR [VERSION]` refuses the tar's root-only
   copy if its content is not the SHA-256 the stage printed, holds it to `stage/usr`, `agentos.sources`,
   `guest/` and `linked/`, then runs the one line image.yml's "Build image" step runs:
   `sudo env "PATH=$PATH" HOME=/root "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" /opt/mkosi/bin/mkosi -C image/mkosi -f --package-manager-tree="$OUT/pkgmngr" --image-version="$VERSION" --environment=AGENTOS_SECURITY_SNAPSHOT="$AGENTOS_SECURITY_SNAPSHOT" --extra-tree="$OUT/stage/usr:/usr" --output-dir "$OUT" build`,
   and `image/finish.sh`. The image is in `DIR/out`.

`DIR` must not exist; relative paths are the caller's. Each half names its log on exit: `DIR/stage.log`, and
`DIR/build.log` once the image is out. A build that fails keeps its root-only directory for reading and names
it on exit, with the log if mkosi ran (a check before mkosi writes none), and the `sudo rm -rf` that removes it.
A checkout with changes or untracked files is refused, as CI builds only commits.
`VERSION` defaults to the commit time and may hold only `0-9 A-Z a-z . + _ -`. `AGENTOS_SECURITY_SNAPSHOT`,
if set on both hosts, is the run's snapshot; unset, `build.sh` resolves one and the build host resolves the
set it must be in, later, so the two can differ: the build then refuses and names the fix, setting it on both
hosts to one of the build host's (`sh image/security-snapshot.sh resolve` prints them) and staging again. `tests/test_image.py` holds each of the wrapper's steps line for line equal to image.yml's;
CI never runs the wrapper. CI: `.github/workflows/image.yml` stages on two runners, builds
each on a fresh runner that never runs `build.sh`, boots one build under Secure Boot in QEMU, and
compares the releases.

| Path | What |
|---|---|
| `build.sh` | Stages the broker, runsc and guests into `OUT/stage`; never runs mkosi |
| `local-build.sh` | Local only: image.yml's stage and build halves, one per host, each step held line for line equal to image.yml's |
| `finish.sh` | After mkosi: finishes the release, copies out the initrds, writes SHA256SUMS |
| `mkosi/mkosi.conf` | Packages, boot chain, pinned snapshot, seed |
| `mkosi/mkosi.repart/` | Disk layout: ESP, `/usr` A and B with verity, root last |
| `mkosi/mkosi.finalize` | Fails the build on per-install state or socket files (HW-1, V15), a tree that could dump the broker's memory, load Bluetooth, turn Wi-Fi on (D-178), forward, tell the LAN about the box, link configuration where the build cannot see it or let another user write it, link anything into a world-writable directory, any tmpfiles.d line not on `tmpfiles.allow` (#1543), and any udev rule, generator or modules-load.d file not on `exec.allow` (#1556), and an agentos unit, fstab line or mount unit that lets writable storage execute (UPD-10); each refusal is a line of the build log |
| `mkosi/mkosi.postinst` | Copies dpkg's status file and os-release to OUT as `agentos.dpkg-status` and `agentos.os-release`, for image.yml's known-vulnerability scan (`tools/vulncheck.py image`, EVL-5), and dpkg's md5sums as `agentos.dpkg-md5sums`, for `unit_rules.py` |
| `mkosi/tmpfiles.allow` | Every tmpfiles.d line the image may ship; `mkosi.finalize` fails the build on any other (#1543) |
| `mkosi/exec.allow` | Every udev rules file, generator, modules-load.d, modprobe.d, sysctl.d and binfmt.d file, and systemd shutdown and sleep hook, the image may ship, by its SHA-256; `mkosi.finalize` fails the build on any other (#1556, #2176) |
| `mkosi/mkosi.extra/` | Health check gating boot-complete, boot report, broker unit, root growth, the noexec `etc/fstab` and `/tmp` drop-in, the weekly reboot (`agentos-reboot.timer`, UPD-10) and its monthly restore drill (`agentos-drill-report.service`, #2932) |
| `finish_image.py` | Counted boot entry, `/usr` verified against the entry's `usrhash=`, release manifest, the `/usr` list read back from the verified partition (#4059); fails the release on a private key or Owner Card anywhere on the disk outside `/usr` slot A (HW-1, IMG-1-1) |
| `compare_manifests.py` | The reproduce job's comparison of two builds of one commit: package manifests, initrds member by member (`--initrd`, IMG-2) and `/usr` lists path by path (`--usr`), differences only in time or link count last (#4059, #4471) |
| `ci_boot.sh` | QEMU boot with OVMF Secure Boot and swtpm; checks health, blessing, root growth, the wired lease and the inbound drop, and that a host disk attached on the first boot comes out unchanged (ONB-2, IMG-1-1) |
| `unit_rules.py` | Boots the built image's own systemd in a container namespace and prints, for each unit it loads (`systemctl show`), the files it applies in systemd's order and whose they are (ours, or byte-identical to a package's); image.yml holds them to the root-side unit rules (`broker/kernel/privfile`, `TestBuiltUnits`, #4677) |
| `probe_inbound.py` | Probes box ports through QEMU's host forwards for `ci_boot.sh`: dropped, answered or error |

Outputs in OUT: `agentos_V.raw` (the drive), `agentos_V.usr.raw` and `.usr-verity.raw` (the
release's `/usr`), `agentos_V.usr.list` (every `/usr` path's type, mode, owner, mtime, link count, size and hash or link target), `agentos_V+3.conf` (its boot entry), `agentos_V.release.json`, the package
manifest, the dpkg status and os-release the vulnerability scan reads, dpkg's md5sums, and `SHA256SUMS`. Write the `.raw` to a drive with `dd` or any image writer.

Assumptions and gaps: [ASSUMPTIONS.md](ASSUMPTIONS.md).
