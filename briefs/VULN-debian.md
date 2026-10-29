# VULN-debian: drop the image packages still behind unfixed Debian advisories

Board section: Harness and operating model. Work item #2919; SPEC EVL-5. Tier A (`image/`). Release class. Written 2026-10-29 against main 1a375683.

## Why

The image scan (`tools/vulncheck.py image`, EVL-5) accepts every Debian 13 advisory with no fix through a record in `assurance/vulncheck.json` (`where: "image"`, issue #2919). Slices a to c (#2970, #2975, #2980) and the later drops (#3120, the NetworkManager and polkitd removals #3387 and #3440) took the image from 199 records to **75 across 18 sources** (main's `image-vulncheck` job on run 40921953987, 2026-10-29: "240 findings, 0 failing"; 240 counts each binary package per advisory). The curl family, duktape, glib, gnutls, p11-kit and the Wi-Fi stack went with NetworkManager, so the issue's original candidate list is spent. This brief says which of the 18 sources can still go, and why the rest stay.

## What main shows

- `image/mkosi/drop.py` purges packages with `dpkg --force-depends` (Essential ones in a second call with `--force-remove-essential`), removes `FILES` that link them, then fails the build if any ELF file under `usr` names a library a dropped package shipped (`needed_violations`) or a script's `#!` names a dropped program (`interpreter_violations`). `mkosi.postinst` runs it before copying dpkg's status file for the scan, so the scan sees the drop.
- `tests/test_image_drop.py::WiringTest::test_no_record_accepts_a_dropped_source` fails while a dropped source keeps a record. CI's scan fails on an unused record and on an unaccepted finding, so deleting a source's records and passing `image-vulncheck` proves the source is gone, both ways.
- `libtirpc3t64` is already dropped (only `ss` linked it). Nothing else the image keeps links krb5.
- `iproute2` stays. `boot-report` line 17 runs `ip -4 -o addr`, and `broker/e2e/boxe2e/main_linux.go:160-166` runs `ip netns add`, `ip link add … type veth`, `ip addr add` and `ip -n … link set` inside the booted image (the end-to-end setup run, #1688; `image/ci_boot.sh:15-17`). `ip` and `tc` link `libelf1t64`, directly and through `libbpf1`, so elfutils stays with it (L3 fix-list item 1 on #3892, comment 6505104470).
- Every script in `mkosi.extra/usr/lib/agentos` is `#!/bin/sh` (11 of them). agentosd and `provagent` run `sh -c`. trixie's `dpkg -L dash` lists both `/usr/bin/dash` and `/usr/bin/sh`.

## The 18 sources

| Source | Records | Kept by | Verdict |
|---|---|---|---|
| krb5 | 6 | nothing since libtirpc went (it was `libtirpc3t64`'s Depends) | **drop, part a** |
| dash | 2 | `/bin/sh` (Essential) | **drop, part b**: `/usr/bin/sh` becomes a link to bash, which is already on the box with no records |
| elfutils | 7 | `iproute2` (`ip`, `tc`, and `libbpf1`), which boxe2e's veth and netns harness and `boot-report` run | keep; see Unowned gaps |
| popt | 3 | `cryptsetup-bin` (`veritysetup`, run by `health` and the TN-drill verify in `reboot-weekly`) | keep; see Unowned gaps |
| expat | 5 | `dbus-daemon` (dbus-broker links it too) | keep: systemd's services need a system bus |
| iptables | 1 | `libnftables1` links `libxtables12` | keep: nftables is the inbound drop |
| lvm2 | 1 | `libdevmapper1.02.1` (libcryptsetup, so dm-verity), which depends on `dmsetup` | keep |
| ncurses | 2 | `libtinfo6` (bash), `ncurses-bin` (Essential) | keep: the record stays while `libtinfo6` does |
| shim | 1 | deliberate, comment 6380056417 (dropping `shim-unsigned` would hide the signed shim's advisory) | keep |
| glibc 21, systemd 7, util-linux 6, coreutils 4, pam 2, gcc-14 2, zlib 2, acl 2, attr 1 | 47 | the base system | keep |

That makes **8 of 75 records removable** (part a 6, part b 2), leaving 67.

**Not verified here:** the krb5 reverse dependencies come from Debian trixie's package metadata as known to this brief's author. This session could not reach `deb.debian.org`, `snapshot.debian.org` or the CI artifacts (the proxy refuses them). The build is the check. If `needed_violations` names a file that still links a dropped library, the builder records what pulled it in on the issue, and that source moves to "keep" with that reason. A dropped source's records are deleted only once a build proves it gone. The L3 review ran part b's order in a `debian:trixie` container (comment 6505104470).

## Part a: krb5 (6 records)

1. `drop.py` `DROP`: `libgssapi-krb5-2`, `libkrb5-3`, `libk5crypto3`, `libkrb5support0` (source `krb5`, why: "only libtirpc3t64 linked it, and that is dropped"). Add `libkeyutils1` if krb5 was its only user (no records; it is less code on the box).
2. `assurance/vulncheck.json`: delete the six `krb5` records.

## Part b: dash (2 records)

1. `drop.py`, in this order, which the L3 review proved in a trixie container:
   1. Divert and relink: `dpkg-divert --local --no-rename --divert /usr/bin/sh.distrib --add /usr/bin/sh`, then make `usr/bin/sh` a link to `bash` (bash runs as POSIX `sh` when called by that name). Run `dpkg-divert` with `--root` on the image tree, or in a chroot, whichever `drop.py`'s existing dpkg calls use.
   2. Purge `dash` in **its own call** (`--force-depends --force-remove-essential`), **before** the existing tar, diffutils and perl-base call. dash's `postrm` and debianutils' trigger are `#!/bin/sh`, so `sh` must resolve when they run. debconf's purge step needs perl, so perl-base must still be there.
   3. Then the existing `ESSENTIAL` call, unchanged.
   Any other order the builder uses must be proven the same way: every dpkg call exits 0, and dash and the three Essentials end `not-installed`.
2. `drop.py`'s `#!` check: dash's file list includes `/usr/bin/sh`, so `programs(...)` puts it among the gone programs, and every `#!/bin/sh` script would fail the build. Remove `/usr/bin/sh` (and `/bin/sh`) from the gone programs once step 1 has relinked it to bash. `/usr/bin/dash` stays gone.
3. `assurance/vulncheck.json`: delete the two `dash` records.
4. Boot e2e: every `/usr/lib/agentos` script, boxe2e and the provagent `sh -c` lines now run under bash. CI's boot test (`ci_boot.sh`), the drill reboot and the end-to-end run are the proof. `tests/test_image.py` runs the scripts with the host's `sh`, so it does not prove bash-as-sh. If a script relies on dash behaviour, fix the script; do not keep dash.

Part b is its own PR, so a bash-as-sh surprise cannot hold part a back.

**Acceptance tests:**
- EVL-5, part a: `tests/test_image_drop.py::NeededTest::test_krb5_goes_with_tirpc` (the four krb5 packages are in `DROP` with source `krb5`, and `main` purges them). It catches a regression that re-adds a krb5 user.
- EVL-5, both parts: `tests/test_image_drop.py::WiringTest::test_no_record_accepts_a_dropped_source` (existing), and the `image-vulncheck` job green with the records deleted. This catches a record left for a source that is gone, or deleted for a source still present.
- EVL-5, part b: `tests/test_image_drop.py::NeededTest::test_dash_goes_and_sh_is_bash`. dash is purged in a call of its own, after the divert and relink and before the `ESSENTIAL` call, with the call order asserted on the recorded dpkg invocations. After `main`, `usr/bin/sh` points to `bash`. This catches a wrong order, which fails dash's `postrm`, and a dangling `/bin/sh`.
- EVL-5, part b: `tests/test_image_drop.py::InterpreterTest::test_sh_scripts_pass_once_sh_is_bash`. With dash dropped and `sh` relinked, a `#!/bin/sh` script passes and a `#!/bin/dash` one fails. This catches the check flagging every shell script, or letting a dash-only script through.
- EVL-5, part b: the image workflow's boot test, drill reboot and end-to-end run, green. These catch a script or boxe2e step that breaks under bash-as-sh.

**Guard files:** none (no broker package).

## Scope

- Part a: `image/mkosi/drop.py`, `tests/test_image_drop.py`, `assurance/vulncheck.json`.
- Part b: `image/mkosi/drop.py`, `tests/test_image_drop.py`, `assurance/vulncheck.json`, and any `image/mkosi/mkosi.extra/usr/lib/agentos/*` script the boot e2e shows depends on dash.
- D-111: both parts touch `image/mkosi/` and `assurance/vulncheck.json`, so they join the image queue behind the open image PRs (#3880, #3867 when this was written). Part b starts after part a merges.

## Unowned gaps (not in a or b)

- **elfutils (7 records), `later`.** It goes only with `iproute2`. That would need boxe2e's veth and netns harness rewritten on rtnetlink through `golang.org/x/sys/unix` (no netlink library is vendored), with tests, and `boot-report` reading the lease another way, such as `ADDRESS=` in `/run/systemd/netif/leases/<ifindex>`. 7 records do not pay for a netlink rewrite of test-only code (L3 recommendation, comment 6505104470).
- **popt (3 records), `later` tagged `recheck`.** `cryptsetup-bin` could go if `health` read the verity state from `dmsetup` (lvm2, which stays anyway) and the TN-drill's `veritysetup verify` became a full read of `/dev/mapper/usr` through the kernel's verity target. That changes what the drill attests. A userspace check of the on-disk tree against `usrhash=` is stronger than the kernel's read path: blocks can come from the page cache, and the hash blocks for unread data are never checked. So it is a design change to TN-drill (UPD-10), not a drop. File it as its own row only if TN-drill's reviewers agree the read-through check is equivalent.
- **expat (5).** It goes only with a bus-less systemd, which no supported configuration offers.

## Estimate

Part a: about 30k tokens and one image CI round (about 45 minutes). Part b: about 50k and one or two rounds. Two sessions. Usage is the builder's to record on the PR.
