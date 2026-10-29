# VULN-debian: drop the image packages still behind unfixed Debian advisories

Board section: Harness and operating model. Work item #2919; SPEC EVL-5. Tier A (`image/`). Release class. Written 2026-10-29 against main 1a375683.

## Why

The image scan (`tools/vulncheck.py image`, EVL-5) accepts every Debian 13 advisory with no fix through a record in `assurance/vulncheck.json` (`where: "image"`, issue #2919). Slices a to c (#2970, #2975, #2980) and the later drops (#3120, the NetworkManager and polkitd removals #3387 and #3440) took the image from 199 records to **75 across 18 sources** (main's `image-vulncheck` job on run 40921953987, 2026-10-29: "240 findings, 0 failing"; 240 counts each binary package per advisory). The curl family, duktape, glib, gnutls, p11-kit and the Wi-Fi stack went with NetworkManager, so the issue's original candidate list is spent. This brief says which of the 18 sources can still go, and why the rest stay.

## What main shows

- `image/mkosi/drop.py` purges packages with `dpkg --force-depends` (Essential ones in a second call with `--force-remove-essential`), removes `FILES` that link them, then fails the build if any ELF file under `usr` names a library a dropped package shipped (`needed_violations`) or a script's `#!` names a dropped program (`interpreter_violations`). `mkosi.postinst` runs it before copying dpkg's status file for the scan, so the scan sees the drop.
- `tests/test_image_drop.py::WiringTest::test_no_record_accepts_a_dropped_source` fails while a dropped source keeps a record. CI's scan fails on an unused record and on an unaccepted finding, so deleting a source's records and passing `image-vulncheck` proves the source is gone, both ways.
- `libtirpc3t64` is already dropped (only `ss` linked it). Nothing else the image keeps links krb5.
- `iproute2` is in `mkosi.conf` `Packages=`. Its one use on the box is `boot-report` line 17 (`ip -4 -o addr show dev <if> scope global`). Nothing in `broker/` or `cmd/` runs `ip` or `tc` on the box (the hits are `image/camnode/e2e` and `broker/enforcer/nft/netns_test.go`, both on the CI host). `ip` and `tc` link `libelf1t64`, directly and through `libbpf1`.
- Every script in `mkosi.extra/usr/lib/agentos` is `#!/bin/sh` (11 of them). agentosd and `provagent` run `sh -c`.

## The 18 sources

| Source | Records | Kept by | Verdict |
|---|---|---|---|
| krb5 | 6 | nothing since libtirpc went (it was `libtirpc3t64`'s Depends) | **drop, part a** |
| elfutils | 7 | `iproute2` (`ip`, `tc`, and `libbpf1`) | **drop with iproute2, part a** |
| dash | 2 | `/bin/sh` (Essential) | **drop, part b**: `/usr/bin/sh` becomes a link to bash, which is already on the box with no records |
| popt | 3 | `cryptsetup-bin` (`veritysetup`, run by `health` and the TN-drill verify in `reboot-weekly`) | keep (see Unowned gaps) |
| expat | 5 | `dbus-daemon` (dbus-broker links it too) | keep: systemd's services need a system bus |
| iptables | 1 | `libnftables1` links `libxtables12` | keep: nftables is the inbound drop |
| lvm2 | 1 | `libdevmapper1.02.1` (libcryptsetup, so dm-verity), which depends on `dmsetup` | keep |
| ncurses | 2 | `libtinfo6` (bash), `ncurses-bin` (Essential) | keep: the record stays while `libtinfo6` does |
| shim | 1 | deliberate, comment 6380056417 (dropping `shim-unsigned` would hide the signed shim's advisory) | keep |
| glibc 21, systemd 7, util-linux 6, coreutils 4, pam 2, gcc-14 2, zlib 2, acl 2, attr 1 | 47 | the base system | keep |

That makes **15 of 75 records removable** (part a 13, part b 2), leaving 60.

**Not verified here:** reverse dependencies come from Debian trixie's package metadata as known to this brief's author. This session could not reach `deb.debian.org`, `snapshot.debian.org` or the CI artifacts (the proxy refuses them). The build is the check. If `needed_violations` names a file that still links a dropped library, or apt still installs `iproute2` as someone's Depends, the builder records what pulled it in on the issue, and that source moves to "keep" with that reason. A dropped source's records are deleted only once a build proves it gone.

## Part a: krb5 and elfutils (13 records)

1. `drop.py` `DROP`: `libgssapi-krb5-2`, `libkrb5-3`, `libk5crypto3`, `libkrb5support0` (source `krb5`, why: "only libtirpc3t64 linked it, and that is dropped"). Add `libkeyutils1` if krb5 was its only user (no records; it is less code on the box).
2. `mkosi.conf`: remove `iproute2` from `Packages=`. If apt still installs it, `libbpf1` or `libelf1t64`, purge them through `DROP` instead and name what depended on them.
3. `boot-report`: read the leased address without `ip`. Recommended: `networkctl status <if>` (systemd, already on the box), whose first `Address:` value is the IPv4 lease. Keep the line's shape `agentos-uplink: <if> <address>`. If the new source loses the `/prefix`, change `image/ci_boot.sh`'s `lease=` regex (line 327) to `[0-9.]+(/[0-9]+)?`, and its `10.0.2.15/` match (line 331) to match the address followed by `/` or a space.
4. `assurance/vulncheck.json`: delete the 13 `krb5` and `elfutils` records.
5. `image/ASSUMPTIONS.md`: in I19's and I21's hardware test plans, change `ip route` and `ip -6 addr` to their `networkctl status` equivalents. No other words change.

## Part b: dash (2 records)

1. `drop.py`: add `dash` to `DROP` and `ESSENTIAL`, and after the purge make `usr/bin/sh` a link to `bash` (bash runs as POSIX `sh` when called by that name). A test proves the link exists after `main`, and that the `#!` check accepts `/bin/sh` scripts because bash ships the target.
2. `assurance/vulncheck.json`: delete the two `dash` records.
3. Boot e2e: every `/usr/lib/agentos` script and the provagent `sh -c` lines now run under bash. CI's boot test (`ci_boot.sh`), the drill reboot and the end-to-end run are the proof. `tests/test_image.py` runs the scripts with the host's `sh`, so it does not prove bash-as-sh. If a script relies on dash behaviour, fix the script; do not keep dash.

Part b is its own PR, so a bash-as-sh surprise cannot hold part a back.

**Acceptance tests:**
- EVL-5, part a: `tests/test_image_drop.py::NeededTest::test_krb5_goes_with_tirpc` (the four krb5 packages are in `DROP` with source `krb5`, and `main` purges them). It catches a regression that re-adds a krb5 user.
- EVL-5, part a: `tests/test_image.py::test_iproute2_is_not_installed` (new; `mkosi.conf`'s `Packages=` has no `iproute2`, and `boot-report` runs no `ip`). It catches a script that calls a program the image no longer ships.
- EVL-5, part a: `tests/test_image.py::test_boot_report_shows_the_wired_lease` and `::test_boot_report_waits_briefly_without_a_cable`, with the `ip` stub replaced by a `networkctl` stub that prints the real output shape (copied from systemd 257's `networkctl status` on the CI boot's console). This catches a parser that misses the lease.
- EVL-5, both parts: `tests/test_image_drop.py::WiringTest::test_no_record_accepts_a_dropped_source` (existing), and the `image-vulncheck` job green with the records deleted. This catches a record left for a source that is gone, or deleted for a source still present.
- EVL-5, part b: `tests/test_image_drop.py::NeededTest::test_dash_goes_and_sh_is_bash` (dash in `DROP` and `ESSENTIAL`; after `main`, `usr/bin/sh` points to `bash`). The image workflow's boot test and end-to-end run, green, prove the runtime side. Together they catch a `/bin/sh` left dangling.

**Guard files:** none (no broker package).

## Scope

- Part a: `image/mkosi/drop.py`, `image/mkosi/mkosi.conf`, `image/mkosi/mkosi.extra/usr/lib/agentos/boot-report`, `image/ci_boot.sh`, `image/ASSUMPTIONS.md` (I19 and I21 test-plan words only), `tests/test_image_drop.py`, `tests/test_image.py` (the boot-report tests and one new test), `assurance/vulncheck.json`.
- Part b: `image/mkosi/drop.py`, `tests/test_image_drop.py`, `assurance/vulncheck.json`.
- D-111: both parts touch `image/mkosi/` and `assurance/vulncheck.json`, so they join the image queue behind the open image PRs (#3880, #3867 when this was written). Part b starts after part a merges.

## Unowned gaps (not in a or b)

- **popt (3 records), `later` tagged `recheck`.** `cryptsetup-bin` could go if `health` read the verity state from `dmsetup` (lvm2, which stays anyway) and the TN-drill's `veritysetup verify` became a full read of `/dev/mapper/usr` through the kernel's verity target. That changes what the drill attests, which a userspace check of the on-disk tree against `usrhash=` does better than the kernel's read path: blocks are served from the page cache, and hash blocks for unread data are never checked. So it is a design change to TN-drill (UPD-10), not a drop. File it as its own row only if the reviewers of TN-drill agree the read-through check is equivalent.
- **expat (5).** It goes only with a bus-less systemd, which no supported configuration offers.

## Estimate

Part a: about 60k tokens and two image CI rounds (about 45 minutes each). Part b: about 30k and one round. Two sessions. Usage is the builder's to record on the PR.
