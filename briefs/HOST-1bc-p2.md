# HOST-1bc-p2: Time sync that leaves the hardware clock alone, and no token or TPM key on the host

Board section: Defects and later findings on surviving packages. Work items #954 (HOST-1b part 2) and #955 (HOST-1c part 2), built as one package because both change the same files (`image/mkosi/mkosi.conf`, the preset, `tests/test_image.py`) and D-111 would run them one after the other anyway. SPEC HW-8 (the hardware-clock sentence and the disclosed-change list), TIM-1, A1. Tier A (`image/`): strongest-model builder, L3, lens screens and the separate Security accept. Written 2026-10-29 against main fb95c8e0, from the pre-migration triage (`dispatch/2026-10-29-pre-migration-triage.md` §4).

## Why

Part 1 of each row merged in October (#177 the clock guard, #183 the owner's guide). What is left is the image side.

- **HOST-1b.** The image ships no time service at all: `tests/test_image.py::test_nothing_writes_the_hardware_clock` pins `systemd-timesyncd` absent, and `mkosi.conf` has no `chrony`. So nothing writes the RTC today only because nothing syncs, and TIM-1 ("time comes from network time when online") is unmet. `broker/clock/chrony/chrony.conf` (NTS first, no `rtcsync`, `cmdport 0`) and `broker/cmd/agentos-clock-boot` exist but are not in the image. K14 in `broker/clock/ASSUMPTIONS.md` lists what the image owes.
- **HOST-1c.** HW-8 lists systemd-boot's `LoaderSystemToken` "unless the image turns it off" and a persistent storage root key. The image does neither on purpose, yet the guide (`docs/owners-guide.md` lines 20 and 21), `broker/hostchange.All` and `tools/hostcheck_hw8.json` disclose both, so HOST-1e's diff would pass either write silently.

## What main shows (checked against systemd v257 source, which trixie ships)

- `systemd-boot-random-seed.service` runs `bootctl --graceful random-seed`. That writes `loader/random-seed` on the ESP and then `set_system_token()` writes the non-volatile `LoaderSystemToken` once per PC, unless `$SYSTEMD_WRITE_SYSTEM_TOKEN` is false (`src/bootctl/bootctl-random-seed.c`). systemd-boot itself only reads the token (`src/boot/random-seed.c`). Its own non-volatile writes (`LoaderEntryDefault`, `LoaderConfigTimeout`, `LoaderConfigConsoleMode`, `OsIndications`) happen only when someone presses keys in its menu.
- `systemd-tpm2-setup.service` and `systemd-tpm2-setup-early.service` make the persistent SRK. Both have `ConditionSecurity=measured-uki`, and the image boots type-1 entries with the Debian kernel, not a UKI, so they should not run. That is a condition, not a pin.
- The keeper's TPM code (`broker/tpmseal`) uses a transient SRK (comment in `broker/hostchange/hostchange.go`).
- agentosd keeps the clock state at `/var/lib/agentos/clock.json` (`cmd/agentosd/questions.go::defaultQuestionConfig`). Polkit is gone (#3387), so timedated already answers root only.
- `tools/hostcheck.py` already reads QEMU's `RTC_CHANGE` events (`guest_rtc_writes`). `image/ci_boot.sh` boots with a user-mode NIC (guest lease 10.0.2.15, runner at 10.0.2.2), OVMF and swtpm.

## Design points settled here (flagged for the reviews)

1. **The rule covers the whole image, not just stick boots.** HW-8's scope leaves out the controller, but a recovery stick is "any USB stick flashed with the image" (§3), so the same units run on a host PC. One rule (never write the RTC, no token, no SRK) is simpler than a controller-only branch, and on the controller it costs only clock accuracy before the first sync, which K12's learned offset covers.
2. **chrony, configured as shipped.** Install `chrony`. `/etc/chrony/chrony.conf` is byte-equal to `broker/clock/chrony/chrony.conf`. No `rtcsync`, `rtcfile`, `rtcautotrim` or `hwclockfile` anywhere in chrony's config tree (including `conf.d`/`sources.d`). Without `rtcsync`, chronyd leaves `STA_UNSYNC` set, and the kernel's 11-minute RTC update runs only while it is clear (`kernel/time/ntp.c`, `sync_hw_clock`).
3. **Masks, not conditions.** Mask `systemd-timedated.service`, `systemd-boot-random-seed.service`, `systemd-tpm2-setup.service` and `systemd-tpm2-setup-early.service` (in the initrd too, if it carries them), as links to `/dev/null`, which `mkosi.finalize` already accepts. Masking the random-seed service drops the ESP seed file as well. The kernel still seeds from the EFI RNG protocol, RDRAND and the TPM hwrng. Record that in `image/ASSUMPTIONS.md`. `$SYSTEMD_WRITE_SYSTEM_TOKEN=0` is the fallback only if a mask breaks the boot.
4. **No hwclock.** No `usr/sbin/hwclock`, no `util-linux-extra`, and no udev rule that runs hwclock (`85-hwclock.rules`). `drop.py` and `mkosi.finalize` refuse them if a dependency pulls them in.
5. **`agentos-clock-boot.service` and O1.** `cmd/agentos-clock-boot` opens the state file once with `O_NOFOLLOW`, checks owner and mode with `fstat` on that descriptor, and reads from it (Security #177 O1). `clock.BootEstimate` gets the bytes or the descriptor, not the path; that is the only `broker/clock` Go change. O2 (capping how far a plain sync can raise the floor) stays on #954 with the TIM-1 port.
   The unit is a oneshot with `After=local-fs.target` and `Before=chronyd.service`, enabled in the preset. It runs `ExecStart=/usr/lib/agentos/agentos-clock-boot -state /var/lib/agentos/clock.json` (the path agentosd writes). The build makes the binary like the other `cmd/` tools. The properties it must have, whatever flags give them: it can set the system clock and read sysfs and its state file, and nothing else. That means no network, no device node (`DevicePolicy=closed`, since it reads the RTC through sysfs `since_epoch`), no write anywhere, no capability but `CAP_SYS_TIME`, and the UPD-10 `NoExecPaths=/` and `ExecPaths=/usr`. It never fails the boot, as its code already ensures.
6. **Who writes the offset.** agentosd is the old core's broker (frozen, D-139). It learns the offset today, and the kernel's port takes that over later. This package does not touch `cmd/agentosd` (serial chain, D-111) and changes no clock-guard logic.
7. **Disclosure list shrinks.** Remove `loader-system-token` and `tpm-srk` from `broker/hostchange.All`, their two items from `docs/owners-guide.md`, and their rules from `tools/hostcheck_hw8.json`. Then HOST-1e's diff flags either write as a defect instead of passing it. HW-8 makes both items conditional ("unless the image turns it off"; "if the TPM holds none"). Neither is left out of SPEC's list in error: the image no longer makes them. A spec-diff that drops them from HW-8's text is a `later` item.
8. **Egress.** chronyd needs UDP 123 and TCP 4460 out. If the box's output rules refuse them, that is a TIM-1 finding against the egress port. Do not edit old-core `broker/egress`. Report it on the PR's Findings line.

## Not in this package (left on the rows as part 3)

- **#955: the owner's recovery-key answer** (HW-8: "when the owner asks the box about it, the box answers in plain words from the owner's guide"). `broker/owner` is agentosd's v0.12 owner channel, which the kernel replaces. In v1.0, an owner's question is answered in the planner conversation (CH-21). Recommendation: when the kernel's owner conversation is ported, give the planner the guide's "If Windows asks for a recovery key" section as fixed reference text. A test then asks about a recovery-key prompt and checks the reply against `hostchange.RecoveryPromptHeading`'s section. #955 stays queued on that port.
- **#954: K15, O2 and the #163 carry.** The wording for codes refused while the clock is unverified, phone-attested time on the Wi-Fi page, and pubid counting days only on a verified clock all live in the kernel's code and owner paths, so they stay on #954, waiting on those ports.
- **Unowned gap (a `later` issue for the builder to open):** the keeper's NV indices (`broker/tpmseal/pins.go`) are not on HW-8's list. Enrollment runs only in controller setup, so this matters only if a stick ever enrolls. HOST-1e2's `--image` run is where that gets checked.
- HOST-1e2 (the full host diff of the image on QEMU and on S1 PCs) stays its own row. This package adds only the cheap in-boot checks below.

## Lifecycle matrix (integration owner: this package)

| Stage | Expected |
|---|---|
| First boot, any PC, network up | clock-boot finds no offset and does nothing; chronyd syncs; no RTC write; no `LoaderSystemToken`; no persistent SRK |
| First boot, no network | clock stays unverified (K11), boot proceeds, no RTC write |
| Reboot on the same PC | clock-boot applies the learned offset (if agentosd learned one), chronyd syncs, no RTC write |
| Same drive on another PC | offset not used (HostKey mismatch), as on first boot |
| A/B update or fallback boot | same units, same masks: nothing new written |

## Acceptance tests

**Acceptance tests:**
- HW-8 clock, static: `tests/test_image.py::test_nothing_writes_the_hardware_clock` extended. It checks: chrony is in `Packages`; the shipped `/etc/chrony/chrony.conf` equals `broker/clock/chrony/chrony.conf`; no `rtcsync|rtcfile|rtcautotrim|hwclockfile` in the built chrony config tree; timesyncd absent; timedated masked; no `hwclock` binary or `85-hwclock.rules`. It catches a package update or a conf drop-in that turns the 11-minute update back on.
- HW-8 clock, O1: `broker/cmd/agentos-clock-boot/main_test.go::TestStateLinkIsNotFollowed` plants a symlink to a root-owned 0600 file and expects no clock change, and `::TestStateCheckedOnTheDescriptorItReads` swaps the file between the check and the read (via a test hook) and expects the check to match the bytes that were read. It catches a check-then-read race.
- HW-8 clock, unit: `::test_clock_boot_runs_before_chronyd` checks the unit's ordering, `-state /var/lib/agentos/clock.json`, `CapabilityBoundingSet=CAP_SYS_TIME`, `DevicePolicy=closed`, no network, UPD-10 settings, and that the preset enables it. It catches the boot estimate landing after chronyd or with extra power.
- HW-8 clock, VM (K14), in `image/ci_boot.sh`. QEMU runs with `-rtc base=localtime` and a QMP socket. A CI-only drop-in points chronyd at a plain NTP server the runner serves on 10.0.2.2, so CI does not depend on the internet. The checks: chronyd reports a sync, then at least 11 minutes of guest uptime pass after it, then the reboot boot runs, and QMP shows zero `RTC_CHANGE` events from OS start to the end of the run (reuse `tools/hostcheck.py::guest_rtc_writes`). The same boot checks that `/dev/rtc0` is root 0600, that `/run/chrony` and chronyd's socket are reachable only by root and `_chrony`, and that the state file, if present, is root-owned 0600. It catches a kernel or chrony that copies synced time into the RTC. If the wait adds more than 8 minutes to the image job, overlap it with the first boot's other checks and say so in the PR.
- HW-8 token and SRK, static: `::test_no_system_token_or_persistent_srk` checks that the random-seed service and both tpm2-setup units are masked (in the initrd too, if present) and that no unit or script runs `bootctl` with `random-seed`, `install` or `update` at runtime. It catches a package update that brings the units back.
- HW-8 token, VM: `ci_boot.sh` checks after each boot that `/sys/firmware/efi/efivars/LoaderSystemToken-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f` does not exist. It catches a writer the static test missed.
- HW-8 disclosure list: `broker/hostchange/hostchange_test.go::TestGuideListsEveryHostChange` (existing) passes on the shortened list, plus `::TestNoTokenOrSRKDisclosed` (neither ID is in `All`, the guide or `tools/hostcheck_hw8.json`). It catches the guide and the diff rules drifting apart.

## Scope

`image/mkosi/mkosi.conf`, `image/mkosi/mkosi.extra/**` (the new unit, the preset, the masks, chrony's config), `image/mkosi/initrd/**` (masks only), `image/mkosi/mkosi.finalize`, `image/mkosi/exec.allow`, `image/mkosi/tmpfiles.allow`, `image/mkosi/drop.py`, `image/build.sh`, `image/ci_boot.sh`, `image/ASSUMPTIONS.md`, `tests/test_image.py`, `broker/hostchange/**`, `docs/owners-guide.md`, `tools/hostcheck_hw8.json`, `broker/cmd/agentos-clock-boot/**`, `clock.BootEstimate`'s signature and its tests in `broker/clock/`, and `broker/clock/chrony/chrony.conf` (only if a test shows it wrong). Not `cmd/agentosd`, not other `broker/clock` code, not `broker/egress` or `broker/owner`.

**Guard files:** none (no broker package added or linked).

**Needs:** nothing open. The old "P2-1 image" and "P2-2" dependencies are the image on main.

**Usage:** about 120k. The checkpoint is the K14 VM check: if CI's NTP path costs more than two fix rounds, ship the static tests and the token check, move the VM check to HOST-1e2 with a hand-off comment, and say so in the PR.

**Lens recurring kinds (security):** state confinement as properties, not flags (point 5). Any root-side file read must not follow a planted link: clock-boot today `Stat`s the state file and then reads it by path, so it follows a link and races a swap. Security #177 O1 (open once with `O_NOFOLLOW`, `fstat` and read that descriptor) is built here.
