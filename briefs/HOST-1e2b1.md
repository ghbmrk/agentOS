# HOST-1e2b1: host-untouched check, software half for the S1 PC run

Board section: Devices, hardware and image (SPEC §13-14). Work item #6135, split from HOST-1e2b (#5815, which keeps the S1 PC run and the owner's steps). Parent: `briefs/HOST-1e2.md` part b, `briefs/HOST-1e.md` part 2.

**Requirements:** HW-8 (host untouched), HW-8a (internal disk by owner opt-in).

**Why:** on a real PC the check snapshots from a third system, so QEMU's `RTC_CHANGE` events do not exist. Today the clock is covered only by the operator's `--rtc-written` yes/no. An image that writes the PC's hardware clock then passes the S1 run. Separately, HOST-1d's opted-in disk is written by design, so without a flag every S1 run with it fails and gets waved through.

**This package:**
- **RTC offset.** `snapshot --rtc-reference HOST[:PORT]` records `rtc`: the PC's hardware clock read from sysfs (`--rtc-device`, default `/sys/class/rtc/rtc0/since_epoch`; a read never sets it) at the edge of its second, less the reference time at that instant. The reference is the third system's clock corrected by one query-only SNTP exchange (the reply must echo the request's transmit time, mode 4, stratum 1-15), so the third system's clock is never set. The snapshot refuses (exit 2) while the third system's kernel counts its clock as synchronised (`adjtimex`, `STA_UNSYNC` clear), because the kernel then copies its clock into that same RTC every 11 minutes. `diff` flags `rtc offset changed` when the offset moved more than `--rtc-tolerance` (default 2 s), and `rtc offset missing` when only one snapshot has it.
- **Opted-in disk.** `diff --opted-in-disk NAME` moves a `changed` finding for that disk from `flagged` to `excluded`, which names HW-8a. An added or removed disk, and every other disk, is still flagged. A name missing from either snapshot stops the diff (exit 2).
- **pcrlock.** P2-1 pins no pcrlock NV index: Debian's `systemd-pcrlock-make-policy.service` carries `ConditionSecurity=measured-uki`, and the image sets `UnifiedKernelImages=no` (image I1). So `hostcheck_hw8.json` gets no rule, and an index pcrlock would define still fails the diff. A test pins both facts.

**Enforced in the tool (L3 and Security on #6140):** an offset check sees a write that sets true time only if the baseline RTC was away from it, so `diff` flags a baseline offset under 60 s (`baseline-near-true-time`), telling the operator to set the RTC wrong in firmware setup and take the baseline again. The SNTP reference is unauthenticated, so the S1 run (#5815) takes it from a server the image never reached, such as the operator's own machine on a direct link. The `adjtimex` decode is a tested pure function that fails closed on a layout or return-value mismatch. A PC snapshot (`--efivarfs`) requires `--rtc-reference`.

**Follow-up HOST-1e2b1-fu (#6166, release items from #6140's reviews):** `--rtc-tolerance` at or above `RTC_BASELINE_FLOOR` and a second `--opted-in-disk` are refused (exit 2), so no operator value switches a check off. Each snapshot records `uefi-source`; a missing offset is flagged unless both snapshots come from an OVMF varstore, and `rtc offset missing` carries a `fix`. The adjtimex bound reads "at least when" and the refusal names the PPS case. The synchronised-clock refusal says to disable the NTP client, then reboot; `baseline-near-true-time` says to rerun the session, and `snapshot` warns of it on stderr. The clock check and SNTP exchange run before the disk hash; a bad `--rtc-device` exits 2; the unknown-disk error lists the disks held.

**Acceptance tests:**
- `tests/test_hostcheck.py::RtcOffsetTest::test_offset_moved_past_tolerance_is_flagged`
- `tests/test_hostcheck.py::RtcOffsetTest::test_offset_in_one_snapshot_only_is_flagged`
- `tests/test_hostcheck.py::RtcOffsetTest::test_rtc_is_read_at_its_second_edge`
- `tests/test_hostcheck.py::RtcOffsetTest::test_sntp_reference_checks_the_echo`
- `tests/test_hostcheck.py::RtcOffsetTest::test_snapshot_refuses_while_the_kernel_clock_is_synchronised`
- `tests/test_hostcheck.py::RtcOffsetTest::test_the_timex_decode_reads_status_and_its_polarity`
- `tests/test_hostcheck.py::RtcOffsetTest::test_a_baseline_near_true_time_is_flagged`
- `tests/test_hostcheck.py::RtcOffsetTest::test_a_pc_snapshot_needs_an_rtc_reference`
- `tests/test_hostcheck.py::OptedInDiskTest::test_only_the_named_disk_change_is_excluded`
- `tests/test_hostcheck.py::OptedInDiskTest::test_unknown_name_stops_the_diff`
- `tests/test_hostcheck.py::PcrlockTest::test_the_image_pins_no_pcrlock_index`
- `tests/test_hostcheck.py::RtcOffsetTest::test_a_tolerance_at_the_baseline_floor_is_refused`
- `tests/test_hostcheck.py::RtcOffsetTest::test_a_pc_snapshot_without_an_offset_is_flagged`
- `tests/test_hostcheck.py::RtcOffsetTest::test_snapshot_warns_on_a_baseline_near_true_time`
- `tests/test_hostcheck.py::RtcOffsetTest::test_a_bad_rtc_device_stops_the_snapshot`
- `tests/test_hostcheck.py::RtcOffsetTest::test_the_clock_is_checked_before_the_disks_are_hashed`
- `tests/test_hostcheck.py::OptedInDiskTest::test_a_second_opted_in_disk_is_refused`

**Scope:** `tools/hostcheck.py`, `tests/test_hostcheck.py`, `tools/ASSUMPTIONS.md` (rows), this brief.

**Tier / gate:** tier A (`tools/hostcheck*`): L3 and a separate Security accept if `premerge.py --needs-mark` prints `mark`. One session, about 60k tokens.
