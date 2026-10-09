# HOST-1b: No hardware-clock writes

Board section: Backlog refill (2026-10-05).

No hardware-clock writes (HW-8): the time service leaves the RTC alone (no `hwclock --systohc`, kernel NTP RTC update off), and the hardware clock is unverified until network or carrier time; test that a synced, rebooted VM's RTC is unchanged. **Part 1 (this package):** `clock` treats the hardware clock as unverified (floor bounding `Latest`/`Earliest`, STATUS line), `Synced` from chronyd (NTS first), `clock/chrony/chrony.conf`, the learned hardware-clock offset and `agentos-clock-boot` ([assumptions](../broker/clock/ASSUMPTIONS.md) K1, K11-K15; lens conditions Security T1-T7, UX-H1b-1, Potency C1). **Part 2:** unverified-clock code wording (Potency C2) and phone-attested time on the Wi-Fi page (Security T8-T10); Security #177 options O1 (`agentos-clock-boot` opens the state file once with O_NOFOLLOW, fstats and reads that fd) and O2 (cap how far a plain sync can raise the floor). **Carry from #163 (OSS-6, pubid wiring W5):** once `Status.Verified` exists, pubid counts days only on a verified clock. **For P2-1:** chrony in, timesyncd masked, timedated refused, no hwclock, the VM test (K14)

**Needs:** P2-1 image

**Gate:** lenses

**State on the board before the 2026-10-08 index split:** part 1 merged (#177); part 2 queued on P2-2w (R1 needs the live page)
