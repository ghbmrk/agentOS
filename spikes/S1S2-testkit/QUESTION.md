# S1 and S2: hardware test kit

**S1.** Does a USB4 SSD boot screenless (≤1 keypress) on ≥3 unmodified PCs from different vendors?
Kill/pivot (PLAN §3): <2 of 3 → bring the integrated key forward or accept a documented one-keypress setup.

**S2.** Does a USB LTE modem do SMS **and** voice under Linux reliably?
Kill/pivot: no voice → MVP is text-only; voice moves to a later gate.

Time box: one afternoon of Mark's hands for S1 (about 15 minutes per PC), one hour for S2 (both modems).

## What Mark does

Print [CHECKLIST.md](CHECKLIST.md). Buy from [SHOPPING.md](SHOPPING.md). The image comes from CI, so nothing is built locally.

## The image

One image serves both spikes. It is S7's recommendation built for real: Debian 13, `/usr` on dm-verity, booted
Microsoft-signed shim → Debian-signed systemd-boot → Debian-signed kernel, with systemd boot counting. Built
and boot-tested by [.github/workflows/testkit.yml](../../.github/workflows/testkit.yml) (GitHub's runners can
reach deb.debian.org; agent sessions cannot). To build by hand instead: `sudo MKOSI=/path/to/mkosi-v24.3 ./build.sh`.

On every boot `testkit.service` runs [testkit.py](mkosi/mkosi.extra/usr/lib/testkit/testkit.py):

1. **Boot 1** (entry `rollback`, 2 tries): probes the PC and writes `results/NN-<vendor>-<model>.txt` to the
   drive's FAT partition `TESTKIT`, then reboots without marking the boot good.
2. **Boot 2**: same entry, reboots again. Its tries are now spent.
3. **Boot 3**: systemd-boot falls back to entry `good`, which is blessed. The kit records the verdict, runs S2
   if enabled, re-arms both entries for the next PC, and **powers off**.

So the PC switching itself off is the screenless pass signal: it booted from USB with no keys, two warm reboots
came back to USB (which A/B updates need), and automatic rollback worked on that firmware. That last point is
S7's open decision boundary (Debian's signed systemd-boot boot counting under shim on real hardware).

Per PC it records: vendor/model and firmware version, Secure Boot state, boot loader, whether gpt-auto found
the root (S7 surprise 3), the boot disk's negotiated USB link, TPM version, boot time, a full `/usr` read through
dm-verity with throughput and error count (S7 surprise 2), and the rollback verdict.

S2 ([s2.py](mkosi/mkosi.extra/usr/lib/testkit/s2.py)) runs when `s2.conf` on the drive says `RUN_S2=yes`.
The owner's phone is the only interface: SMS out, SMS in (reply PING), a call out (owner hears 4 digits and
presses them; the box decodes the keypad tones from uplink audio with [dtmf.py](mkosi/mkosi.extra/usr/lib/testkit/dtmf.py),
which is also CH-17's premise), and a call in. It records IMS registration (`AT+CIREG?`), since US voice is VoLTE-only.

Privacy: `results/` holds no serial numbers, MAC addresses, IMEI/ICCID/IMSI, or phone numbers, so Mark can upload
it. Call recordings go to `private/`, which stays on the drive.

## Verified vs. not

| | Status |
|---|---|
| State machine, entry generation, DTMF decoder | unit tests ([tests/test_s1s2_testkit.py](../../tests/test_s1s2_testkit.py)) |
| Image builds; boots under OVMF with Microsoft keys + Secure Boot; rollback sequence; blessing; power-off | CI boot test in QEMU ([ci_boot.sh](ci_boot.sh)) |
| Real firmware, real USB4/USB 3 links, real TPMs | S1, Mark's hands |
| Modem audio routes (Quectel USB Audio Class, SIMCom PCM over serial) | **untested**: from vendor AT manuals; S2 is their first run |

If S2 fails in a way the result file doesn't explain, a builder can debug live through Remote Control on a Linux
PC with the modem attached.
