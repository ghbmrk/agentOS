# Enforcer image (ENF-m)

The enforcer's signed system image (SPEC NET-2 Hardening; briefs/ENF.md decision 7, D-229): the
core's pipeline ([../README.md](../README.md)) with the enforcer's own names, key and feed. Debian 13
packages, `/usr` read-only on dm-verity in A/B slots, Microsoft-signed shim, Debian-signed
systemd-boot and kernel, boot counting with fallback to the previous release, a hardware watchdog,
Wi-Fi and USB storage off, unknown USB devices unauthorised, and only the services the enforcer
needs. ENF-m-b adds the daemon (`broker/cmd/agentos-enforcer`) in place of the placeholder unit.

Build: `sudo ENFORCER_RELEASE_ROOT=root.json AGENTOS_RELEASE_KEYS="k ..." MKOSI=/path/to/mkosi
image/enforcer/build.sh OUT [VERSION]` on a Linux host that reaches the Debian mirrors. CI:
`.github/workflows/enforcer-image.yml` makes throwaway feeds, builds, and boots under Secure Boot.

| Path | What |
|---|---|
| `build.sh` | Checks the root's keys, stages the root, runs mkosi, finishes the image, writes SHA256SUMS |
| `finish_image.py` | The core's finish step, imported, with enforcer names; refuses a root, disk or feed carrying an agentOS release key (NET-2 Channel, acceptance test 2) |
| `test_finish_image.py` | Unit tests for the key separation and entry names |
| `throwaway_feeds.sh` | CI only: throwaway agentOS and enforcer feeds made with `agentos-release`, and the key separation on them |
| `mkosi/mkosi.conf` | Packages, boot chain, command line (`usbcore.authorized_default=0`), pinned snapshot, seed |
| `mkosi/mkosi.repart/` | ESP, `/usr` A and B with verity (`enforcer_VERSION`), the writable state partition last |
| `mkosi/mkosi.finalize` | Refuses Wi-Fi packages and firmware, a missing module block, a blocked module left installed, any unit enabled outside the preset, a core dump setting other than discard, and any `rp_filter` or `accept_redirects` left on (`test_finalize.py`) |
| `mkosi/mkosi.extra/` | Self-check (`agentos-enforcer/health`), fallback, boot report, watchdog, module blocks, core dumps discarded, the reverse-path filter off (`usr/lib/sysctl.d/99-enforcer-rpfilter.conf`), ICMP redirects refused (`usr/lib/sysctl.d/99-enforcer-redirects.conf`), preset, the placeholder daemon unit |
| `ci_boot.sh` | QEMU boot with OVMF Secure Boot, swtpm and an i6300esb watchdog: self-check, `rp_filter` and `accept_redirects` 0 on a network card, the WAN's router-advertisement handling, blessing, state growth, a USB stick left unauthorised, Wi-Fi refused, and the rollback |
| `ci_wan.sh` | `ci_boot.sh`'s check of the WAN's router-advertisement handling: a probe in the guest, keyed on the daemon unit's effective `ExecStart`, and the verdict on its line (`test_ci_wan.py`) |

The image ships the enforcer feed's root at `/usr/share/agentos-enforcer/release-root.json`; it is
the only root its updates are checked against. Assumptions and gaps: [ASSUMPTIONS.md](ASSUMPTIONS.md).
