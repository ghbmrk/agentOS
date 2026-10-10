# AgentOS device image (P2-1)

The image that goes on the drive: Debian 13 packages, `/usr` read-only on dm-verity in A/B slots,
booted by Microsoft-signed shim, Debian-signed systemd-boot and kernel (S7), with boot counting.
It carries the broker (`agentosd`), gVisor's `runsc`, and the OpenClaw guest image.

Build: `sudo MKOSI=/path/to/mkosi image/build.sh OUT [VERSION]` on a Linux host that can reach
the Debian mirrors (cloud agent sessions cannot; CI can). CI: `.github/workflows/image.yml`
builds on two runners, boots one build under Secure Boot in QEMU, and compares the releases.

| Path | What |
|---|---|
| `build.sh` | Stages the broker, runsc and guest, runs mkosi, finishes the image, writes SHA256SUMS |
| `mkosi/mkosi.conf` | Packages, boot chain, pinned snapshot, seed |
| `mkosi/mkosi.repart/` | Disk layout: ESP, `/usr` A and B with verity, root last |
| `mkosi/mkosi.finalize` | Fails the build on per-install state or socket files (HW-1, V15) |
| `mkosi/mkosi.extra/` | Health check gating boot-complete, boot report, broker unit, root growth |
| `finish_image.py` | Counted boot entry, `/usr` verified against the entry's `usrhash=`, release manifest |
| `ci_boot.sh` | QEMU boot with OVMF Secure Boot and swtpm; checks health, blessing, root growth |

Outputs in OUT: `agentos_V.raw` (the drive), `agentos_V.usr.raw` and `.usr-verity.raw` (the
release's `/usr`), `agentos_V+3.conf` (its boot entry), `agentos_V.release.json`, the package
manifest, and `SHA256SUMS`. Write the `.raw` to a drive with `dd` or any image writer.

Assumptions and gaps: [ASSUMPTIONS.md](ASSUMPTIONS.md).
