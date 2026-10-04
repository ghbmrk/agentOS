# S7 result: host foundation

**Answer: yes, with one structural caveat.** An image-based host built from an existing distribution meets the update, offline, TPM, modem and build-time criteria. No candidate gives *both* screenless setup and Secure Boot coverage of AgentOS's own boot files (initrd, kernel command line, verity root hash). That needs a spec decision (proposed diff below).

**Recommendation [Rec]:** candidate **A**, the systemd image-based stack (mkosi + systemd-repart + systemd-sysupdate, dm-verity `/usr`, A/B slots), on **Debian 13** rather than the Ubuntu 24.04 base measured here. The switch matters because Debian signs systemd-boot under its shim, which brings systemd's automatic boot assessment. Ubuntu does not sign systemd-boot, and its GRUB path has no automatic rollback (measured, below). **bootc on CentOS Stream 10** is the fallback if Debian's signed systemd-boot doesn't hold up on real hardware.

Labels: **[M]** measured here, **[D]** primary documentation, **[I]** inference.

## Measurements (candidate A, Ubuntu 24.04 packages)

Setup: a 4-vCPU, 15 GB cloud VM without KVM. Images were built with mkosi 24.3 and booted in QEMU 8.2 (TCG) under OVMF with **Microsoft keys enrolled and Secure Boot on**, with swtpm as TPM 2.0. Excerpts are in [evidence.md](evidence.md); to reproduce, run [run.sh](run.sh).

| Property | Result | |
|---|---|---|
| Build time, full image (packages, initrd, verity, partitions) | 252 s cold (incl. downloads); 183–205 s warm (4 runs) | [M] |
| Image layout | ESP 1 GiB · `/usr` A 1.0 GiB erofs + 69 MiB verity · `/usr` B slot 3 GiB + 256 MiB · root 1 GiB ext4 → 6.3 GiB disk, 1.5 GiB allocated | [M] |
| Default initrd | 400 MiB uncompressed footprint, because mkosi pulls firmware for every included module. It needs trimming before the ESP has to hold two kernels plus initrds | [M] |
| Secure Boot from a USB device | Microsoft-signed shim → Canonical-signed GRUB → Canonical-signed kernel, all accepted from an emulated USB stick. Kernel reports "Secure boot enabled", lockdown on | [M] |
| Measured boot | Kernel EFI stub: "Measured initrd data into PCR 9". GRUB measures the command line it passes | [M] / [I] |
| `/usr` integrity | `/dev/mapper/usr`, read-only, `veritysetup status: verified` on both v1 and v2 | [M] |
| TPM | `/dev/tpmrm0` present; `systemd-cryptenroll --tpm2` ships in systemd 255 | [M] / [D] |
| ModemManager, NetworkManager (Wi-Fi AP via NM hotspot), wpa_supplicant | All in the image from the distribution's main archive | [M] |
| Offline A/B update (DEP-4) | `systemd-sysupdate` found v2 on a second plain ext4 drive, wrote `/usr` and its verity into the empty B slot in **60 s** (TCG), and labelled them `agentos_2`. Verity on the B slot checks out against v2's root hash | [M] |
| Boot into B | With GRUB pointed at B and A kept as `fallback`, the box booted `version=2` with verity verified | [M] |
| Automatic rollback | **Fails on this stack.** With 64 MiB of the B slot overwritten, dm-verity rejected every bad read (32 errors), but the system stayed on B in a degraded state. GRUB's `fallback` only fires when GRUB itself can't load an entry, and Ubuntu's GRUB has no boot counting | [M] |

## Surprises

1. **Secure Boot stops at the distribution's kernel. [M]** Under shim → GRUB, the kernel is verified but the initrd and `grub.cfg` (which carries `usrhash=`, the root of all `/usr` integrity) are not. Anyone who can write the drive's ESP can point it at a different `/usr`, and Secure Boot still reports "enabled". Covering these files needs one of three things:
   - a key enrolled into shim (MOK), which takes a one-time confirmation at the firmware console with a screen and keyboard;
   - AgentOS's own shim, which needs Microsoft review. That is a one-time project dependency, not a runtime one;
   - TPM measurement instead of verification, which protects only on a host where a TPM seal exists.

   On an unknown host (CRED-8's approval-code path), a tampered drive is undetectable by the box itself. This applies to all three candidates: bootc's sealed-UKI mode and MicroOS's systemd-boot path need the same key enrollment. [D]
2. **Emulated USB corrupted reads. [M, emulator only]** On QEMU's USB mass-storage emulation, dm-verity rejected hash blocks in 2 of 2 boots, at a different block each time. The same disk image verifies on the host and boots cleanly over virtio. QEMU's emulated UAS can't be booted by OVMF at all. Whatever the cause, verity turns any silent USB read error into a hard failure. That's correct for integrity, but it puts enclosure and cable quality on the availability path. S1 should run a full `/usr` read-verify on every PC it tests.
3. **GRUB doesn't tell systemd which disk it booted from. [M]** `LoaderDevicePartUUID` is unset, so systemd's automatic partition discovery fails and the first boot found no root. This build needed an explicit `root=PARTLABEL=…`. A real box with a second drive attached must not depend on partition labels being unique.
4. **sysupdate doesn't move the boot entry. [M]** It wrote `/usr` B, but the kernel, initrd and the entry carrying the new root hash need their own transfer. On systemd-boot that is one UKI or Type #1 entry file per version, which sysupdate supports. On GRUB it is custom code.
5. **Tooling version skew. [M]** Ubuntu's packaged mkosi 20.2 can't build noble images: its initrd package names predate the t64 renames. Upstream mkosi 24.3 works. Pin mkosi from upstream rather than from the distribution.

## Candidates compared

| Criterion | **A. systemd image stack (mkosi/sysupdate)** | **B. bootc (Fedora / CentOS Stream)** | **C. openSUSE MicroOS** |
|---|---|---|---|
| Update model | Whole-`/usr` A/B partitions, dm-verity [M] | OCI image → ostree deployment (or composefs); `bootc upgrade` / `rollback` [D] | Package-based btrfs snapshot via `transactional-update` [D] |
| Automatic rollback | Ubuntu/GRUB: **no** [M]. Debian 13: yes, via signed systemd-boot boot counting + `systemd-bless-boot` [D: Debian ships `systemd-boot-efi-amd64-signed`; boot counting is upstream systemd] [I: not run here] | Yes on the ostree backend: greenboot health checks + GRUB `boot_counter`. The composefs backend doesn't do boot counting yet [D: bootc docs] | Yes: `health-checker` rolls back to the last good snapshot [D] |
| Secure Boot via Microsoft-signed shim, no enrollment | Yes, for distribution-signed parts [M] | Yes, Fedora/CentOS-signed shim and GRUB [D] | Yes, openSUSE-signed shim [D] |
| Boot files beyond the distribution covered without enrollment | No (surprise 1) | No: sealed UKIs need your own key [D] | No [I] |
| TPM-sealed unlock | `systemd-cryptenroll` [D] | Left to the image author; same systemd tooling [D] | Strongest: FDE with TPM2 + measured boot by default in Aeon, managed by `sdbootutil` [D] |
| Offline, mirrorable, verifiable updates (DEP-4) | Files from any directory or HTTP mirror; `SHA256SUMS` + GPG signature (`Verify=yes`) [D]; offline drive [M] | Any OCI registry or mirror; `bootc switch --transport oci /mnt/usb/…` from a drive [D]; signatures via `containers-policy.json`, which are **not required by default** [D] | zypper repos are mirrorable and the RPMs are signed, but there is no single image hash: each box assembles its own snapshot [I] |
| Identical bits on every box (reproducible, hash-checkable) | Yes: one verity root hash per release [M] | Yes: OCI digest [D] | No [I] |
| Base lifecycle | Debian 13: ~5 years | CentOS Stream 10: ~5 years; Fedora: ~13 months | Tumbleweed rolling: constant churn |
| Build on modest hardware | 3–4 min on 4 vCPU [M] | Containerfile + bootc-image-builder; not measured here because quay.io is blocked by this box's network policy | Not measured |
| Original code AgentOS has to own | Partition definitions, sysupdate transfers, a health-check unit | Containerfile, greenboot checks | Little, but the host isn't image-defined |
| Fits spec §4 "immutable, signed image with A/B updates" | Literally | Yes (deployments rather than partitions) | Partly (snapshots, package-assembled) |

**Why A over B [Rec]:**
- Both meet the criteria. A is smaller and fully systemd-native, which keeps the dependency count low (DEP-1/2), and its per-release verity root hash is exactly the content hash DEP-4 and LOOP-8 ask for.
- B's advantages are its mature tooling and health checks, but it brings a container stack onto the host, and signature checking is opt-in.
- C is out: the host isn't image-defined, the rolling base churns constantly, and there's no single release hash.

**Decision boundary:** if Debian 13's signed systemd-boot fails boot counting under shim on real hardware (S1 sessions), switch to B on CentOS Stream 10. Its rollback is proven today; the cost is ~1 GiB more image and a container runtime on the host.

## Proposed SPEC.md diff (for L1 → Mark; SPEC.md not edited here)

```diff
 | **Host** | Trusted base | Immutable, signed image with A/B updates; an existing distribution, not a custom one |
+  [S7] Reference: Debian 13 packages, `/usr` A/B partitions with dm-verity, systemd-sysupdate, shim → distribution-signed systemd-boot.

-- **HW-5** Secure Boot MUST be supported through a Microsoft-signed shim [Fact: standard for mainstream distributions].
+- **HW-5** Secure Boot MUST be supported through a Microsoft-signed shim, booting only distribution-signed bootloader and kernel, so no per-PC key enrollment is needed.
+- **HW-5a** Secure Boot does not cover AgentOS's initrd, kernel command line, or `/usr` root hash. Their integrity MUST rest on TPM measured boot: the vault unlock slot (CRED-8) is sealed to the PCRs that measure them, so a modified boot path cannot unlock on a trusted host.
+  [Risk] On an unknown host, offline tampering with the drive is not detectable by the box. Options for Mark: (a) accept for MVP and say so in the owner's guide; (b) optional MOK enrollment for owners with a screen; (c) pursue an AgentOS shim through Microsoft review after MVP.

-- **UPD-1** A/B image updates: stage → test → activate → health-check → commit or fall back. …
+- **UPD-1** A/B image updates: stage → test → activate → health-check → commit or fall back. Fallback MUST be automatic, using boot-loader boot counting plus a health check, with no owner action. …
+- **UPD-1a** A release is one content hash (the `/usr` verity root hash) plus its boot entry. Both MUST transfer together.

 - **HW-6** …
+  [S7] dm-verity makes USB read errors fatal. Qualification (A1) MUST include a full read-verify of the image on each tested PC and enclosure.
```

## Not done or not measured

- Real USB hardware (that's S1). Here, USB boot was verified only up to the kernel and initrd; the full boot to a running system was over virtio.
- Debian 13 and bootc builds: their mirrors and registries (deb.debian.org, quay.io, Fedora mirrors) are denied by this cloud box's network policy. The Debian claims are [D]/[I] and should get a 30-minute verification in P2 step 1.
- TPM sealing itself was not exercised; only the device and tooling were confirmed.
- Signed update payloads (`Verify=yes`) were not exercised; the test used `Verify=no`.

## Budget

Model usage wasn't measured; the harness can't read the usage screen (PLAN §4A B-6). Estimate: one session of about 60 tool turns with small outputs, ≈2–3% of the weekly allowance [I], inside the ~3% cap. Build and boot compute ran on the cloud VM and used no model tokens.
