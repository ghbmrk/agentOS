# Camera node image (CAM-node part c)

The eave camera's firmware (#3513, `briefs/CAM-node.md`): a Buildroot root with one service, `agentos-camnode` (`broker/cmd/agentos-camnode`), on a read-only erofs root under dm-verity, booted from a signed boot image in A/B slots. No shell, getty, SSH or console; one port in, nothing out but replies and DHCP.

Build: `image/camnode/build.sh cm4|qemu OUT [VERSION]` on a Linux host that can reach Buildroot's download sites (GitHub archives too, for the CM4 board). A cm4 build needs `CAMNODE_RELEASE_PUB`, the release signer's public key. CI: `.github/workflows/camnode-image.yml` builds both boards and runs the end-to-end test on the QEMU one.

| Path | What |
|---|---|
| `build.sh` | Fetches the pinned Buildroot, builds the static node binary (and, for qemu, the stand-ins and the test driver), merges the board's configuration and runs Buildroot |
| `external/configs/` | `common.config` (toolchain from source, systemd, no shell or busybox, erofs root), `cm4.config` (Raspberry Pi kernel and firmware, libcamera, `rpicam-vid`), `qemu.config` (mainline kernel, test board only) |
| `external/package/camnode-init/` | The initramfs's only program: verity over the booted slot's root, read whole, mounted read-only, then systemd |
| `external/board/common/` | The firewall, the network, the units and mounts, the user, the kernel fragment, `post-build.sh` (refuses a shell or setuid file), `post-image.sh` (slot image, boot image, factory disk) |
| `external/board/cm4/` | `config.txt` inside the boot image, udev names for the eMMC, element, button and camera devices, the IR file |
| `external/board/qemu/` | udev names and units for the stand-ins; the journal on the serial console |
| `e2e/driver/` | The end-to-end test: plays the bootloader, the home network, the core and the enforcer |
| `e2e/element/`, `e2e/button/`, `e2e/encoder/` | QEMU-only stand-ins for the OPTIGA Trust M (CUSE), the button (uinput) and `rpicam-vid` |

Outputs in OUT: `camnode-BOARD.disk.img` (the factory disk: write it to the eMMC), `camnode-BOARD.slot.img` (what an update carries; its SHA-256 and size go in the manifest), `camnode-BOARD.boot.img` (for the release signer's `boot.sig`), `camnode-BOARD.slot.json` and `SHA256SUMS`.

End-to-end test: `sudo ip netns add camnode-e2e && sudo ip netns exec camnode-e2e OUT/e2e/camnode-e2e run -out OUT` (needs `dnsmasq`).

Assumptions and gaps: [ASSUMPTIONS.md](ASSUMPTIONS.md).
