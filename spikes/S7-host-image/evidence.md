# S7 evidence excerpts (QEMU 8.2 TCG, OVMF 2024.02 with Microsoft keys, swtpm TPM 2.0). Full logs not committed.


## boot1: v1 on emulated USB (usb-storage, xHCI), Secure Boot on
```
BdsDxe: starting Boot0001 "UEFI QEMU QEMU USB HARDDRIVE 1-0000:00:02.0-1" from PciRoot(0x0)/Pci(0x2,0x0)/USB(0x0,0x0)
EFI stub: UEFI Secure Boot is enabled.
[    0.000000] secureboot: Secure boot enabled
[    0.000000] Kernel is locked down from EFI Secure Boot mode; see man kernel_lockdown.7
[    0.000000] secureboot: Secure boot enabled
[   31.236844] systemd-gpt-auto-generator[110]: (The boot loader did not set EFI variable LoaderDevicePartUUID.)
[   31.293590] systemd-veritysetup-generator[117]: Using data device /dev/disk/by-partuuid/90da43a0-0bf8-d3c6-381e-a300c9c35c24 and hash device /dev/disk/by-partuuid/893f007f-a66e-5c65-1ab3-f7cff415ab25 for usr.
```
## boot3: rebuilt v1 on emulated USB (usb-storage), root= fixed
```
BdsDxe: starting Boot0001 "UEFI QEMU QEMU USB HARDDRIVE 1-0000:00:02.0-1" from PciRoot(0x0)/Pci(0x2,0x0)/USB(0x0,0x0)
[   75.611255] device-mapper: verity: 8:2: metadata block 21522 is corrupted
[   75.859072] device-mapper: verity: 8:2: metadata block 21522 is corrupted
```
## boot5: emulated UAS
```
BdsDxe: No bootable option or device was found.
```
## boot8: v1 on virtio + offline update drive
```
S7: version=1
S7: secureboot=SecureBoot enabled
S7: usr=/dev/mapper/usr
S7: usr_ro=ro
S7: verity= status: verified
S7: bootdisk=virtio
S7: tpm=/dev/tpmrm0
S7: mm=/usr/sbin/ModemManager nm=/usr/sbin/NetworkManager
S7: done
S7U: Operation completed successfully.
S7U: Exiting.
S7U: Successfully acquired '/run/s7-updates/agentos_2.usr-verity.raw'.
S7U: Successfully installed '/run/s7-updates/agentos_2.usr.raw' (regular-file) as '/proc/self/fd/3p4' (partition).
S7U: Successfully installed '/run/s7-updates/agentos_2.usr-verity.raw' (regular-file) as '/proc/self/fd/3p5' (partition).
S7U: ✨ Successfully installed update '2'.
S7U: update_rc=0 secs=60
S7U: sr0                     1024M
S7U: vda                      6.3G
S7U: ├─vda1 esp                 1G
S7U: ├─vda2 agentos_1           1G
S7U: ├─vda3 agentos_1_verity 68.9M
S7U: ├─vda4 _empty              3G
S7U: ├─vda5 agentos_2_verity  256M
S7U: └─vda6 root-x86-64         1G
S7U: vdb                      1.3G
S7U: done
[  160.560015] systemd[1]: Startup finished in 28.093s (kernel) + 30.641s (initrd) + 1min 41.817s (userspace) = 2min 40.552s.
```
## boot9: B slot (v2) via edited grub.cfg, A kept as GRUB fallback
```
S7: version=2
S7: secureboot=SecureBoot enabled
S7: usr=/dev/mapper/usr
S7: usr_ro=ro
S7: verity= status: verified
S7: bootdisk=virtio
S7: tpm=/dev/tpmrm0
S7: mm=/usr/sbin/ModemManager nm=/usr/sbin/NetworkManager
S7: done
```
## boot10: B slot corrupted (64 MiB random overwrite)
```
[   60.802589] device-mapper: verity: 253:4: data block 29888 is corrupted
[   60.816081] device-mapper: verity: 253:4: data block 29888 is corrupted
[   60.834040] device-mapper: verity: 253:4: data block 29888 is corrupted
[   61.131121] device-mapper: verity: 253:4: data block 29888 is corrupted
(... 32 verity errors; system stays on B in degraded state; GRUB fallback never triggers)
```
