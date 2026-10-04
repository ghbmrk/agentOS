# S7: Host foundation

**Question (BOARD S7, PLAN §3):** Which existing-distribution, image-based host can run AgentOS entirely from an external USB SSD, and does at least one of 2–3 candidates satisfy all of these?

| Criterion | Spec |
|---|---|
| A/B or transactional updates with automatic rollback | UPD-1, UPD-6 |
| Secure Boot through a Microsoft-signed shim, no per-PC key enrollment | HW-5, HW-6 (screenless) |
| Boots from an external USB drive on UEFI x86-64 | HW-3, HW-6 |
| TPM-sealed unlock on a trusted host | CRED-8 |
| ModemManager and Wi-Fi access point available | HW-2, CH-7 |
| Image build time on modest hardware | PLAN P2.1 |
| Updates verifiable by hash/signature, mirrorable, installable offline from a drive | DEP-4, UPD-2 |
| Existing distribution, no custom distribution work | §4 host row, §10 |

**Candidates**
- **A.** systemd image-based stack (mkosi + systemd-repart + systemd-sysupdate, dm-verity `/usr`, A/B partitions) on a Debian-family base. Built and booted here.
- **B.** bootc (OCI container image → bootable host; ostree or composefs backend) on Fedora/CentOS Stream. Desk research; its base images live on quay.io, which this cloud box's network policy blocks.
- **C.** openSUSE MicroOS (btrfs snapshots + `transactional-update` + `health-checker`). Desk research only.

**Kill/pivot rule (PLAN §3):** pick by measured properties. If no candidate meets Secure Boot + screenless + automatic rollback together, record which requirement must give and propose the spec diff.

**Time box:** ~3% of one week's plan allowance (coordinator brief). Stop and report rather than overrun.

**Method:** build candidate A with mkosi on Ubuntu 24.04 packages in a 4-vCPU cloud VM (no KVM), boot it in QEMU/TCG as a **USB mass-storage device on xHCI** under OVMF with **Microsoft keys enrolled and Secure Boot on**, with a software TPM 2.0. A probe unit prints `S7:` facts to the serial console; `check_boot.py` asserts them.
