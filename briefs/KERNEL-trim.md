# KERNEL-trim: the image kernel's attack surface, per box (HW-5a, #4094)

Board section: Devices, hardware and image (SPEC §13-14). Work item #4094, approved by Mark in Decisions on 2026-10-30 ("Yes - the kernel itself is a dependency"). Tier A. Three parts, one session each: **a** measures (this file), **b** writes trimmed, locked-down settings per box and boot-tests them, **c** reports the CVE-class reduction and the cost of our own signed kernel. Parts b and c extend this file.

**Acceptance tests:** none: part a only measures and changes no code. Its acceptance (#4094) is that the lists below exist per box and that a reader can rerun the method (Method, Appendix) and get the same lists. Parts b and c name a boot test per box.

## The gap

Every box runs Debian's generic `linux-image-amd64`: 4,230 loadable modules and 2,651 built-in options, made for every PC. The code agentOS runs needs a small part of that. The rest is still reachable. An unprivileged process can make the kernel load about 330 modules (measured below), and about 188 of them only through unprivileged user namespaces, which nothing on the boxes uses. Recent local kernel exploits mostly come in through those paths: nf_tables, user-namespace mounts, AF_ALG, packet schedulers, and old protocol families.

- **Failure path:** a guest that escapes its gVisor sandbox (PLN-6), or any compromised unprivileged service on the core, edge or enforcer, opens a user namespace. It makes the kernel load nf_tables, a scheduler or a filesystem the box never uses, triggers a known bug in it, and becomes root on the host. That root reaches the sealed store, the clerks and the enforcer channel (KRN-2), on a box whose code never needed that kernel path.

## What was measured

- **Kernel:** `linux-image-6.12.113+deb13-amd64` 6.12.113-1, from `deb.debian.org/debian-security`, `trixie-security/main` (`pool/updates/main/l/linux-signed-amd64/linux-image-6.12.113+deb13-amd64_6.12.113-1_amd64.deb`). Its SHA-256, `a4ad0bf9f084b199dd2b12cb8a2ed918abb442da467f40b772166a267c784a5b`, matches the archive index. The image pins the main archive at snapshot 20261001 but reads `security.debian.org` live (`image/mkosi/mkosi.conf`). On 2026-10-30, trixie main had 6.12.107-1 and trixie-security had 6.12.113-1, so a build today installs 6.12.113. Point releases within trixie keep the config, so the lists below hold for the 6.12 trixie series. Part b re-reads the config of the kernel it builds.
- **Boxes:** the core and the edge run the same image (HW-10: "one signed image serves controller install, the edge"). The enforcer's image will reuse the same mkosi pipeline and Debian packages with its own key (`briefs/ENF.md` decision 7, D-229, slice m, not built yet). So today all three boxes would boot this one kernel with this one config. What differs per box is what they need (Needs per box).
- **Not measured, and why:** the session could not build the agentOS image, because `snapshot.debian.org` is not reachable from the agent network. It also could not fetch CI's built image or console logs, because the GitHub artifact blob host answered 403. So the booted VM is Debian's kernel with a minimal probe initramfs, not the agentOS image. Two consequences follow. First, lockdown reads `[none]`, because the VM booted without Secure Boot (Lockdown and module signing gives the configured behaviour under Secure Boot). Second, there was no udev, so device-driven autoload is counted from `modules.alias` rather than observed. Part b's per-box boot tests run on the real image in CI, under Secure Boot, and read the same values on the booted box.

## Method (rerunnable; the Appendix gives the probe)

1. Download the kernel package from the security archive, check its SHA-256 against `Packages.xz`, and unpack it with `dpkg-deb -x`. Read `boot/config-*` for the options in the tables below, and count `usr/lib/modules/*/kernel/**.ko*`.
2. Run `depmod -b` on the unpacked tree to get `modules.alias`, then count the modules per autoload trigger: `net-pf-*` (socket families), `net-pf-16-proto-16-family-*` (generic netlink), `crypto-*` (AF_ALG), `fs-*` (mount), `usb:`, `pci:`.
3. Boot the kernel in QEMU (`qemu-system-x86_64 -m 3072 -smp 4 -kernel vmlinuz -initrd probe.cpio.gz -append "console=ttyS0 quiet panic=-1"`). The initramfs holds busybox, kmod as `/sbin/modprobe` (the kernel's `CONFIG_MODPROBE_PATH`), the unpacked modules with depmod's output, util-linux `setpriv` and `unshare`, iproute2 `ip` and `tc`, `nft`, and the static Go probe in the Appendix. Its `/init` prints the lockdown state, the LSM list and the sysctls in the tables below. Then, as uid 1000 with no groups (`setpriv --reuid=1000 --regid=1000 --clear-groups`), it runs each trigger stage in turn and prints which modules appeared in `/proc/modules` during that stage. The stages are: without a user namespace (sockets, generic netlink families, AF_ALG binds, mounts), then inside `unshare -Urn` (the same four, then link types, nftables rules and tc qdiscs, filters and actions). A module that an earlier stage already loaded is counted only in that earlier stage. Each probe tries the names `modules.alias` lists, so the counts are a lower bound for each trigger: a probe that did not think of a name does not load its module.
4. Hardware-driven autoload (udev matching a plugged or present device) was not exercised. It is counted from `modules.alias`.

## Measured: lockdown, signing and the knobs

Config values come from the config file. Runtime values come from the booted VM, which ran kernel defaults with no agentOS sysctl applied.

| Item | Value | What it means on the boxes |
|---|---|---|
| Lockdown LSM | `SECURITY_LOCKDOWN_LSM=y`, `_EARLY=y`, `LOCK_DOWN_KERNEL_FORCE_NONE=y`, `LOCK_DOWN_IN_EFI_SECURE_BOOT=y`; VM: `[none] integrity confidentiality` | Under Secure Boot (shim, HW-5) the kernel locks itself to **integrity**. Booted with Secure Boot off, it is **none**. Confidentiality is never set. |
| Module signing | `MODULE_SIG=y`, `MODULE_SIG_FORCE` not set, `MODULE_FORCE_LOAD=y`, `MODULE_UNLOAD=y` | Integrity lockdown enforces signatures, so a module must be Debian-signed. With Secure Boot off, unsigned modules load (taint only). Any Debian-signed module loads, from any path, for root. |
| Other LSMs (VM `lsm`) | `lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm` | IPE is built in (`SECURITY_IPE=y`, dm-verity properties), but its policies must be signed by a key in the secondary or platform keyring (`IPE_POLICY_SIG_*`). LoadPin is not built. AppArmor is active with no profile from the image. |
| Unprivileged user namespaces | `USER_NS=y`; `kernel.unprivileged_userns_clone=1`, `user.max_user_namespaces=11491` | **On.** This is the largest single door in the probe (188 modules plus the code already loaded). |
| Unprivileged BPF | `BPF_UNPRIV_DEFAULT_OFF=y`; `kernel.unprivileged_bpf_disabled=2`; `net.core.bpf_jit_harden=0`; `BPF_JIT_ALWAYS_ON` not set | **Off** for unprivileged users already. Privileged BPF stays on (systemd uses it for `DeviceAllow=`, 12 uses in the image's units). |
| io_uring | `IO_URING=y`; `kernel.io_uring_disabled=0` | On for everyone. |
| userfaultfd | `USERFAULTFD=y`; `vm.unprivileged_userfaultfd=0` | Unprivileged users may only use it on their own memory (kernel-fault handling is refused). |
| kexec | `KEXEC=y`, `KEXEC_FILE=y`, `KEXEC_SIG=y`; `kernel.kexec_load_disabled=0` | Integrity lockdown allows only signed kexec. With Secure Boot off, root can kexec anything. |
| 32-bit and legacy ABIs | `IA32_EMULATION=y` (on by default), `X86_X32_ABI=y`, `MODIFY_LDT_SYSCALL=y`, `USELIB=y`; `LEGACY_VSYSCALL_NONE=y` | 32-bit and x32 syscall tables are reachable by any process. |
| Memory and introspection | `DEVMEM=y` (`STRICT_DEVMEM`, `IO_STRICT_DEVMEM`), `PROC_KCORE=y`, `DEBUG_FS=y`, `KPROBES=y`, `HIBERNATION=y` | Integrity lockdown blocks /dev/mem writes, hibernation and kprobes writes. It leaves reads that confidentiality lockdown would block. |
| Hardening already on | `INIT_ON_ALLOC_DEFAULT_ON`, `INIT_STACK_ALL_ZERO`, `HARDENED_USERCOPY`, `SLAB_FREELIST_HARDENED`/`_RANDOM`, `RANDOMIZE_BASE`/`_MEMORY`, `X86_KERNEL_IBT`, `X86_USER_SHADOW_STACK`, `STACKPROTECTOR_STRONG`, `FORTIFY_SOURCE`, `SECURITY_DMESG_RESTRICT` | Off: `INIT_ON_FREE_DEFAULT_ON`, `RANDOM_KMALLOC_CACHES`, `ZERO_CALL_USED_REGS`, `STATIC_USERMODEHELPER`; `RANDSTRUCT_NONE`. |
| Sysctls (VM) | `kptr_restrict=0`, `dmesg_restrict=1`, `perf_event_paranoid=3`, `yama.ptrace_scope=0`, `dev.tty.ldisc_autoload=1`, `kernel.sysrq=438`, `fs.protected_fifos=0`, `fs.protected_regular=0`, `protected_symlinks=1`, `protected_hardlinks=1`, `modules_disabled=0` | The image adds only `99-agentos-nodump.conf` (core_pattern, suid_dumpable). Debian's `linux-sysctl-defaults` (sysrq 0x1b6, protected_fifos 1, protected_regular 2) is only a Recommends of systemd, and mkosi installs no Recommends by default, so it is probably absent (inference). Part b confirms from the release record's dpkg status. |

## Measured: what an unprivileged process can make the kernel load

These are modules that appeared in the booted VM when uid 1000 with no groups ran the probe. **142 load with no namespace at all, and 188 more load once the process creates a user namespace: 330 in total.** These counts are lower bounds (Method, step 3). On the real image, some of these are already loaded at boot, such as ext4, vfat, erofs and nf_tables on the core. For those, the code is reachable whether or not autoload happens, and only closing the path (the namespace, the socket family) removes it.

| Trigger | Without a namespace | Loaded |
|---|---|---|
| `socket()` families and protocols | 52 | sctp, l2tp (ip, ip6, ppp, netlink), pppoe, pptp, appletalk, atm, can, bluetooth, nfc, phonet, qrtr, rxrpc, kcm, smc, llc2, af_key, xfrm_user, af_alg, crypto_user, vsock (+vmci, virtio, loopback), mpls_router, gre, ib_core, scsi_transport_iscsi |
| Generic netlink family lookup | 25 | wireguard, openvswitch, ip_vs, gtp, macsec, batman_adv, nbd, cfg80211, drop_monitor, nsh, psample, bridge, nf_conntrack, nf_nat, nf_conncount |
| AF_ALG bind (`crypto-*` names) | 67 | algif_{hash,skcipher,aead,rng} and 60 cipher, hash and mode modules (des, blowfish, twofish, serpent, camellia, cast5/6, md4, rmd160, wp512, streebog, ecrdsa, pcrypt, intel_qat, ...) |
| `mount()` | 0 | Needs CAP_SYS_ADMIN |

| Trigger | Only inside `unshare -Urn` | Loaded |
|---|---|---|
| `mount()` of each `fs-*` name | 90 | btrfs, xfs, f2fs, bcachefs, ntfs3, hfs/hfsplus, jfs, reiserfs, ocfs2, gfs2, nilfs2, udf, ubifs, jffs2, cifs, nfs, nfsd, ceph, 9p, coda, overlay, squashfs, erofs, ext4, vfat, exfat, efivarfs, binfmt_misc, configfs, gadgetfs, usb_f_fs, vboxsf, ... (the mount fails, but the module loads first) |
| `ip link add type ...` | 26 | dummy, veth, bonding, team, vxlan, geneve, ip_gre/ip6_gre, ipip, sit, ip6_tunnel, vti/vti6, xfrm_interface, vrf, ifb, nlmon, hsr, vcan, vxcan, tls |
| nftables rules (`nft`) | 40 | nf_tables, nft_ct, nft_nat, nft_masq, nft_redir, nft_reject (inet, bridge), nft_fib, nft_socket, nft_tproxy, nft_synproxy, nft_osf, nft_queue, nft_xfrm, nft_hash, nft_numgen, nft_limit, nft_quota, nft_log, nft_connlimit, nft_dup_netdev, nf_flow_table, ... |
| `tc` qdiscs, filters and actions | 37 | sch_{netem,cake,htb,hfsc,qfq,drr,taprio,cbs,etf,fq,fq_pie,pie,hhf,sfb,sfq,multiq,mqprio,skbprio,plug,prio,codel,ingress}, cls_{u32,flower,bpf,basic,matchall,fw,route,cgroup,flow}, act_{ct,ctinfo,connmark} |

Debian already removes the autoload aliases of DCCP, RDS, TIPC, X.25, AX.25 and similar families. The modules are still shipped, and root can load them.

**Device-driven autoload (counted, not exercised):** 350 modules carry `usb:` aliases and 620 carry `pci:` aliases. A USB device plugged into any box makes udev load whichever driver matches it: media (580 modules), sound (349), HID (129), IIO (300), storage (uas, usb_storage) and network adapters (cdc_ether, cdc_ncm, rndis_host). `dev.tty.ldisc_autoload=1` also lets any process that holds a tty load the 11 `tty-ldisc-*` modules.

## Needs per box (what the code in this repository actually uses)

"Needed" means something in `broker/`, `image/` or a brief uses it. "Root only" means the box needs the feature but no unprivileged process needs to trigger it. Hardware entries are from the briefs, and drivers for hardware that has not arrived are marked unverified.

| Item | Core | Edge | Enforcer | Evidence |
|---|---|---|---|---|
| IPv4, IPv6, Unix, netlink route, AF_PACKET (built in) | yes | yes | yes | networkd's DHCP client; `broker/netguard/netlink_linux.go`; dnsmasq on the enforcer (ENF decision 5) |
| nf_tables | root only (inet, bridge) | root only | root only (inet, NAT, VLAN sets) | `image/mkosi/mkosi.extra/usr/lib/agentos/inbound.nft`, `broker/netguard/inbound.go` (`table bridge`), ENF decision 4 |
| 802.1Q VLANs, bridge | bridge family only | no | yes | ENF per-device VLANs (`broker/enforcer/nft`, `dns`, `wol`) |
| User namespaces | root only (agentosd starts runsc; the inference supervisor clones with `CLONE_NEWUSER` from root, `broker/infer/supervise/supervise.go` `jail`) | no planner, no sandbox (HW-15) | no (radio confinement filters `unshare`/`setns`, `broker/enforcer/radio/confine/filter.go`) | Nothing creates one unprivileged on the host. Codex's bwrap runs inside the gVisor sandbox, whose namespaces are gVisor's own. |
| Unprivileged BPF | no | no | no | Already off |
| Privileged BPF | yes (systemd `DeviceAllow=`) | yes | yes | image units |
| io_uring | none found | none found | none found | Go's runtime and gVisor's systrap platform do not use host io_uring (inference; part b's boot test confirms) |
| AF_ALG | root only, at most (cryptsetup may probe a cipher through it when formatting, inference) | no | no | `cryptsetup-bin` in `mkosi.conf` |
| SCTP, L2TP, PPP, AppleTalk, ATM, CAN, NFC, Phonet, QRTR, RxRPC, KCM, SMC, AF_KEY, VSOCK, MPLS, IPVS, Open vSwitch, WireGuard, GTP, MACsec, batman-adv, NBD, cfg80211/mac80211 | no | no | no | No use in code or briefs; the core and the edge never turn on Wi-Fi (D-178) |
| Tunnels and virtual links (vxlan, geneve, gre, ipip, sit, vti, bond, team, vrf, veth, dummy) | no | no | VLAN only | gVisor runs `--network=none` or `host`, so it needs no veth or tun |
| tc qdiscs, classifiers, actions | fq_codel only (built in, the default qdisc) | same | same | No `tc` use in code |
| KVM, vhost, tun | not today (runsc runs on the default systrap platform, with no `-platform` flag) | no | no | PLN-6 allows a microVM later (S5 browser): keep KVM on the core only if that path is taken |
| Filesystems | ext4 (root), vfat (ESP), erofs (`/usr`), dm-verity, dm-crypt, tmpfs, proc, sysfs, cgroup2, devpts, mqueue, securityfs, bpf | ext4, vfat, erofs, verity | same as the edge, with dm-crypt if it seals | `image/mkosi/mkosi.repart`; all other 50-odd filesystems unused (overlay included: guests use `--overlay2=none`) |
| GPU and NPU | amdgpu, i915, xe, intel_vpu, amdxdna (whichever the box has) | no | no | `broker/accel/accel.go` (inference, core only) |
| TPM 2.0 (`tpm_crb`, `tpm_tis`, built in) | yes (`/dev/tpmrm0`, sealed store) | not used today | yes if its image seals (ENF slice m) | `broker/tpmseal`, units' `DeviceAllow=/dev/tpmrm0` |
| Cellular modem | option, usb_wwan, usbserial (AT over ttyUSB, owner line) | the same (second line) | no | `broker/modem/at/udev/71-agentos-modem.rules`; no QMI, MBIM or PPP data path (calls ride SIP over IP, `broker/modem/sipline`) |
| USB Ethernet | for the edge link when ports 1 and 2 are taken (r8152, ax88179_178a, cdc_ether) | the same, on the edge's end | no | HW-15; I19 holds any other USB link down, but the driver still loads |
| Thread, Zigbee and Bluetooth radios | no (Bluetooth already blocked) | no (the same) | btusb plus bluetooth; cdc_acm or cp210x for the nRF52840 and EFR32 dongles | ENF decision 11, slice j |
| Wired NIC | Realtek r8169 (M6 Ultra, unverified) | r8169 (NucBox 5, unverified) | Intel igc (V1410's i226-V, unverified) | `hardware/M6-hardware-test-steps.md`; check with `lspci -k` when the hardware arrives |
| 32-bit and x32 ABIs, `modify_ldt`, `uselib` | no | no | no | Go amd64 binaries, llama-server amd64; gVisor runs no 32-bit guests |
| kexec, hibernation | no | no | no | A/B update reboots through systemd-boot (UPD-1) |
| tty line disciplines beyond n_tty | no | no | no | The modem uses the default discipline |
| Media, sound, IIO, HID, comedi, InfiniBand, MTD, watchdogs other than the board's | no | no | the board's watchdog (NET-2 Hardening) | Cameras and the drone reach the core over the network (`image/camnode`) |

**Reading across the table:** no box needs unprivileged user namespaces, io_uring, unprivileged AF_ALG, any socket family outside inet, inet6, unix, netlink and packet, any tc beyond fq_codel, or the 32-bit ABIs. By estimate, each box needs well under 100 of the 4,230 modules: the rows above plus their dependencies. Part b produces the exact list from `lsmod` on a booted box per role.

## What part b can turn off without changing the kernel binary

Debian's own kernel already provides these knobs. Part b sets them in `image/` and its boot tests check each one on the booted box. They are listed here as inputs to part b, not decided here.

- `kernel.unprivileged_userns_clone=0`: closes the 188 namespace-only modules, and the namespace path into code already loaded, such as nf_tables. (Part b's boot test must show runsc and the inference supervisor still start; both clone from root.)
- `kernel.io_uring_disabled=2`, `kernel.kexec_load_disabled=1`, `dev.tty.ldisc_autoload=0`, `kernel.sysrq=0`, `kernel.kptr_restrict=2`, `kernel.yama.ptrace_scope=2` (or 3), `fs.protected_fifos=1`, `fs.protected_regular=2`, `net.core.bpf_jit_harden=2`.
- `ia32_emulation=0`, `lockdown=integrity` (so a box booted with Secure Boot off still locks down) and `module.sig_enforce=1` on the command line. The command line is covered by TPM measurement (HW-5a), not by Secure Boot.
- Remove the unneeded module files from the image (`/usr` is erofs on dm-verity, so a removed module cannot come back by autoload), or blocklist them per role with `install <m> /bin/false`, which the image already does for Bluetooth. Part b checks whether mkosi v24.3's `KernelModulesExclude=` applies to the main image. If it does not, `RemoveFiles=` does.
- `kernel.modules_disabled=1` once boot has loaded what the box needs. This is one-way until reboot, and it is the only Debian-kernel knob that stops root from loading a Debian-signed module brought in from writable storage. Its cost: a USB device of a new class, plugged in after boot, gets no driver until the next reboot (the weekly reboot already exists, UPD-10).

What these knobs cannot remove: built-in code (io_uring, x32, the user-namespace code itself, AF_PACKET, XDP sockets, MPTCP, the LSMs) stays in the binary, reachable only through the paths left open. Only a kernel we configure and sign removes it.

## Design forks found (for Mark, through the coordinator; not decided here)

1. **Our own signed kernel vs Debian-signed plus the knobs above.** HW-5 says MUST boot "only a distribution-signed boot loader and kernel, so no per-PC key enrollment is needed". Our own kernel needs either our own Microsoft-signed shim (deferred past MVP, risk 11) or a MOK key enrolled on each PC, which HW-5 rules out. So our own kernel needs a SPEC change. The same holds for IPE policies that pin modules to `/usr`, because they need a key in the machine or secondary keyring. Part c measures how much CVE history the knobs above remove compared with a trimmed build. That is the evidence for the card.
2. **One image for the core and the edge (HW-10) vs per-box module sets.** The edge needs no GPU, sandbox or inference drivers, but HW-10 gives it the core's image. Part b can either keep one image with a role-selected blocklist at boot (the role must then come from something the edge can't forge, such as the enrolled link), or ship a separate edge image. The enforcer already gets its own image (D-229).

## Unowned gaps

- The board's actual NICs, TPM interface and USB IDs are unverified until the hardware arrives. Part b's lists are by class, with the board's drivers added from `lspci -k` and `lsusb -t` on arrival.
- Lockdown under Secure Boot was configured, not observed. Part b's boot test reads `/sys/kernel/security/lockdown` on the CI Secure Boot boot (`image/ci_boot.sh` already boots with OVMF Secure Boot).

## Appendix: the probe

`probe.go` (`CGO_ENABLED=0 go build`). It reads `modules.alias` and tries every name of one trigger kind:

```go
// probe: tries each autoload trigger named in modules.alias, as whatever user runs it.
// Usage: probe sock|genl|alg|mount ALIASFILE
package main

import ("bufio"; "encoding/binary"; "os"; "strconv"; "strings"; "syscall"; "unsafe")

func aliases(path, prefix string) (out []string) {
	f, _ := os.Open(path); defer f.Close()
	seen := map[string]bool{}
	for s := bufio.NewScanner(f); s.Scan(); {
		w := strings.Fields(s.Text())
		if len(w) == 3 && strings.HasPrefix(w[1], prefix) && !seen[w[1]] {
			seen[w[1]] = true; out = append(out, strings.TrimPrefix(w[1], prefix))
		}
	}
	return
}

func sock(path string) {
	types := []int{1, 2, 3, 5} // stream, dgram, raw, seqpacket
	for af := 1; af < 46; af++ { for _, t := range types { if fd, err := syscall.Socket(af, t, 0); err == nil { syscall.Close(fd) } } }
	for _, a := range aliases(path, "net-pf-") { // net-pf-X-proto-Y[-type-Z]
		p := strings.Split(a, "-")
		if len(p) < 3 || p[1] != "proto" { continue }
		af, _ := strconv.Atoi(p[0]); pr, err := strconv.Atoi(p[2]); if err != nil { continue }
		ts := types
		if len(p) >= 5 && p[3] == "type" { t, _ := strconv.Atoi(p[4]); ts = []int{t} }
		for _, t := range ts { if fd, err := syscall.Socket(af, t, pr); err == nil { syscall.Close(fd) } }
	}
}

func genl(path string) { // CTRL_CMD_GETFAMILY by name
	for _, a := range aliases(path, "net-pf-16-proto-16-family-") {
		fd, err := syscall.Socket(16, 3, 16); if err != nil { return }
		name := append([]byte(a), 0); alen := 4 + len(name)
		msg := make([]byte, 16+4+(alen+3)&^3)
		binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
		binary.LittleEndian.PutUint16(msg[4:], 16); binary.LittleEndian.PutUint16(msg[6:], 1)
		msg[16], msg[17] = 3, 1
		binary.LittleEndian.PutUint16(msg[20:], uint16(alen)); binary.LittleEndian.PutUint16(msg[22:], 2)
		copy(msg[24:], name)
		syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: 16})
		buf := make([]byte, 8192); syscall.Recvfrom(fd, buf, 0); syscall.Close(fd)
	}
}

type sockaddrALG struct { family uint16; typ [14]byte; feat, mask uint32; name [64]byte }

func alg(path string) {
	for _, a := range aliases(path, "crypto-") {
		for _, t := range []string{"hash", "skcipher", "aead", "rng", "akcipher"} {
			fd, err := syscall.Socket(38, 5, 0); if err != nil { return }
			sa := sockaddrALG{family: 38}; copy(sa.typ[:], t); copy(sa.name[:], a)
			syscall.Syscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
			syscall.Close(fd)
		}
	}
}

func mount(path string) {
	os.MkdirAll("/tmp/m", 0o755)
	for _, a := range aliases(path, "fs-") { syscall.Mount("none", "/tmp/m", a, 0, ""); syscall.Unmount("/tmp/m", 0) }
}

func main() {
	map[string]func(string){"sock": sock, "genl": genl, "alg": alg, "mount": mount}[os.Args[1]](os.Args[2])
}
```

`/init` (busybox `sh`). The util-linux and iproute2 binaries are copied in as `xsetpriv`, `xunshare`, `xip`, `xtc` and `xnft`, so busybox's applets of the same name don't shadow them:

```sh
A=/lib/modules/$(uname -r)/modules.alias
snap() { cut -d' ' -f1 /proc/modules | sort > /tmp/m.$1; }
run() { snap a; xsetpriv --reuid=1000 --regid=1000 --clear-groups sh -c "$2" >/dev/null 2>&1; snap b
        echo "@@load $1: $(grep -vxF -f /tmp/m.a /tmp/m.b | tr '\n' ' ')"; }
cat /sys/kernel/security/lockdown /sys/kernel/security/lsm   # and each sysctl in the tables
for s in sock genl alg mount; do run unpriv-$s "probe $s $A"; done
for s in sock genl alg; do run userns-$s "xunshare -Urn probe $s $A"; done
run userns-mount "xunshare -Urn xunshare -m probe mount $A"
run userns-link "xunshare -Urn sh -c 'for t in dummy veth bridge bond team vlan macvlan macvtap ipvlan ipvtap vxlan geneve gre gretap ip6gre ip6gretap ipip sit ip6tnl vti vti6 ifb nlmon vrf wireguard can vcan vxcan netdevsim batadv hsr xfrm bareudp amt macsec gtp erspan ip6erspan; do xip link add l\$t type \$t; done'"
run userns-nft "xunshare -Urn nftstage"   # inet/ip/bridge/netdev/arp tables, ~30 rule expressions, NAT, flowtable, sets
run userns-tc  "xunshare -Urn tcstage"    # each qdisc as root on a dummy, then clsact with each classifier and action
```

`nftstage` adds one rule per expression (counter, limit, quota, log, reject, ct, meta, fib, numgen, jhash, queue, socket, osf, dup, ct count, tcp option, synproxy, secpath, ipsec, exthdr, tproxy, rt, ct helper, nftrace, fwd), plus masquerade, snat and redirect chains, a bridge and a netdev chain, a flowtable and three set types. `tcstage` adds each of pfifo, bfifo, pfifo_fast, prio, multiq, red, sfb, sfq, tbf, cbs, etf, taprio, gred, netem, drr, mqprio, skbprio, choke, qfq, codel, fq_codel, cake, fq, fq_pie, hhf, pie, plug, ets, hfsc and htb as the root qdisc of a dummy link, then the classifiers u32, flower, bpf, basic, matchall, fw, route, cgroup and flow, and the actions gact, mirred, pedit, skbedit, csum, vlan, tunnel_key, nat, police, connmark, ctinfo, ct, mpls, skbmod, ife, sample, gate and simple. Commands that fail without arguments still count when the module loads before the argument check, which is the property measured.
