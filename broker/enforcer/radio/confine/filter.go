package confine

import (
	"syscall"
	"unsafe"
)

const (
	auditArchX8664 = 0xc000003e
	retAllow       = 0x7fff0000
	retKill        = 0x80000000 // SECCOMP_RET_KILL_PROCESS
	retErrno       = 0x00050000 // SECCOMP_RET_ERRNO
	x32Bit         = 0x40000000

	sysClone      = 56
	sysClone3     = 435
	sysSocket     = 41
	sysSocketpair = 53
	sysSeccomp    = 317

	// cloneNew is every CLONE_NEW* flag clone(2) takes: NEWNS, NEWCGROUP,
	// NEWUTS, NEWIPC, NEWUSER, NEWPID, NEWNET.
	cloneNew = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000
)

// denied are syscalls no radio stack needs (spikes/ENF-radio): they widen
// what an exploit of the stack reaches (other namespaces, mounts, the
// kernel's attack surface, other processes). x86-64 numbers. A per-stack
// allowlist recorded on hardware replaces this list later (ASSUMPTIONS
// ENF-k-3); the deny list is the floor.
var denied = []uint32{
	101,           // ptrace
	165, 166, 155, // mount, umount2, pivot_root
	161, 272, 308, // chroot, unshare, setns
	321,      // bpf
	246, 320, // kexec_load, kexec_file_load
	175, 313, 176, // init_module, finit_module, delete_module
	250, 248, 249, // keyctl, add_key, request_key
	298, 323, // perf_event_open, userfaultfd
	310, 311, // process_vm_readv, process_vm_writev
	169, 167, 168, // reboot, swapon, swapoff
	163, 172, 173, // acct, iopl, ioperm
	425, 426, 427, // io_uring_setup, io_uring_enter, io_uring_register
	428, 429, 430, // open_tree, move_mount, fsopen (the new mount API)
	431, 432, 433, // fsconfig, fsmount, fspick
	442, // mount_setattr
}

type insn struct {
	code   uint16
	jt, jf uint8
	k      uint32
}

func stmt(code uint16, k uint32) insn  { return insn{code: code, k: k} }
func jeq(k uint32, jt, jf uint8) insn  { return insn{code: 0x15, jt: jt, jf: jf, k: k} }
func jset(k uint32, jt, jf uint8) insn { return insn{code: 0x45, jt: jt, jf: jf, k: k} }
func ldAbs(off uint32) insn            { return stmt(0x20, off) }
func ret(k uint32) insn                { return stmt(0x06, k) }
func errno(e syscall.Errno) uint32     { return retErrno | uint32(e) }

// filter builds the BPF program over struct seccomp_data (nr at 0, arch at
// 4, args[0]'s low word at 16): kill on another architecture or the x32
// ABI; EPERM for the denied calls, clone with a CLONE_NEW* flag, and
// socket or socketpair outside families; ENOSYS for clone3, whose flags
// seccomp cannot read, so libc falls back to clone.
func filter(families []int) []insn {
	p := []insn{
		ldAbs(4), jeq(auditArchX8664, 1, 0), ret(retKill),
		ldAbs(0), jset(x32Bit, 0, 1), ret(retKill),
	}
	for _, nr := range denied {
		p = append(p, jeq(nr, 0, 1), ret(errno(syscall.EPERM)))
	}
	p = append(p, jeq(sysClone3, 0, 1), ret(errno(syscall.ENOSYS)))
	p = append(p, jeq(sysClone, 0, 4), ldAbs(16), jset(cloneNew, 0, 1), ret(errno(syscall.EPERM)), ldAbs(0))
	// socket and socketpair: allow a listed family, refuse the rest.
	n := uint8(len(families))
	for _, nr := range []uint32{sysSocket, sysSocketpair} {
		p = append(p, jeq(nr, 0, n+3), ldAbs(16))
		for i, f := range families {
			p = append(p, jeq(uint32(f), n-uint8(i), 0))
		}
		p = append(p, ret(errno(syscall.EPERM)), ret(retAllow))
	}
	return append(p, ret(retAllow))
}

func install(prog []insn) error {
	fprog := struct {
		n    uint16
		_    [6]byte
		insn *insn
	}{n: uint16(len(prog)), insn: &prog[0]}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 38, 1, 0); e != 0 { // PR_SET_NO_NEW_PRIVS
		return e
	}
	// seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &fprog):
	// every thread of the Go runtime takes the filter, and exec keeps it.
	if _, _, e := syscall.RawSyscall(sysSeccomp, 1, 1, uintptr(unsafe.Pointer(&fprog))); e != 0 {
		return e
	}
	return nil
}
