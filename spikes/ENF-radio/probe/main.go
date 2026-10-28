// Command probe measures the confinement recipe ENF-j proposes for a radio
// stack: an unprivileged user, a private network namespace and a seccomp
// filter. It runs no radio stack; it runs the checks a stack's process would
// face. Linux x86-64 only. See ../README.md for how run.sh drives it.
//
//	probe exec <profile> -- cmd args...   install the profile's filter, then exec cmd
//	probe check <profile> <policy-file>   report what the confined process can do
//
// Profiles: "serial" (Zigbee: a serial device and nothing else, no IP sockets)
// and "thread" (Thread and the Matter controller: IPv6, but only inside a
// network namespace that holds lo and the stack's own tun interface).
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	auditArchX8664 = 0xc000003e
	retAllow       = 0x7fff0000
	retKill        = 0x80000000 // SECCOMP_RET_KILL_PROCESS
	retErrno       = 0x00050000 // SECCOMP_RET_ERRNO
	x32Bit         = 0x40000000
)

// denied are syscalls no radio stack needs: they widen what an exploit of the
// stack can reach (other namespaces, the kernel's attack surface, other
// processes). An allowlist recorded per stack on hardware replaces this in
// ENF-k; the deny list is the floor.
var denied = []uintptr{ // x86-64 numbers
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
}

type insn struct {
	code   uint16
	jt, jf uint8
	k      uint32
}

func stmt(code uint16, k uint32) insn  { return insn{code: code, k: k} }
func jeq(k uint32, jt, jf uint8) insn  { return insn{code: 0x15, jt: jt, jf: jf, k: k} }
func ldAbs(off uint32) insn            { return stmt(0x20, off) }
func ret(k uint32) insn                { return stmt(0x06, k) }
func errno(e syscall.Errno) uint32     { return retErrno | uint32(e) }
func jset(k uint32, jt, jf uint8) insn { return insn{code: 0x45, jt: jt, jf: jf, k: k} }

// filter builds the profile's BPF program over struct seccomp_data
// (nr at 0, arch at 4, args[0] low word at 16).
func filter(profile string) []insn {
	p := []insn{
		ldAbs(4), jeq(auditArchX8664, 1, 0), ret(retKill),
		ldAbs(0), jset(x32Bit, 0, 1), ret(retKill),
	}
	for _, nr := range denied {
		p = append(p, jeq(uint32(nr), 0, 1), ret(errno(syscall.EPERM)))
	}
	families := []uint32{syscall.AF_PACKET}
	if profile == "serial" {
		families = append(families, syscall.AF_INET, syscall.AF_INET6, syscall.AF_NETLINK)
	}
	p = append(p, jeq(syscall.SYS_SOCKET, 0, uint8(2+2*len(families))), ldAbs(16))
	for _, f := range families {
		p = append(p, jeq(f, 0, 1), ret(errno(syscall.EPERM)))
	}
	return append(p, ldAbs(0), ret(retAllow))
}

func install(profile string) error {
	prog := filter(profile)
	fprog := struct {
		n    uint16
		_    [6]byte
		insn *insn
	}{n: uint16(len(prog)), insn: &prog[0]}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 38, 1, 0); e != 0 { // PR_SET_NO_NEW_PRIVS
		return e
	}
	// seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, prog)
	if _, _, e := syscall.RawSyscall(317, 1, 1, uintptr(unsafe.Pointer(&fprog))); e != 0 {
		return e
	}
	return nil
}

func result(name string, err error, wantOK bool) bool {
	ok := (err == nil) == wantOK
	mark := "PASS"
	if !ok {
		mark = "FAIL"
	}
	got := "allowed"
	if err != nil {
		got = "refused: " + err.Error()
	}
	fmt.Printf("%s  %-46s %s\n", mark, name, got)
	return ok
}

func socket(family, typ int) error {
	fd, err := syscall.Socket(family, typ, 0)
	if err == nil {
		syscall.Close(fd)
	}
	return err
}

type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

func check(profile, policy string) bool {
	all := true
	pass := func(ok bool) { all = all && ok }
	status, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(l, "CapEff:") || strings.HasPrefix(l, "Seccomp:") || strings.HasPrefix(l, "NoNewPrivs:") {
			fmt.Println("info  " + strings.Join(strings.Fields(l), " "))
		}
	}
	fmt.Printf("info  uid=%d euid=%d (as seen inside its namespaces)\n", syscall.Getuid(), syscall.Geteuid())

	_, err := os.ReadFile(policy)
	pass(result("read the enforcer's policy file", err, false))
	pass(result("ptrace(PTRACE_ATTACH, 1)", ptrace(1), false))
	pass(result("unshare(CLONE_NEWNS)", syscall.Unshare(syscall.CLONE_NEWNS), false))
	pass(result("socket(AF_PACKET)", socket(syscall.AF_PACKET, syscall.SOCK_RAW), false))
	pass(result("socket(AF_UNIX) for the command interface", socket(syscall.AF_UNIX, syscall.SOCK_STREAM), true))

	ifs := interfaces()
	fmt.Printf("info  interfaces visible: %s\n", strings.Join(ifs, " "))
	if profile == "serial" {
		pass(result("socket(AF_INET)", socket(syscall.AF_INET, syscall.SOCK_DGRAM), false))
		pass(result("socket(AF_INET6)", socket(syscall.AF_INET6, syscall.SOCK_DGRAM), false))
		pass(result("socket(AF_NETLINK)", socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM), false))
		return all
	}
	pass(result("only lo and the stack's own interface", onlyOwn(ifs), true))
	pass(result("create tun wpan0 in its own namespace", tun("wpan0"), true))
	pass(result("bring wpan0 up (stack sets its own addresses)", up("wpan0"), true))
	pass(result("UDP to a LAN address (192.0.2.1:53)", dial(), false))
	return all
}

func ptrace(pid int) error {
	_, _, e := syscall.RawSyscall(syscall.SYS_PTRACE, syscall.PTRACE_ATTACH, uintptr(pid), 0)
	if e != 0 {
		return e
	}
	return nil
}

func interfaces() []string {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return []string{"(unreadable: " + err.Error() + ")"}
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n")[2:] {
		if i := strings.Index(l, ":"); i > 0 {
			out = append(out, strings.TrimSpace(l[:i]))
		}
	}
	return out
}

func onlyOwn(ifs []string) error {
	for _, n := range ifs {
		if n != "lo" && n != "wpan0" {
			return fmt.Errorf("sees %s", n)
		}
	}
	return nil
}

var tunFD = -1

func tun(name string) error {
	// TUN names a tun device node the launcher granted to the stack user, as
	// the image grants /dev/net/tun to the radio user (DeviceAllow).
	fd, err := syscall.Open(os.Getenv("TUN"), syscall.O_RDWR, 0)
	if err != nil {
		return err
	}
	var r ifreq
	copy(r.name[:], name)
	r.flags = syscall.IFF_TUN | syscall.IFF_NO_PI
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&r))); e != 0 {
		syscall.Close(fd)
		return e
	}
	tunFD = fd
	return nil
}

func up(name string) error {
	// Any family serves the flags ioctl; AF_INET because the CI kernel this
	// was measured on has no IPv6 (see README).
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(s)
	var r ifreq
	copy(r.name[:], name)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&r))); e != 0 {
		return e
	}
	r.flags |= syscall.IFF_UP
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&r))); e != 0 {
		return e
	}
	return nil
}

func dial() error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(s)
	return syscall.Connect(s, &syscall.SockaddrInet4{Port: 53, Addr: [4]byte{192, 0, 2, 1}})
}

func main() {
	a := os.Args
	switch {
	case len(a) >= 5 && a[1] == "exec" && a[3] == "--":
		if err := install(a[2]); err != nil {
			fmt.Fprintln(os.Stderr, "seccomp:", err)
			os.Exit(2)
		}
		err := syscall.Exec(a[4], a[4:], os.Environ())
		fmt.Fprintln(os.Stderr, "exec:", err)
		os.Exit(2)
	case len(a) == 4 && a[1] == "check":
		if !check(a[2], a[3]) {
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: probe exec <serial|thread> -- cmd... | probe check <serial|thread> <policy-file>")
		os.Exit(2)
	}
}
