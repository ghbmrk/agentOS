package confine

import (
	"bufio"
	"encoding/binary"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// REQ: NET-2

// run evaluates a seccomp program the way the kernel does, over the
// instructions filter emits, for one call: nr, the architecture word and
// the low words of its first arguments.
func run(t *testing.T, p []insn, nr, arch uint32, args ...uint32) uint32 {
	t.Helper()
	var data [64]byte
	binary.LittleEndian.PutUint32(data[0:], nr)
	binary.LittleEndian.PutUint32(data[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint32(data[16+8*i:], a)
	}
	var a uint32
	for pc := 0; pc < len(p); pc++ {
		i := p[pc]
		switch i.code {
		case 0x20: // ld [k]
			a = binary.LittleEndian.Uint32(data[i.k:])
		case 0x15: // jeq #k
			if a == i.k {
				pc += int(i.jt)
			} else {
				pc += int(i.jf)
			}
		case 0x45: // jset #k
			if a&i.k != 0 {
				pc += int(i.jt)
			} else {
				pc += int(i.jf)
			}
		case 0x06: // ret #k
			return i.k
		default:
			t.Fatalf("instruction %#x at %d not modelled", i.code, pc)
		}
	}
	t.Fatal("program fell off its end")
	return 0
}

// TestFilterDeniesEachEntry (NET-2 Confined radio stacks): every entry of
// the deny list is refused by the program the stacks get, and a mutant
// list missing any one entry lets that call through, so each line of the
// table is what refuses its call, apart from what the kernel would refuse
// anyway for want of a capability (ENF-j delta L3 finding 2, #3702).
func TestFilterDeniesEachEntry(t *testing.T) {
	fam := []int{syscall.AF_UNIX}
	eperm := errno(syscall.EPERM)
	for i, d := range denyList {
		if got := run(t, filter(fam), d.Nr, auditArchX8664, 0); got != eperm {
			t.Errorf("%s (%d): %#x, want EPERM", d.Name, d.Nr, got)
		}
		mutant := append(append([]denied{}, denyList[:i]...), denyList[i+1:]...)
		if got := run(t, filterOf(mutant, fam), d.Nr, auditArchX8664, 0); got != retAllow {
			t.Errorf("without its line, %s (%d) gets %#x: the line is not what refuses it", d.Name, d.Nr, got)
		}
	}
	p := filter(fam)
	for _, c := range []struct {
		what           string
		nr, arch, arg0 uint32
		want           uint32
	}{
		{"read", 0, auditArchX8664, 0, retAllow},
		{"clone3", sysClone3, auditArchX8664, 0, errno(syscall.ENOSYS)},
		{"clone, a thread", sysClone, auditArchX8664, syscall.CLONE_VM | syscall.CLONE_THREAD, retAllow},
		{"clone, a user namespace", sysClone, auditArchX8664, syscall.CLONE_NEWUSER, eperm},
		{"clone, a network namespace", sysClone, auditArchX8664, syscall.CLONE_NEWNET, eperm},
		{"socket, a listed family", sysSocket, auditArchX8664, syscall.AF_UNIX, retAllow},
		{"socket, another family", sysSocket, auditArchX8664, syscall.AF_PACKET, eperm},
		{"socketpair, another family", sysSocketpair, auditArchX8664, syscall.AF_INET, eperm},
		{"another architecture", 0, 0x40000003, 0, retKill},
		{"the x32 ABI", x32Bit | 0, auditArchX8664, 0, retKill},
	} {
		if got := run(t, p, c.nr, c.arch, c.arg0); got != c.want {
			t.Errorf("%s: %#x, want %#x", c.what, got, c.want)
		}
	}
	// Of netlink, a stack with the family gets only route netlink, and
	// every listed family around it still opens.
	fam = []int{syscall.AF_UNIX, syscall.AF_INET, syscall.AF_INET6, syscall.AF_NETLINK}
	p = filter(fam)
	for _, nr := range []uint32{sysSocket, sysSocketpair} {
		for _, f := range fam {
			if got := run(t, p, nr, auditArchX8664, uint32(f), syscall.SOCK_RAW, 0); got != retAllow {
				t.Errorf("call %d, family %d: %#x, want allowed", nr, f, got)
			}
		}
		for _, proto := range []uint32{syscall.NETLINK_NETFILTER, syscall.NETLINK_AUDIT, syscall.NETLINK_XFRM, syscall.NETLINK_GENERIC, 0xffff} {
			if got := run(t, p, nr, auditArchX8664, syscall.AF_NETLINK, syscall.SOCK_RAW, proto); got != eperm {
				t.Errorf("call %d, netlink protocol %d: %#x, want EPERM", nr, proto, got)
			}
		}
		if got := run(t, p, nr, auditArchX8664, syscall.AF_PACKET, syscall.SOCK_RAW, 0); got != eperm {
			t.Errorf("call %d, an unlisted family: %#x, want EPERM", nr, got)
		}
	}
}

// entryPoint matches the kernel's namespace and mount entry points by
// name, so a call the kernel adds to that class (as open_tree_attr was in
// Linux 6.15) must join the deny list.
var entryPoint = regexp.MustCompile(`mount|^fs(open|config|pick)|^open_tree|^pivot_root$|^chroot$|^unshare$|^setns$`)

// TestDenyListCoversKernel (NET-2 Confined radio stacks): every namespace
// and mount entry point in the build host's syscall table is on the deny
// list under its own number, and every list entry's number is the
// kernel's for its name (ENF-j delta L3 finding 1, #3702). clone and
// clone3 are refused by flag and by ENOSYS, outside the list.
func TestDenyListCoversKernel(t *testing.T) {
	var path string
	for _, p := range []string{"/usr/include/x86_64-linux-gnu/asm/unistd_64.h", "/usr/include/asm/unistd_64.h"} {
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("no unistd_64.h: install the kernel headers (linux-libc-dev)")
		}
		t.Skip("no unistd_64.h")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	kernel := map[string]uint32{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.Fields(sc.Text())
		if len(w) == 3 && w[0] == "#define" && strings.HasPrefix(w[1], "__NR_") {
			if n, err := strconv.ParseUint(w[2], 10, 32); err == nil {
				kernel[strings.TrimPrefix(w[1], "__NR_")] = uint32(n)
			}
		}
	}
	if len(kernel) < 300 {
		t.Fatalf("%s: read %d syscalls", path, len(kernel))
	}
	listed := map[string]uint32{}
	for _, d := range denyList {
		listed[d.Name] = d.Nr
		if nr, ok := kernel[d.Name]; ok && nr != d.Nr {
			t.Errorf("%s is %d on the list but %d in the kernel", d.Name, d.Nr, nr)
		}
	}
	for name, nr := range kernel {
		if entryPoint.MatchString(name) {
			if _, ok := listed[name]; !ok {
				t.Errorf("%s (%d) is a namespace or mount entry point missing from the deny list", name, nr)
			}
		}
	}
}
