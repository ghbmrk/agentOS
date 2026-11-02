package confine

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// REQ: NET-2

// liveArg makes this test binary the live probe: root of a user, mount and
// network namespace of its own, so it holds every capability over them and
// the kernel allows each namespace and mount call; it installs the named
// filter and reports each call's errno.
const liveArg = "confine-live-probe"

// liveUID is the host user the probe's namespace root maps to: never root.
const liveUID = 4249

func TestMain(m *testing.M) {
	Trampoline()
	if len(os.Args) == 2 && os.Args[1] == exitArg {
		os.Exit(0)
	}
	if len(os.Args) == 4 && os.Args[1] == viewArg {
		os.Exit(viewProbe(os.Args[2], os.Args[3]))
	}
	if len(os.Args) == 4 && os.Args[1] == liveArg {
		os.Exit(liveProbe(os.Args[2], os.Args[3]))
	}
	os.Exit(m.Run())
}

// liveCase is one namespace or mount call the live probe makes. entry names
// the deny-list line that refuses it ("" for clone, which the filter
// refuses by flag); args builds its arguments in the probe, from its
// directory and the descriptors it set up before the filter.
type liveCase struct {
	name  string
	entry string
	nr    uintptr
	args  func(p *probeState) [6]uintptr
}

// probeState is what the probe holds before the filter goes on.
type probeState struct {
	dir                   string
	netns, tree, fs, made uintptr // own netns; a detached clone of t/; a tmpfs context; a created one
	keep                  [][]byte
}

func (p *probeState) str(s string) uintptr {
	b := append([]byte(s), 0)
	p.keep = append(p.keep, b)
	return uintptr(unsafe.Pointer(&b[0]))
}

func (p *probeState) path(name string) uintptr { return p.str(filepath.Join(p.dir, name)) }

const (
	moveMountFEmpty   = 0x4
	fsconfigCmdCreate = 6
)

// liveCases is every filter rule the live probes claim: each of
// stacks_test.go's namespace and mount keys, and the other mount calls
// on the list but pivot_root, open_tree_attr, statmount and listmount. The interpreter model
// (TestFilterDeniesEachEntry) covers every line of the list; this table
// shows the kernel itself refusing these with the filter's EPERM, in a
// process the kernel would otherwise let make them.
var liveCases = []liveCase{
	{"unshare-user", "unshare", syscall.SYS_UNSHARE, func(*probeState) [6]uintptr { return [6]uintptr{syscall.CLONE_NEWUSER} }},
	{"unshare-mnt", "unshare", syscall.SYS_UNSHARE, func(*probeState) [6]uintptr { return [6]uintptr{syscall.CLONE_NEWNS} }},
	{"clone-net", "", sysClone, func(*probeState) [6]uintptr { return [6]uintptr{syscall.CLONE_NEWNET | uintptr(syscall.SIGCHLD)} }},
	{"clone-user", "", sysClone, func(*probeState) [6]uintptr { return [6]uintptr{syscall.CLONE_NEWUSER | uintptr(syscall.SIGCHLD)} }},
	{"setns", "setns", sysSetns, func(p *probeState) [6]uintptr { return [6]uintptr{p.netns, syscall.CLONE_NEWNET} }},
	{"mount", "mount", syscall.SYS_MOUNT, func(p *probeState) [6]uintptr {
		return [6]uintptr{p.str("none"), p.path("m"), p.str("tmpfs"), 0, p.str("")}
	}},
	{"umount2", "umount2", syscall.SYS_UMOUNT2, func(p *probeState) [6]uintptr { return [6]uintptr{p.path("u")} }},
	{"chroot", "chroot", syscall.SYS_CHROOT, func(p *probeState) [6]uintptr { return [6]uintptr{p.str("/")} }},
	{"fsopen", "fsopen", 430, func(p *probeState) [6]uintptr { return [6]uintptr{p.str("tmpfs")} }},
	{"fsconfig", "fsconfig", 431, func(p *probeState) [6]uintptr { return [6]uintptr{p.fs, fsconfigCmdCreate} }},
	{"fsmount", "fsmount", 432, func(p *probeState) [6]uintptr { return [6]uintptr{p.made} }},
	{"fspick", "fspick", 433, func(p *probeState) [6]uintptr { return [6]uintptr{atFdcwd, p.path("t")} }},
	{"open_tree", "open_tree", 428, func(p *probeState) [6]uintptr { return [6]uintptr{atFdcwd, p.path("t"), openTreeClone} }},
	{"move_mount", "move_mount", 429, func(p *probeState) [6]uintptr {
		return [6]uintptr{p.tree, p.str(""), atFdcwd, p.path("v"), moveMountFEmpty}
	}},
	{"mount_setattr", "mount_setattr", 442, func(p *probeState) [6]uintptr {
		attr := make([]byte, 32) // struct mount_attr: attr_set first
		attr[0] = mountAttrNosuid
		p.keep = append(p.keep, attr)
		return [6]uintptr{atFdcwd, p.path("t"), 0, uintptr(unsafe.Pointer(&attr[0])), 32}
	}},
}

// probeDirs are the probe's mount points: t and u get a tmpfs before the
// filter (fspick, open_tree, mount_setattr and umount2 need a mount root
// of the probe's own), m and v take new mounts.
var probeDirs = []string{"t", "u", "m", "v"}

// attempt makes one call in a single-threaded child forked for it, so the
// kernel sees one thread (it refuses unshare(CLONE_NEWUSER) to a threaded
// caller with EINVAL, which a probe would misread as a refusal) and a
// namespace it makes ends with it; a mount change stays in the probe's
// mount namespace, which ends with the probe. The child inherits the
// filter. It
// returns the call's errno, 0 for success, or an error when the child did
// not exit (the filter killed it).
func attempt(nr uintptr, a [6]uintptr) (syscall.Errno, error) {
	pid, e := forkCall(nr, a)
	if e != 0 {
		return 0, fmt.Errorf("fork: %v", e)
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return 0, err
	}
	if !ws.Exited() {
		return 0, fmt.Errorf("child ended by %v", ws.Signal())
	}
	return syscall.Errno(ws.ExitStatus()), nil
}

// forkCall forks; the child makes the call and exits with its errno. The
// child runs only raw system calls, with no stack check, as the runtime's
// own fork does.
//
//go:nosplit
func forkCall(nr uintptr, a [6]uintptr) (int, syscall.Errno) {
	pid, _, e := syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if e == 0 && pid == 0 {
		_, _, e = syscall.RawSyscall6(nr, a[0], a[1], a[2], a[3], a[4], a[5])
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, uintptr(e), 0, 0)
	}
	return int(pid), e
}

// liveProbe sets up its mounts and descriptors, installs the filter the
// variant names ("none", "shipped", or "drop:<entry>", the shipped list
// without that line), makes each case's call and prints {case: errno}.
func liveProbe(variant, dir string) int {
	fail := func(err error) int {
		fmt.Fprintf(os.Stderr, "live probe: %v\n", err)
		return 2
	}
	p := &probeState{dir: dir}
	for _, d := range []string{"t", "u"} {
		if err := syscall.Mount("none", filepath.Join(dir, d), "tmpfs", 0, ""); err != nil {
			return fail(fmt.Errorf("mount %s: %w", d, err))
		}
	}
	f, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fail(err)
	}
	p.netns = f.Fd()
	sys := func(what string, nr uintptr, a ...uintptr) uintptr {
		var v [6]uintptr
		copy(v[:], a)
		r, _, e := syscall.Syscall6(nr, v[0], v[1], v[2], v[3], v[4], v[5])
		if e != 0 {
			panic(fmt.Sprintf("live probe: %s: %v", what, e))
		}
		return r
	}
	p.tree = sys("open_tree", 428, atFdcwd, p.path("t"), openTreeClone)
	p.fs = sys("fsopen", 430, p.str("tmpfs"))
	p.made = sys("fsopen", 430, p.str("tmpfs"))
	sys("fsconfig", 431, p.made, fsconfigCmdCreate)

	args := make([][6]uintptr, len(liveCases))
	for i, c := range liveCases {
		args[i] = c.args(p)
	}
	fam := slices.Sorted(slices.Values(Thread(1, 1, "/s", "/r", "/d").Families))
	switch {
	case variant == "none":
	case variant == "shipped":
		if err := install(filter(fam)); err != nil {
			return fail(err)
		}
	case strings.HasPrefix(variant, "drop:"):
		mutant := slices.DeleteFunc(slices.Clone(denyList), func(d denied) bool { return d.Name == variant[5:] })
		if len(mutant) != len(denyList)-1 {
			return fail(fmt.Errorf("%s: no such line", variant))
		}
		if err := install(filterOf(mutant, fam)); err != nil {
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("variant %q", variant))
	}
	out := map[string]int{}
	for i, c := range liveCases {
		e, err := attempt(c.nr, args[i])
		if err != nil {
			return fail(fmt.Errorf("%s: %w", c.name, err))
		}
		out[c.name] = int(e)
	}
	// The calls point at p's strings and use f's descriptor.
	runtime.KeepAlive(p)
	runtime.KeepAlive(f)
	json.NewEncoder(os.Stdout).Encode(out)
	return 0
}

// liveVerdict reads one call: "refused" only when the kernel allows it
// without a filter (control 0) and the filter gives EPERM; "allowed" when
// the filter let it through; otherwise "untested: <reason>", since a
// refusal the kernel makes on its own says nothing of the filter.
func liveVerdict(control, filtered syscall.Errno) string {
	switch {
	case control != 0:
		return fmt.Sprintf("untested: the kernel refuses it without the filter (%v)", control)
	case filtered == syscall.EPERM:
		return "refused"
	case filtered == 0:
		return "allowed"
	}
	return fmt.Sprintf("untested: %v, not the filter's EPERM", filtered)
}

// TestFilterRefusesLive (NET-2 Confined radio stacks): in a process that
// holds every capability over its own user, mount and network namespaces,
// each namespace and mount call the live probes claim succeeds with no
// filter and gets the filter's EPERM under the shipped one, so the refusal
// is the filter's and not the kernel's capability check (#4233, from
// #4125's combined review). Mutation: with any one of those deny-list
// lines dropped from a synthetic filter, its calls go through, so the
// probe fails. Catches a filter edit that drops a namespace or mount line
// while the kernel's capability checks keep the confined stacks' own
// probe green.
func TestFilterRefusesLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to map the probe's user namespace to its own user")
	}
	dir, err := os.MkdirTemp("", "confine")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range probeDirs {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(dir, "confine.test")
	b, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, b, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(variant string) map[string]syscall.Errno {
		t.Helper()
		var stderr strings.Builder
		cmd := exec.Command(bin, liveArg, variant, dir)
		cmd.Env = []string{}
		cmd.Stderr = &stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: liveUID, Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: liveUID, Size: 1}},
			// Root of its namespace, which is liveUID outside, with no
			// supplementary group kept from the test's own root.
			Credential:                 &syscall.Credential{Uid: 0, Gid: 0, Groups: []uint32{}},
			GidMappingsEnableSetgroups: true,
			Pdeathsig:                  syscall.SIGKILL,
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("probe %s: %v\n%s", variant, err, stderr.String())
		}
		got := map[string]syscall.Errno{}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("probe %s: %v: %q", variant, err, out)
		}
		return got
	}

	control, shipped := run("none"), run("shipped")
	for _, c := range liveCases {
		v := liveVerdict(control[c.name], shipped[c.name])
		t.Logf("%-14s %s", c.name, v)
		if v != "refused" {
			t.Errorf("%s under the shipped filter: %s, want refused", c.name, v)
		}
	}
	entries := map[string]bool{}
	for _, c := range liveCases {
		if c.entry != "" {
			entries[c.entry] = true
		}
	}
	for _, e := range slices.Sorted(maps.Keys(entries)) {
		mutant := run("drop:" + e)
		for _, c := range liveCases {
			if c.entry != e {
				continue
			}
			if v := liveVerdict(control[c.name], mutant[c.name]); v != "allowed" {
				t.Errorf("without its %s line, %s is %s: the live probe would not notice the line gone", e, c.name, v)
			}
		}
	}
}

// TestLiveCasesNameTheirLines (NET-2 Confined radio stacks): each live
// case calls the number of the deny-list line it names, and the clone
// cases carry a CLONE_NEW* flag, so a mutant that drops a line is the
// mutant of that case's call.
func TestLiveCasesNameTheirLines(t *testing.T) {
	for _, c := range liveCases {
		if c.entry == "" {
			if a := c.args(&probeState{}); c.nr != sysClone || a[0]&cloneNew == 0 {
				t.Errorf("%s: call %d flags %#x, want clone with a CLONE_NEW* flag", c.name, c.nr, a[0])
			}
			continue
		}
		i := slices.IndexFunc(denyList, func(d denied) bool { return d.Name == c.entry })
		if i < 0 || uintptr(denyList[i].Nr) != c.nr {
			t.Errorf("%s: calls %d, but the deny list's %s line is at %d", c.name, c.nr, c.entry, i)
		}
	}
}
