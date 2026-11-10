package confine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/ghbmrk/agentos/broker/internal/netnstest"
)

// REQ: NET-2

// exitArg makes this test binary a stack that exits the moment it runs.
const exitArg = "confine-exit-probe"

// zombie reports whether pid has exited and is not yet reaped.
func zombie(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := bytes.LastIndexByte(b, ')')
	return i > 0 && i+2 < len(b) && b[i+2] == 'Z'
}

// TestStartHoldsUntilNetOpen (NET-2 Confined radio stacks; #4477): Start
// releases a stack only once it holds the stack's network namespace, so
// a stack that exits the moment it is released still starts. The test
// delays Start's open of the namespace by a second, watching the stack
// meanwhile: a held stack is still alive at the open, and starts. Catches
// a Start that releases the stack before the open, whose stack exits in
// the delay (a zombie has no namespace to open) and fails its own start.
func TestStartHoldsUntilNetOpen(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	dir, bin := viewDir(t)
	real := openNet
	t.Cleanup(func() { openNet = real })
	var exited bool
	openNet = func(pid int) (*os.File, error) {
		for end := time.Now().Add(time.Second); time.Now().Before(end) && !exited; {
			exited = zombie(pid)
			time.Sleep(5 * time.Millisecond)
		}
		return real(pid)
	}
	p := BLE(viewUID, viewUID)
	p.View = []Entry{{Path: filepath.Join(dir, vBus), Kind: Socket}}
	proc, conn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{exitArg}, Stderr: testWriter{t}})
	if exited {
		t.Error("the stack exited before Start opened its network namespace: it was released early")
	}
	if err != nil {
		t.Fatalf("a stack that exits at once failed its start: %v", err)
	}
	conn.Close()
	if err := proc.Wait(); err != nil {
		t.Errorf("the stack: %v", err)
	}
}

// TestStackDumpsNoCore (NET-2 Confined radio stacks; #4459): every stack
// starts with RLIMIT_CORE 0, soft and hard, and cannot raise it, so a
// crash writes no core holding its keys where another process sees it,
// whatever limit the enforcer itself runs with. Thread's profile holds
// capabilities in its user namespace, which do not reach the host's
// limits. Catches a Trampoline that leaves the enforcer's own limit on
// the stack.
func TestStackDumpsNoCore(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	var was syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &was); err != nil {
		t.Fatal(err)
	}
	// The enforcer's own limit as high as it goes, so a stack that kept it
	// would show it.
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: ^uint64(0), Max: ^uint64(0)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Setrlimit(syscall.RLIMIT_CORE, &was) })
	dir, bin := viewDir(t)
	at := func(n string) string { return filepath.Join(dir, n) }
	if err := os.Mkdir(at("run"), 0o755); err != nil {
		t.Fatal(err)
	}
	thread := threadProfile(viewUID, viewUID, at(vState), at("run"), devNull)
	thread.View = append(thread.View, Entry{Path: at(vBus), Kind: Socket})
	thread.Links = nil // the enforcer's links need CONFIG_DUMMY; this test is about the limit
	ble := BLE(viewUID, viewUID)
	ble.View = []Entry{{Path: at(vBus), Kind: Socket}, {Path: at(vState), Kind: Dir, Write: true}}
	for _, p := range []Profile{ble, thread, {Name: "noview", UID: viewUID, GID: viewUID, Families: []int{syscall.AF_UNIX}}} {
		t.Run(p.Name, func(t *testing.T) {
			proc, conn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{viewArg, "dial", dir},
				Dir: at(vState), Stderr: testWriter{t}})
			if err != nil {
				t.Fatal(err)
			}
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			r := readReport(t, proc, conn)
			if r.Core != [2]uint64{0, 0} {
				t.Errorf("RLIMIT_CORE %v, want 0 soft and hard", r.Core)
			}
			if r.CoreRaise != int(syscall.EPERM) {
				t.Errorf("raising RLIMIT_CORE: %v, want EPERM", syscall.Errno(r.CoreRaise))
			}
		})
	}
}

// TestStartRefusesRootAndJoinedLinks (NET-2 Confined radio stacks;
// #5140): Start refuses a profile with uid or gid 0, and a joining
// stack's NetAdmin or Links, each alone, before it forks; a join to a
// stack holding no namespace is ErrNoNet. A nil Proc's pid is 0. Catches
// a Start that drops either refusal, or reads one side of a compare only.
func TestStartRefusesRootAndJoinedLinks(t *testing.T) {
	plain := BLE(1, 1)
	plain.View = nil
	admin, links := plain, plain
	admin.NetAdmin = true
	links.Links = []string{"d0"}
	for _, c := range []struct {
		name string
		s    Spec
		want error
	}{
		{"uid 0", Spec{Profile: BLE(0, 1)}, ErrRoot},
		{"gid 0", Spec{Profile: BLE(1, 0)}, ErrRoot},
		{"joined NetAdmin", Spec{Profile: admin, Net: &Proc{}}, ErrJoin},
		{"joined links", Spec{Profile: links, Net: &Proc{}}, ErrJoin},
		{"joined, neither", Spec{Profile: plain, Net: &Proc{}}, ErrNoNet},
	} {
		c.s.Path = "/nonexistent"
		if proc, _, err := Start(c.s); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
			if err == nil {
				proc.Stop()
			}
		}
	}
	if pid := (*Proc)(nil).Pid(); pid != 0 {
		t.Errorf("a nil Proc's pid %d", pid)
	}
}

// leakCheck returns a check that, within a few seconds, this process is
// back to the descriptors and goroutines it holds now, with no thread
// left in another network namespace.
func leakCheck(t *testing.T) func(what string) {
	t.Helper()
	fds, gs := openFDs(t), runtime.NumGoroutine()
	return func(what string) {
		t.Helper()
		nfds, ngs, stray := 0, 0, []string(nil)
		for end := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			nfds, ngs, stray = openFDs(t), runtime.NumGoroutine(), strayThreads(t)
			if nfds <= fds && ngs <= gs && stray == nil || time.Now().After(end) {
				break
			}
		}
		if nfds > fds || ngs > gs || stray != nil {
			t.Errorf("%s: %d descriptors (%d before), %d goroutines (%d before), threads in another network namespace %v",
				what, nfds, fds, ngs, gs, stray)
		}
	}
}

// strayThreads lists this process's threads, the main one included, in a
// network namespace not the calling goroutine's. inNetns moves no step
// onto the main thread (TestStepLeavesTheMainThread), so the runtime ends
// every thread it moved (#5159, #5286).
func strayThreads(t *testing.T) []string {
	t.Helper()
	runtime.LockOSThread()
	own, err := os.Readlink("/proc/thread-self/ns/net")
	runtime.UnlockOSThread()
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	var stray []string
	for _, e := range tasks {
		if l, err := os.Readlink("/proc/self/task/" + e.Name() + "/ns/net"); err == nil && l != own {
			stray = append(stray, e.Name()+":"+l)
		}
	}
	return stray
}

// TestStepLeavesTheMainThread (NET-2 Confined radio stacks; #5286): a
// step that finds itself on the main thread runs on another thread, and
// the main thread is freed for the runtime to keep, so confine needs no
// lock on the main thread in the binary that links it. A locked thread
// other than the main one stands in for it, since the runtime never ends
// the real one. Catches a step run on the main thread, which would park
// it in the stack's namespace for good (#5159), and a main thread left
// locked, which the runtime would end (here) or park (there) as its
// goroutine exits.
func TestStepLeavesTheMainThread(t *testing.T) {
	defer func(f func() bool) { onMainThread = f }(onMainThread)
	var held int
	onMainThread = func() bool { return syscall.Gettid() == held }
	type result struct {
		held, ran int
		err       error
	}
	parked := make(chan struct{})
	defer close(parked)
	for range 10 {
		got := make(chan result, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if tid := syscall.Gettid(); tid == syscall.Getpid() {
				got <- result{held: tid} // the real main thread: kept busy, so the next try runs elsewhere
				<-parked
				return
			}
			held = syscall.Gettid()
			ran, errc := 0, make(chan error, 1)
			step(nil, func() error { ran = syscall.Gettid(); return nil }, nil, errc)
			err := <-errc
			got <- result{held, ran, err}
		}()
		r := <-got
		if r.held == syscall.Getpid() {
			continue
		}
		if r.err != nil || r.ran == 0 || r.ran == r.held {
			t.Fatalf("step on thread %d, held thread %d (%v): want it off the held thread", r.ran, r.held, r.err)
		}
		time.Sleep(500 * time.Millisecond) // a thread whose goroutine exits locked ends at once
		if _, err := os.Stat(fmt.Sprintf("/proc/self/task/%d", r.held)); err != nil {
			t.Errorf("the held thread ended: %v", err)
		}
		return
	}
	t.Fatal("every try ran on the main thread")
}

// TestStartLeavesNothingBehind (NET-2 Confined radio stacks; ENF-k-11;
// #5140): the enforcer's end of a stack's socket takes deadlines and
// reads EOF once the stack exits; a stack starts in / when its spec names
// no directory; InNet enters the stack's own namespace, again and again,
// where lo is up only for NetAdmin (or Links), and a joined stack runs in
// its host's; after Stop, InNet refuses. A
// started, stopped, joined, failed or refused start leaves no descriptor,
// goroutine or thread behind. Catches a Start that keeps the stack's end,
// a pipe or a namespace open, leaves its starting thread waiting, a
// blocking enforcer's end, a lost namespace check, or an InNet whose
// thread outlives it in the stack's namespace.
func TestStartLeavesNothingBehind(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	dir, bin := viewDir(t)
	p := BLE(viewUID, viewUID)
	p.View = nil
	check := leakCheck(t)

	proc, conn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{exitArg}, Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Errorf("the enforcer's end takes no deadline: %v", err)
	}
	if n, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("read after the stack exited: %d, %v, want EOF", n, err)
	}
	conn.Close()
	if err := proc.Stop(); err != nil {
		t.Errorf("a stack that exited 0: %v", err)
	}
	check("a stack that exited")

	host, hconn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{sleepArg}, Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	if wd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", host.Pid())); err != nil || wd != "/" {
		t.Errorf("a stack with no directory runs in %q, %v; want /", wd, err)
	}
	var ns [2]string
	for i := range ns {
		if err := host.InNet(func() (err error) { ns[i], err = os.Readlink("/proc/thread-self/ns/net"); return }); err != nil {
			t.Fatal(err)
		}
	}
	if own, _ := os.Readlink("/proc/thread-self/ns/net"); ns[0] == own || ns[1] != ns[0] {
		t.Errorf("InNet ran in %q, then %q; the enforcer is in %q", ns[0], ns[1], own)
	}
	// Only NetAdmin or Links has the enforcer set up links: lo stays down here.
	admin := p
	admin.NetAdmin = true
	netAdmin, aconn, err := Start(Spec{Profile: admin, Self: bin, Path: bin, Args: []string{sleepArg}, Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		proc *Proc
		up   bool
	}{{host, false}, {netAdmin, true}} {
		if err := c.proc.InNet(func() error {
			f, err := ifFlags("lo")
			if err == nil && f&syscall.IFF_UP != 0 != c.up {
				t.Errorf("lo flags %#x in a stack where lo up is %v", f, c.up)
			}
			return err
		}); err != nil {
			t.Error(err)
		}
	}
	aconn.Close()
	netAdmin.Stop()
	joined, jconn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{sleepArg}, Stderr: testWriter{t}, Net: host})
	if err != nil {
		t.Fatal(err)
	}
	if l, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", joined.Pid())); err != nil || l != ns[0] {
		t.Errorf("the joined stack runs in %q, %v; want its host's %q", l, err, ns[0])
	}
	jconn.Close()
	joined.Stop()
	hconn.Close()
	host.Stop()
	if err := host.InNet(func() error { t.Error("InNet ran in a stopped stack"); return nil }); err == nil {
		t.Error("InNet after Stop returned nil")
	}
	if _, _, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{sleepArg}, Net: host}); !errors.Is(err, ErrNoNet) {
		t.Errorf("a join to a stopped stack: %v, want ErrNoNet", err)
	}
	check("a stack entered twice, one joined to it, both stopped, and a join refused")

	if _, _, err := Start(Spec{Profile: p, Self: filepath.Join(dir, "missing"), Path: bin}); err == nil {
		t.Error("a start of a missing binary succeeded")
	}
	check("a start whose fork failed")

	real := openNet
	t.Cleanup(func() { openNet = real })
	refused := errors.New("refused")
	openNet = func(int) (*os.File, error) { return nil, refused }
	if _, _, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{sleepArg}, Stderr: testWriter{t}}); !errors.Is(err, refused) {
		t.Errorf("a namespace that would not open: %v, want its error", err)
	}
	openNet = real
	check("a start whose namespace would not open")
}

// TestStartDefaultsToItsOwnBinary (NET-2; #5140): a spec naming no Self
// starts this binary (os.Executable): the start either runs or fails
// naming it. Catches a Start that forks an empty path.
func TestStartDefaultsToItsOwnBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := BLE(viewUID, viewUID)
	p.View = nil
	proc, conn, err := Start(Spec{Profile: p, Path: "/nonexistent"})
	if err != nil {
		if !strings.Contains(err.Error(), exe) {
			t.Errorf("the start failed without naming %s: %v", exe, err)
		}
		return
	}
	conn.Close()
	if err := proc.Wait(); err == nil {
		t.Error("a stack of /nonexistent exited 0")
	}
}

// fdLimit sets this process's descriptor limit to its lowest free
// descriptor plus extra while fn runs.
func fdLimit(t *testing.T, extra uint64, fn func()) {
	t.Helper()
	var was syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &was); err != nil {
		t.Fatal(err)
	}
	free, err := syscall.Open("/dev/null", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	syscall.Close(free)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: uint64(free) + extra, Max: was.Max}); err != nil {
		t.Fatal(err)
	}
	defer syscall.Setrlimit(syscall.RLIMIT_NOFILE, &was)
	fn()
}

// TestStartReportsNoDescriptors (NET-2; #5140): with no descriptor
// left, Start fails with the socket pair's EMFILE; with two left, with
// the pipe's; and InNet into a running stack fails without running fn.
// Catches a Start or InNet that goes on past a failed call.
func TestStartReportsNoDescriptors(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	_, bin := viewDir(t)
	p := BLE(viewUID, viewUID)
	p.View = nil
	spec := Spec{Profile: p, Self: bin, Path: bin, Args: []string{sleepArg}}
	var err error
	fdLimit(t, 0, func() { _, _, err = Start(spec) })
	if err != syscall.EMFILE {
		t.Errorf("no descriptor left: %v, want the socket pair's EMFILE", err)
	}
	var se *os.SyscallError
	lowest := func() int {
		fd, err := syscall.Open("/dev/null", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		syscall.Close(fd)
		return fd
	}
	before := lowest()
	fdLimit(t, 2, func() { _, _, err = Start(spec) })
	if !errors.As(err, &se) || se.Syscall != "pipe2" || se.Err != syscall.EMFILE {
		t.Errorf("two descriptors left: %v, want the pipe's EMFILE", err)
	}
	// The failed pipe leaves both ends of the socket pair closed, not
	// held until a finalizer runs (#5152).
	if after := lowest(); after != before {
		t.Errorf("after the pipe's EMFILE the lowest free descriptor is %d, was %d: the socket pair leaked", after, before)
	}
	proc, conn, err := Start(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Stop()
	defer conn.Close()
	fdLimit(t, 0, func() {
		err = proc.InNet(func() error { t.Error("InNet ran with no descriptor for the namespace"); return nil })
	})
	if err == nil {
		t.Error("InNet with no descriptor left returned nil")
	}
}

// inFreshNet runs fn on a thread of its own in a fresh network namespace.
func inFreshNet(fn func() error) error {
	return inNetns(nil, func() error {
		if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
			return err
		}
		return fn()
	}, nil)
}

// ifFlags is the interface flags of link name, in this thread's namespace.
func ifFlags(name string) (uint16, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	var ifr [40]byte
	copy(ifr[:syscall.IFNAMSIZ-1], name)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return 0, e
	}
	return binary.NativeEndian.Uint16(ifr[syscall.IFNAMSIZ:]), nil
}

// TestSetupLinksSetsOnlyTheirFlags (NET-2 Confined radio stacks; #5140):
// setupLinks brings lo up and creates each link, up and multicast, with
// a dummy's own NOARP kept (it sets those flags and only those), once:
// a second create of the same name fails. It closes its socket, and with
// no descriptor left fails with the socket's EMFILE. Catches a request
// left out, a flag or change mask lost, an attribute left unpadded, or a
// kind left off.
func TestSetupLinksSetsOnlyTheirFlags(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root of a network namespace")
	}
	err := inFreshNet(func() error {
		fds := openFDs(t)
		if err := setupLinks(nil); err != nil {
			return err
		}
		if n := openFDs(t); n != fds {
			t.Errorf("setupLinks left %d descriptors open, %d before", n, fds)
		}
		if f, err := ifFlags("lo"); err != nil || f&syscall.IFF_UP == 0 {
			t.Errorf("lo flags %#x, %v; want up", f, err)
		}
		var err error
		fdLimit(t, 0, func() { err = setupLinks(nil) })
		if !errors.Is(err, syscall.EMFILE) {
			t.Errorf("no descriptor left: %v, want the socket's EMFILE", err)
		}
		if err := setupLinks([]string{"d0"}); err != nil {
			return err
		}
		const want = syscall.IFF_UP | syscall.IFF_MULTICAST | syscall.IFF_NOARP
		if f, err := ifFlags("d0"); err != nil || f&want != want {
			t.Errorf("d0 flags %#x, %v; want %#x", f, err, want)
		}
		if err := setupLinks([]string{"d0"}); !errors.Is(err, syscall.EEXIST) {
			t.Errorf("a second d0: %v, want EEXIST", err)
		}
		return nil
	})
	if errors.Is(err, syscall.EOPNOTSUPP) && !netnstest.Required() {
		t.Skipf("no dummy links here (CONFIG_DUMMY): %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// TestAckTakesOnlyItsOwn (NET-2; #5140): ack takes only the kernel's
// acknowledgement of its own request: not another request's, nor a
// dump's replies; on a silent socket it ends at ackWait, and a read that
// fails is that failure. Catches an ack that takes the first message, a
// wait with no receive timeout, or a failed read waited out.
func TestAckTakesOnlyItsOwn(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root of a network namespace")
	}
	real := ackWait
	t.Cleanup(func() { ackWait = real })
	ackWait = 200 * time.Millisecond
	err := inFreshNet(func() error {
		fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
		if err != nil {
			return err
		}
		defer syscall.Close(fd)
		msg := newLink("lo", "", syscall.IFF_UP, syscall.NLM_F_ACK)
		binary.NativeEndian.PutUint32(msg[8:], 5)
		if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
			return err
		}
		if err := ack(fd, 6); err != errNoAck {
			t.Errorf("request 5's ack read as 6's: %v", err)
		}
		dump := make([]byte, syscall.SizeofNlMsghdr+syscall.SizeofIfInfomsg)
		binary.NativeEndian.PutUint32(dump[0:], uint32(len(dump)))
		binary.NativeEndian.PutUint16(dump[4:], syscall.RTM_GETLINK)
		binary.NativeEndian.PutUint16(dump[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
		if err := request(fd, 8, dump); err != errNoAck {
			t.Errorf("a dump's replies read as its ack: %v", err)
		}
		done := make(chan error, 1)
		go func() { done <- ack(fd, 9) }()
		select {
		case err := <-done:
			if err != errNoAck {
				t.Errorf("a silent socket: %v, want errNoAck", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("ack on a silent socket waited past ackWait")
		}
		tcp, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer syscall.Close(tcp)
		if err := ack(tcp, 1); err != syscall.ENOTCONN {
			t.Errorf("a failed read: %v, want ENOTCONN", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestPathCallRefusesNUL (NET-2; #5140): a path holding NUL is an error
// before the call is made. Catches a pathCall that calls with no path.
func TestPathCallRefusesNUL(t *testing.T) {
	called := false
	if _, err := pathCall(0, "/a\x00b", func(uintptr) (uintptr, uintptr, syscall.Errno) { called = true; return 0, 0, 0 }); err == nil || called {
		t.Errorf("a NUL path: %v, called %v", err, called)
	}
}
