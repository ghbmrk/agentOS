// Package confine starts a radio stack as a confined process (NET-2
// Confined radio stacks; briefs/ENF.md decision 6, slice k): its own
// unprivileged user with no supplementary groups, a fresh empty network and
// IPC namespace (or, for the Matter controller, Thread's network namespace;
// slice t), no-new-privileges, an empty environment, and the seccomp
// filter spikes/ENF-radio measured, with socket families narrowed to the
// profile's list. Thread alone also gets a user namespace the enforcer
// creates as root, with CAP_NET_ADMIN and CAP_NET_RAW in it. A profile
// with a View (BLE's is the system bus socket) sees only those paths, in a
// mount namespace of its own (view.go). The process gets its command interface as fd 3, one end
// of a socket pair, and nothing else: it never opens a path to the
// enforcer, so the policy store and the page's socket stay its owner's
// files, unreadable to it.
//
// It is the one enforcer package besides the firewall loader that starts a
// process, and the only one that links unsafe (the seccomp program's
// address). Linux x86-64 only, the enforcer's hardware (decision 11).
package confine

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Profile is how one stack is confined.
type Profile struct {
	// Name names the stack in logs.
	Name string
	// UID and GID are the stack's own user and group, never root's and
	// never the enforcer's.
	UID, GID uint32
	// Families are the only socket families it may open.
	Families []int
	// NetAdmin puts the stack in a user namespace of its own, created by
	// the enforcer as root and mapping only the stack's user and group,
	// and gives it CAP_NET_ADMIN and CAP_NET_RAW there and nothing else,
	// so it can configure its own network namespace (a tun link, its
	// addresses and routes, raw ICMPv6) and no other. The stack never
	// creates a namespace itself: the filter refuses it, and the enforcer
	// turns unprivileged user namespaces off (KERNEL-trim, #4094).
	NetAdmin bool
	// Links are dummy links the enforcer creates, up and multicast, in
	// the stack's new network namespace before the stack runs, after
	// bringing lo up.
	Links []string
	// View, when set, is all of the file system the stack sees: its root
	// is an empty read-only tmpfs holding each listed path that exists,
	// bound read-only, nosuid and nodev at its own path, so a
	// Unix socket the list leaves out cannot be named. The stack's own
	// mount namespace is built in a user namespace created by the
	// enforcer as root, mapping only the stack's user and group, whose
	// CAP_SYS_ADMIN Trampoline drops before the exec. Not with NetAdmin.
	View []string
}

// BLE is the Bluetooth stack's profile: it reaches BlueZ over the system
// bus's Unix socket and nothing else, so no IP, netlink, packet or raw
// Bluetooth socket (BLE commissioning goes through BlueZ, never raw HCI),
// and the bus socket is the only file it sees (#4215).
func BLE(uid, gid uint32) Profile {
	return Profile{Name: "ble", UID: uid, GID: gid, Families: []int{syscall.AF_UNIX}, View: []string{SystemBus}}
}

// Thread is the Thread stack's profile (ot-daemon; D-231): its own user
// and network namespace holding lo, the wpan0 it creates from a tun, and
// a dummy infra0 as its infrastructure link, so its SRP advertising proxy
// and mDNS reach the Matter controller and no LAN (spikes/ENF-radio,
// consequence 1). IP, netlink and Unix sockets only: no packet socket.
func Thread(uid, gid uint32) Profile {
	return Profile{Name: "thread", UID: uid, GID: gid, NetAdmin: true, Links: []string{"infra0"},
		Families: []int{syscall.AF_UNIX, syscall.AF_INET, syscall.AF_INET6, syscall.AF_NETLINK}}
}

// Matter is the Matter controller's profile: started into the Thread
// stack's network namespace (Spec.Net) as its own user, with no
// capability, so it reaches Thread devices and the SRP proxy's mDNS on
// infra0 and nothing else.
func Matter(uid, gid uint32) Profile {
	return Profile{Name: "matter", UID: uid, GID: gid,
		Families: []int{syscall.AF_UNIX, syscall.AF_INET, syscall.AF_INET6, syscall.AF_NETLINK}}
}

// ThreadAdapter is the Thread adapter's profile: ot-daemon's user, so it
// can open ot-daemon's command socket in their state directory, in a
// fresh empty network namespace with Unix sockets only.
func ThreadAdapter(uid, gid uint32) Profile {
	return Profile{Name: "thread-adapter", UID: uid, GID: gid, Families: []int{syscall.AF_UNIX}}
}

// Spec is one stack process to start.
type Spec struct {
	Profile Profile
	Path    string   // the stack's executable
	Args    []string // its arguments after the path
	Stderr  io.Writer
	// Self is the enforcer's own binary, re-executed to confine itself
	// (Trampoline); empty means os.Executable. The stack's user must be
	// able to execute it.
	Self string
	// Dir is the stack's working directory (default /).
	Dir string
	// Net, when set, starts the stack in that running stack's network
	// namespace instead of a fresh empty one (the Matter controller in
	// Thread's). Its profile may not have NetAdmin or Links.
	Net *Proc
}

// Proc is a running stack.
type Proc struct {
	cmd  *exec.Cmd
	net  *os.File      // its network namespace, unless it joined another's
	keep chan struct{} // holds the thread that started the stack
	once sync.Once
}

// Arg0 marks the re-exec of the enforcer's own binary that confines itself
// and then execs the stack (Trampoline). ArgHold marks one that also waits
// for the enforcer to set up its network namespace before the exec.
const (
	Arg0    = "agentos-radio-confine"
	ArgHold = "agentos-radio-confine-hold"
)

// holdFD is the descriptor a held stack waits on: one byte means go on.
const holdFD = 4

var (
	ErrRoot = errors.New("confine: a stack never runs as root")
	ErrArch = errors.New("confine: linux/amd64 only")
	ErrJoin = errors.New("confine: a stack joining another's network gets no capability or link")
)

const (
	capNetAdmin = 12
	capNetRaw   = 13
)

// Start starts s and returns the enforcer's end of its command interface.
// The caller must be root (in its user namespace) to drop to the profile's
// user, and its binary must call Trampoline first thing in main.
func Start(s Spec) (*Proc, *os.File, error) {
	p := s.Profile
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, nil, ErrArch
	}
	if p.UID == 0 || p.GID == 0 {
		return nil, nil, ErrRoot
	}
	if s.Net != nil && (p.NetAdmin || len(p.Links) > 0) {
		return nil, nil, ErrJoin
	}
	if err := checkView(p); err != nil {
		return nil, nil, err
	}
	self := s.Self
	if self == "" {
		var err error
		if self, err = os.Executable(); err != nil {
			return nil, nil, err
		}
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		syscall.Close(fds[0])
		syscall.Close(fds[1])
		return nil, nil, err
	}
	ours, theirs := os.NewFile(uintptr(fds[0]), p.Name), os.NewFile(uintptr(fds[1]), p.Name)
	defer theirs.Close()

	fam := make([]string, len(p.Families))
	for i, f := range p.Families {
		fam[i] = strconv.Itoa(f)
	}
	dir := s.Dir
	if dir == "" {
		dir = "/"
	}
	attr := &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: p.UID, Gid: p.GID, Groups: []uint32{}},
		Cloneflags: syscall.CLONE_NEWIPC,
		Setsid:     true,
		Pdeathsig:  syscall.SIGKILL,
	}
	if s.Net == nil {
		attr.Cloneflags |= syscall.CLONE_NEWNET
	}
	if p.NetAdmin {
		// Root creates the user namespace in the fork, so the stack never
		// needs unprivileged user namespaces; only its own ids are mapped.
		attr.Cloneflags |= syscall.CLONE_NEWUSER
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: int(p.UID), HostID: int(p.UID), Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: int(p.GID), HostID: int(p.GID), Size: 1}}
		attr.GidMappingsEnableSetgroups = true // to clear the supplementary groups inside
		attr.AmbientCaps = []uintptr{capNetAdmin, capNetRaw}
	}
	if len(p.View) > 0 {
		// As for NetAdmin, but for the stack's own mount namespace:
		// Trampoline builds the view with CAP_SYS_ADMIN there and drops
		// it before the exec.
		attr.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: int(p.UID), HostID: int(p.UID), Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: int(p.GID), HostID: int(p.GID), Size: 1}}
		attr.GidMappingsEnableSetgroups = true
		attr.AmbientCaps = []uintptr{capSysAdmin}
	}
	arg0, extra := Arg0, []*os.File{theirs}
	hold := p.NetAdmin || len(p.Links) > 0
	var release *os.File
	if hold {
		r, w, err := os.Pipe()
		if err != nil {
			ours.Close()
			return nil, nil, err
		}
		defer r.Close()
		arg0, extra, release = ArgHold, append(extra, r), w
		defer release.Close()
	}
	cmd := &exec.Cmd{
		Path:        self,
		Args:        append([]string{arg0, strings.Join(fam, ","), strings.Join(p.View, "\n"), s.Path}, s.Args...),
		Env:         []string{},
		Dir:         dir,
		Stderr:      s.Stderr,
		ExtraFiles:  extra,
		SysProcAttr: attr,
	}
	// The child's Pdeathsig fires when the OS thread that forked it exits,
	// and the runtime ends a thread whose goroutine exits locked (as
	// inNetns's do), so the fork runs on a thread of its own that outlives
	// the child.
	proc := &Proc{cmd: cmd, keep: make(chan struct{})}
	var ns *os.File
	if s.Net != nil {
		if s.Net.net == nil {
			ours.Close()
			return nil, nil, ErrJoin
		}
		ns = s.Net.net
	}
	if err := inNetns(ns, cmd.Start, proc.keep); err != nil {
		proc.release()
		ours.Close()
		return nil, nil, fmt.Errorf("confine: start %s: %w", p.Name, err)
	}
	fail := func(err error) (*Proc, *os.File, error) {
		proc.Stop()
		ours.Close()
		return nil, nil, fmt.Errorf("confine: start %s: %w", p.Name, err)
	}
	if s.Net == nil {
		// The child has not been reaped, so its pid is still its own.
		f, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid))
		if err != nil {
			return fail(err)
		}
		proc.net = f
	}
	if hold {
		if err := inNetns(proc.net, func() error { return setupLinks(p.Links) }, nil); err != nil {
			return fail(err)
		}
		if _, err := release.Write([]byte{1}); err != nil {
			return fail(err)
		}
	}
	return proc, ours, nil
}

// Pid is the stack's process id.
func (p *Proc) Pid() int { return p.cmd.Process.Pid }

// Wait waits for the stack to exit.
func (p *Proc) Wait() error {
	err := p.cmd.Wait()
	p.release()
	return err
}

// release lets the thread that started the stack exit, once the stack has
// been reaped.
func (p *Proc) release() {
	p.once.Do(func() { close(p.keep) })
}

// Stop kills the stack and reaps it.
func (p *Proc) Stop() error {
	p.cmd.Process.Kill()
	if p.net != nil {
		p.net.Close()
	}
	err := p.cmd.Wait()
	p.release()
	return err
}

// InNet runs fn on an OS thread inside the stack's network namespace; the
// thread is then discarded. It is for the enforcer's tests; a process fn
// starts runs in that namespace.
func (p *Proc) InNet(fn func() error) error {
	if p.net == nil {
		return errors.New("confine: the stack shares another's network namespace")
	}
	return inNetns(p.net, fn, nil)
}

// inNetns runs fn on a fresh locked OS thread moved into the network
// namespace ns (nil: left in the enforcer's own). The thread never moves back, since inside a user namespace
// it may lack the right to re-enter the enforcer's own: it stays locked and
// exits with its goroutine, once keep closes (nil: at once), so no other
// code runs there. A child fn starts holds Pdeathsig on that thread, so
// keep must outlive it.
func inNetns(ns *os.File, fn func() error, keep <-chan struct{}) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread exits with this goroutine
		if ns != nil {
			if err := setns(ns, syscall.CLONE_NEWNET); err != nil {
				errc <- fmt.Errorf("setns: %w", err)
				return
			}
		}
		errc <- fn()
		if keep != nil {
			<-keep
		}
	}()
	return <-errc
}

func setns(f *os.File, kind int) error {
	if _, _, e := syscall.RawSyscall(sysSetns, f.Fd(), uintptr(kind), 0); e != 0 {
		return e
	}
	return nil
}

// Trampoline confines this process and execs the stack when it was started
// by Start; otherwise it returns at once. Call it first in main (or
// TestMain). It never returns from a confined start: on any failure it
// exits 126 before the stack runs.
func Trampoline() {
	if len(os.Args) < 4 || (os.Args[0] != Arg0 && os.Args[0] != ArgHold) {
		return
	}
	err := confineAndExec(os.Args[1], os.Args[2], os.Args[3], os.Args[3:], os.Args[0] == ArgHold)
	fmt.Fprintf(os.Stderr, "confine: %v\n", err)
	os.Exit(126)
}

func confineAndExec(families, view, path string, argv []string, hold bool) error {
	var fam []int
	for f := range strings.SplitSeq(families, ",") {
		if f == "" {
			continue // a profile with no socket families
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			return err
		}
		fam = append(fam, n)
	}
	if syscall.Getuid() == 0 || syscall.Geteuid() == 0 || syscall.Getgid() == 0 || syscall.Getegid() == 0 {
		return ErrRoot
	}
	if groups, err := syscall.Getgroups(); err != nil || len(groups) != 0 {
		return fmt.Errorf("confine: supplementary groups %v (%v)", groups, err)
	}
	// Mark every descriptor past the interface (fd 3) close-on-exec, so
	// nothing the enforcer inherited without it reaches the stack. Marking
	// rather than closing leaves the Go runtime's own fds (netpoll) open
	// until the exec.
	if _, _, e := syscall.RawSyscall(sysCloseRange, 4, 1<<32-1, closeRangeCloexec); e != 0 {
		return fmt.Errorf("confine: close_range: %w", e)
	}
	runtime.LockOSThread()
	exe := -1
	if view != "" {
		var err error
		if exe, err = enterView(strings.Split(view, "\n"), path); err != nil {
			return fmt.Errorf("confine: view: %w", err)
		}
		if err := dropCaps(); err != nil {
			return fmt.Errorf("confine: capabilities: %w", err)
		}
	}
	if err := install(filter(slices.Sorted(slices.Values(fam)))); err != nil {
		return fmt.Errorf("confine: seccomp: %w", err)
	}
	if hold {
		// The enforcer sets up the network namespace, then writes one
		// byte; end of file means it gave up. The descriptor is
		// close-on-exec, so the stack never holds it.
		var b [1]byte
		if n, err := syscall.Read(holdFD, b[:]); n != 1 {
			return fmt.Errorf("confine: not released (%v)", err)
		}
	}
	if exe != -1 {
		return execFD(exe, argv)
	}
	return syscall.Exec(path, argv, []string{})
}
