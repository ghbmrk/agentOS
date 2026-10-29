// Package confine starts a radio stack as a confined process (NET-2
// Confined radio stacks; briefs/ENF.md decision 6, slice k): its own
// unprivileged user with no supplementary groups, a fresh empty network and
// IPC namespace, no-new-privileges, an empty environment, and the seccomp
// filter spikes/ENF-radio measured, with socket families narrowed to the
// profile's list. The process gets its command interface as fd 3, one end
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
}

// BLE is the Bluetooth stack's profile: it reaches BlueZ over the system
// bus's Unix socket and nothing else, so no IP, netlink, packet or raw
// Bluetooth socket (BLE commissioning goes through BlueZ, never raw HCI).
func BLE(uid, gid uint32) Profile {
	return Profile{Name: "ble", UID: uid, GID: gid, Families: []int{syscall.AF_UNIX}}
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
}

// Proc is a running stack.
type Proc struct {
	cmd *exec.Cmd
}

// Arg0 marks the re-exec of the enforcer's own binary that confines itself
// and then execs the stack (Trampoline).
const Arg0 = "agentos-radio-confine"

var (
	ErrRoot = errors.New("confine: a stack never runs as root")
	ErrArch = errors.New("confine: linux/amd64 only")
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
	cmd := &exec.Cmd{
		Path:       self,
		Args:       append([]string{Arg0, strings.Join(fam, ","), s.Path}, s.Args...),
		Env:        []string{},
		Dir:        "/",
		Stderr:     s.Stderr,
		ExtraFiles: []*os.File{theirs},
		SysProcAttr: &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: p.UID, Gid: p.GID, Groups: []uint32{}},
			Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC,
			Setsid:     true,
			Pdeathsig:  syscall.SIGKILL,
		},
	}
	if err := cmd.Start(); err != nil {
		ours.Close()
		return nil, nil, fmt.Errorf("confine: start %s: %w", p.Name, err)
	}
	return &Proc{cmd: cmd}, ours, nil
}

// Pid is the stack's process id.
func (p *Proc) Pid() int { return p.cmd.Process.Pid }

// Wait waits for the stack to exit.
func (p *Proc) Wait() error { return p.cmd.Wait() }

// Stop kills the stack and reaps it.
func (p *Proc) Stop() error {
	p.cmd.Process.Kill()
	return p.cmd.Wait()
}

// Trampoline confines this process and execs the stack when it was started
// by Start; otherwise it returns at once. Call it first in main (or
// TestMain). It never returns from a confined start: on any failure it
// exits 126 before the stack runs.
func Trampoline() {
	if len(os.Args) < 3 || os.Args[0] != Arg0 {
		return
	}
	err := confineAndExec(os.Args[1], os.Args[2], os.Args[2:])
	fmt.Fprintf(os.Stderr, "confine: %v\n", err)
	os.Exit(126)
}

func confineAndExec(families, path string, argv []string) error {
	var fam []int
	for f := range strings.SplitSeq(families, ",") {
		n, err := strconv.Atoi(f)
		if err != nil {
			return err
		}
		fam = append(fam, n)
	}
	if syscall.Getuid() == 0 || syscall.Geteuid() == 0 || syscall.Getgid() == 0 {
		return ErrRoot
	}
	if groups, err := syscall.Getgroups(); err != nil || len(groups) != 0 {
		return fmt.Errorf("confine: supplementary groups %v (%v)", groups, err)
	}
	runtime.LockOSThread()
	if err := install(filter(slices.Sorted(slices.Values(fam)))); err != nil {
		return fmt.Errorf("confine: seccomp: %w", err)
	}
	return syscall.Exec(path, argv, []string{})
}
