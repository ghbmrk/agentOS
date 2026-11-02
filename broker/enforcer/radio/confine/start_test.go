package confine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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
	thread := Thread(viewUID, viewUID, at(vState), at("run"), devNull)
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
