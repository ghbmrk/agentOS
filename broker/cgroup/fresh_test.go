package cgroup

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// REQ: RES-1, RES-2

// A group an earlier run left is killed, emptied and removed, and the group
// handed back is a new directory: never the old one, which clone3 may
// refuse a child (#5135).
func TestRES1FreshReplacesALeftoverGroup(t *testing.T) {
	g := fakeV2(t)
	old := filepath.Join(g.Path, "svc")
	must(t, os.Mkdir(old, 0o755))
	setEvents(filepath.Join(old, "cgroup.events"), "populated 0\n")
	must(t, os.WriteFile(filepath.Join(old, "marker"), nil, 0o644))
	// The fake's files are regular files, which rmdir would refuse; the
	// stand-in records the call and removes them as the kernel's rmdir
	// does its own.
	var killed bool
	removeDir = func(p string) error {
		b, err := os.ReadFile(filepath.Join(p, "cgroup.kill"))
		killed = err == nil && string(b) == "1"
		return os.RemoveAll(p)
	}
	defer func() { removeDir = os.Remove }()
	c, err := g.Fresh(context.Background(), "svc")
	must(t, err)
	if !killed {
		t.Fatal("the leftover group was removed without cgroup.kill")
	}
	if c.Path != old {
		t.Fatalf("path %s, want %s", c.Path, old)
	}
	if es, err := os.ReadDir(c.Path); err != nil || len(es) != 0 {
		t.Fatalf("the group handed back is not new: %v, %v", es, err)
	}
}

// A leftover that will not empty or will not go is an error, never reused.
func TestRES1FreshNeverReusesALeftover(t *testing.T) {
	g := fakeV2(t)
	old := filepath.Join(g.Path, "svc")
	must(t, os.Mkdir(old, 0o755))
	setEvents(filepath.Join(old, "cgroup.events"), "populated 1\n")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := g.Fresh(ctx, "svc"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a leftover that never emptied: %v", err)
	}
	setEvents(filepath.Join(old, "cgroup.events"), "populated 0\n")
	removeDir = func(string) error { return syscall.EBUSY }
	defer func() { removeDir = os.Remove }()
	if _, err := g.Fresh(context.Background(), "svc"); !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("a leftover that would not go: %v", err)
	}
	if _, err := g.Child("svc", mem(1<<20)); !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("Child over a leftover that would not go: %v", err)
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a.b"} {
		if _, err := g.Fresh(context.Background(), bad); err == nil {
			t.Errorf("Fresh(%q) made a group", bad)
		}
	}
}

// TestRES1Clone3IntoANewGroupAfterKill runs against the kernel as root
// under AGENTOS_CGROUP_PARENT. On Linux 6.18 a child clone3 places in a
// group that was ever killed dies of SIGKILL at birth (#5135): a service
// restarted into its killed group never ran. Each round here starts a
// process into the group by clone3, requires it to live, and ends it with
// Kill or by making the group new over it.
func TestRES1Clone3IntoANewGroupAfterKill(t *testing.T) {
	root := os.Getenv("AGENTOS_CGROUP_PARENT")
	if root == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_CGROUP_PARENT to a writable cgroup v2 group (root only)")
	}
	// No controllers are needed: a new group's limits are its parent's.
	p := &Group{Path: root}
	name := "agentos-fresh-" + strconv.Itoa(os.Getpid())
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := p.Fresh(ctx, name)
	must(t, err)
	defer func() { c.Kill(ctx); c.Remove() }()
	for i := 0; i < 4; i++ {
		cmd := startInto(t, c)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
			t.Fatalf("round %d: the process clone3 placed in the group died at birth: %v", i, cmd.ProcessState)
		case <-time.After(200 * time.Millisecond):
		}
		joined(t, c, cmd)
		if i%2 == 0 {
			kill(t, c)
		}
		// Odd rounds leave the process for Fresh to kill.
		if c, err = p.Fresh(ctx, name); err != nil {
			cmd.Process.Kill()
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			t.Fatalf("round %d: the process outlived its group", i)
		}
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Fatalf("round %d: the process ended with %v, not by the group's SIGKILL", i, cmd.ProcessState)
		}
	}
}

// startInto starts sleep in c by clone3 (CLONE_INTO_CGROUP), as the
// supervisor and gVisor runtime start their children.
func startInto(t *testing.T, c *Group) *exec.Cmd {
	t.Helper()
	fd, err := syscall.Open(c.Path, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	must(t, err)
	defer syscall.Close(fd)
	cmd := exec.Command("sleep", "600")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	must(t, cmd.Start())
	return cmd
}
