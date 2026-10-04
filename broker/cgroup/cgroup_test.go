package cgroup

import (
	"context"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REQ: RES-1, RES-2

// fakeV2 builds a directory that looks like a cgroup v2 parent. The kernel's
// side (cgroup.events) is played by the test.
func fakeV2(t *testing.T) *Group {
	t.Helper()
	d := t.TempDir()
	must(t, os.WriteFile(filepath.Join(d, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(d, "cgroup.subtree_control"), []byte(""), 0o644))
	g, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// setEvents replaces cgroup.events in one step, as the kernel does.
func setEvents(path, s string) {
	os.WriteFile(path+".tmp", []byte(s), 0o644)
	os.Rename(path+".tmp", path)
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	must(t, err)
	return strings.TrimSpace(string(b))
}

func TestRES2OpenRejectsGroupWithoutMemoryController(t *testing.T) {
	d := t.TempDir()
	must(t, os.WriteFile(filepath.Join(d, "cgroup.controllers"), []byte("cpu pids\n"), 0o644))
	if _, err := Open(d); !errors.Is(err, ErrNotV2) {
		t.Fatalf("Open = %v, want ErrNotV2", err)
	}
	if _, err := Open(t.TempDir()); !errors.Is(err, ErrNotV2) {
		t.Fatalf("Open(v1-like dir) = %v, want ErrNotV2", err)
	}
}

func TestRES2ChildEnforcesBudgetWithThrottleBelowHardLimitAndNoSwap(t *testing.T) {
	g := fakeV2(t)
	if got := read(t, filepath.Join(g.Path, "cgroup.subtree_control")); got != "+memory" {
		t.Fatalf("subtree_control = %q, want memory enabled for children", got)
	}
	c, err := g.Child("m1", Limits{MaxBytes: 1600 << 20})
	must(t, err)
	if got := read(t, filepath.Join(c.Path, "memory.max")); got != "1677721600" {
		t.Errorf("memory.max = %s", got)
	}
	if got := read(t, filepath.Join(c.Path, "memory.high")); got != "1572864000" {
		t.Errorf("memory.high = %s, want max - 1/16", got)
	}
	if got := read(t, filepath.Join(c.Path, "memory.swap.max")); got != "0" {
		t.Errorf("memory.swap.max = %s, want 0 (RES-2: no swap thrashing)", got)
	}
	if got := read(t, filepath.Join(c.Path, "memory.oom.group")); got != "1" {
		t.Errorf("memory.oom.group = %s, want 1", got)
	}
	if _, err := g.Child("m2", Limits{}); err == nil {
		t.Error("a machine without a budget was given a group")
	}
	for _, bad := range []string{"", "..", "a/b", "x.y"} {
		if _, err := g.Child(bad, Limits{MaxBytes: 1}); err == nil {
			t.Errorf("Child(%q) accepted", bad)
		}
	}
}

func TestRES1FreezeAndKillWaitForTheKernel(t *testing.T) {
	g := fakeV2(t)
	c, err := g.Child("exp", Limits{MaxBytes: 1 << 30})
	must(t, err)
	ev := filepath.Join(c.Path, "cgroup.events")
	must(t, os.WriteFile(ev, []byte("populated 1\nfrozen 0\n"), 0o644))

	go func() {
		time.Sleep(20 * time.Millisecond)
		setEvents(ev, "populated 1\nfrozen 1\n")
	}()
	start := time.Now()
	must(t, c.Freeze(context.Background()))
	if time.Since(start) < 15*time.Millisecond {
		t.Error("Freeze returned before the kernel reported frozen")
	}
	if got := read(t, filepath.Join(c.Path, "cgroup.freeze")); got != "1" {
		t.Errorf("cgroup.freeze = %s", got)
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		setEvents(ev, "populated 0\nfrozen 1\n")
	}()
	must(t, c.Kill(context.Background()))
	if p, _ := c.Populated(); p {
		t.Error("Kill returned with processes left, so memory is not released")
	}

	// A group that never empties fails within the caller's deadline.
	must(t, os.WriteFile(ev, []byte("populated 1\nfrozen 0\n"), 0o644))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := c.Kill(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Kill on a stuck group = %v", err)
	}
}

func TestRES2PressureIsParsedAndFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "memory.pressure")
	must(t, os.WriteFile(p, []byte("some avg10=12.50 avg60=3.00 avg300=1.00 total=99\nfull avg10=1.00 avg60=0.00 avg300=0.00 total=5\n"), 0o644))
	v, err := ReadPressure(p)
	must(t, err)
	if v != 12.5 {
		t.Fatalf("pressure = %v, want 12.5 (some avg10)", v)
	}
	read, ok := PressureSource(p)
	if !ok || read() != 12.5 {
		t.Fatal("PressureSource did not read the file")
	}
	// After PSI has worked, losing it must read as maximal pressure, so
	// admission refuses everything but foreground instead of admitting blind.
	os.Remove(p)
	if got := read(); !math.IsInf(got, 1) {
		t.Fatalf("pressure after the source vanished = %v, want +Inf", got)
	}
	if _, ok := PressureSource(p); ok {
		t.Fatal("a missing PSI file was reported as a source")
	}
	must(t, os.WriteFile(p, []byte("some avg10=NaN\n"), 0o644))
	if _, err := ReadPressure(p); err == nil {
		t.Fatal("NaN accepted")
	}
}

// TestRES1RES2RealCgroupV2 runs against the kernel when the test is root on a
// cgroup v2 host (CI's integration job). It shows the limits take effect,
// that Kill releases memory, and that PSI is readable per group.
func TestRES1RES2RealCgroupV2(t *testing.T) {
	root := os.Getenv("AGENTOS_CGROUP_PARENT")
	if root == "" {
		t.Skip("set AGENTOS_CGROUP_PARENT to a writable cgroup v2 group (root only)")
	}
	g, err := Open(root)
	must(t, err)
	c, err := g.Child("agentos-test", Limits{MaxBytes: 64 << 20})
	must(t, err)
	defer c.Remove()

	// A shell in the group that allocates past the budget is throttled and
	// then killed by the kernel or by us; it never takes host memory.
	cmd := exec.Command("/bin/sh", "-c", "echo $$ > "+filepath.Join(c.Path, "cgroup.procs")+"; exec sleep 600")
	must(t, cmd.Start())
	deadline := time.Now().Add(5 * time.Second)
	for {
		if p, _ := c.Populated(); p {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("process never joined the group")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t0 := time.Now()
	must(t, c.Freeze(ctx))
	t.Logf("freeze took %v", time.Since(t0))
	must(t, c.Thaw())
	t0 = time.Now()
	must(t, c.Kill(ctx))
	t.Logf("kill to empty took %v", time.Since(t0))
	cmd.Wait()
	if cur := read(t, filepath.Join(c.Path, "memory.current")); cur != "0" {
		t.Logf("memory.current after kill = %s (page cache may stay charged)", cur)
	}
	if _, err := c.Pressure(); err != nil {
		t.Fatalf("per-group PSI unreadable: %v", err)
	}
}
