package cgroup

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// REQ: RES-2

func TestRES2ComponentHardLimitWithoutGroupOOMKill(t *testing.T) {
	g := fakeV2(t)
	c, err := g.Component("inference", Limits{MaxBytes: 2000 << 20})
	must(t, err)
	if got := read(t, filepath.Join(c.Path, "memory.max")); got != strconv.Itoa(2000<<20) {
		t.Errorf("memory.max = %s", got)
	}
	if got := read(t, filepath.Join(c.Path, "memory.high")); got != strconv.Itoa(2000<<20-2000<<20/16) {
		t.Errorf("memory.high = %s, want max - 1/16", got)
	}
	if got := read(t, filepath.Join(c.Path, "memory.swap.max")); got != "0" {
		t.Errorf("memory.swap.max = %s, want 0", got)
	}
	// A component holds many independent children (the machine pool holds
	// every machine), so an OOM in it must not take all of them at once.
	if _, err := os.Stat(filepath.Join(c.Path, "memory.oom.group")); err == nil {
		t.Errorf("memory.oom.group written on a component group")
	}
}

func TestRES2ProtectedComponentHasNoHardLimitAndIsNotReclaimed(t *testing.T) {
	g := fakeV2(t)
	c, err := g.Component("broker", Limits{MinBytes: 1000 << 20})
	must(t, err)
	if got := read(t, filepath.Join(c.Path, "memory.min")); got != strconv.Itoa(1000<<20) {
		t.Errorf("memory.min = %s, want the broker's budget protected from reclaim", got)
	}
	// No hard limit: the broker is never OOM-killed by its own group
	// (RES-2); it is everything else that is capped.
	if got := read(t, filepath.Join(c.Path, "memory.max")); got != "max" {
		t.Errorf("memory.max = %s, want max", got)
	}
	if _, err := os.Stat(filepath.Join(c.Path, "memory.high")); err == nil {
		t.Errorf("memory.high written on a protected component")
	}
}

func TestRES2ComponentNeedsALimitOrAProtection(t *testing.T) {
	g := fakeV2(t)
	if _, err := g.Component("x", Limits{}); err == nil {
		t.Fatal("component with neither max nor min accepted")
	}
	if _, err := g.Component("../x", Limits{MaxBytes: 1}); err == nil {
		t.Fatal("bad name accepted")
	}
}

func TestRES2JoinMovesAProcess(t *testing.T) {
	g := fakeV2(t)
	c, err := g.Component("broker", Limits{MinBytes: 1 << 20})
	must(t, err)
	must(t, c.Join(4242))
	if got := read(t, filepath.Join(c.Path, "cgroup.procs")); got != "4242" {
		t.Errorf("cgroup.procs = %q", got)
	}
}

func TestRES2OOMKillsReadsMemoryEvents(t *testing.T) {
	g := fakeV2(t)
	must(t, os.WriteFile(filepath.Join(g.Path, "memory.events"),
		[]byte("low 0\nhigh 12\nmax 0\noom 1\noom_kill 3\noom_group_kill 0\n"), 0o644))
	n, err := g.OOMKills()
	must(t, err)
	if n != 3 {
		t.Fatalf("OOMKills = %d, want 3", n)
	}
}
