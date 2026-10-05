package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// REQ: RES-1, RES-2

// Open enables every controller RES-2 enforces for the children, in one
// write, and refuses a group that lacks any of them: a machine without a
// CPU weight or a process cap could starve the owner channel (security
// review 2, finding 4).
func TestRES2OpenEnablesCPUIOAndPidsWithMemory(t *testing.T) {
	g := fakeV2(t)
	if got := read(t, filepath.Join(g.Path, "cgroup.subtree_control")); got != "+cpu +io +memory +pids" {
		t.Fatalf("subtree_control = %q, want cpu, io, memory and pids enabled", got)
	}
	// Already-enabled controllers are not written again.
	d := t.TempDir()
	must(t, os.WriteFile(filepath.Join(d, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(d, "cgroup.subtree_control"), []byte("memory cpu\n"), 0o644))
	_, err := Open(d)
	must(t, err)
	if got := read(t, filepath.Join(d, "cgroup.subtree_control")); got != "+io +pids" {
		t.Fatalf("subtree_control = %q, want only the missing io and pids", got)
	}
	d = t.TempDir()
	must(t, os.WriteFile(filepath.Join(d, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(d, "cgroup.subtree_control"), []byte("cpu io memory pids\n"), 0o644))
	_, err = Open(d)
	must(t, err)
	if got := read(t, filepath.Join(d, "cgroup.subtree_control")); got != "cpu io memory pids" {
		t.Fatalf("Open wrote subtree_control %q with every controller already on", got)
	}
	for _, missing := range []string{"cpu", "io", "memory", "pids"} {
		d := t.TempDir()
		ctl := ""
		for _, c := range []string{"cpu", "io", "memory", "pids"} {
			if c != missing {
				ctl += c + " "
			}
		}
		must(t, os.WriteFile(filepath.Join(d, "cgroup.controllers"), []byte(ctl+"\n"), 0o644))
		must(t, os.WriteFile(filepath.Join(d, "cgroup.subtree_control"), nil, 0o644))
		if _, err := Open(d); !errors.Is(err, ErrNotV2) {
			t.Errorf("Open without %s = %v, want ErrNotV2", missing, err)
		}
		if got := read(t, filepath.Join(d, "cgroup.subtree_control")); got != "" {
			t.Errorf("Open without %s still wrote subtree_control %q", missing, got)
		}
	}
}

// Every machine gets a process cap and its CPU and I/O weights.
func TestRES2ChildSetsWeightsAndAProcessCap(t *testing.T) {
	g := fakeV2(t)
	c, err := g.Child("m1", Limits{MaxBytes: 1 << 30, CPUWeight: 7, IOWeight: 9, Pids: 512})
	must(t, err)
	for file, want := range map[string]string{
		"cpu.weight": "7",
		"io.weight":  "default 9",
		"pids.max":   "512",
	} {
		if got := read(t, filepath.Join(c.Path, file)); got != want {
			t.Errorf("%s = %q, want %q", file, got, want)
		}
	}
	if _, err := g.Child("m2", Limits{MaxBytes: 1 << 30, CPUWeight: 7, IOWeight: 9}); err == nil {
		t.Error("a machine without a process cap was given a group (RES-2)")
	}
	if _, err := os.Stat(filepath.Join(g.Path, "m2")); !os.IsNotExist(err) {
		t.Error("refused machine left a group")
	}
	for _, l := range []Limits{
		{MaxBytes: 1, Pids: 1, CPUWeight: 0, IOWeight: 1},
		{MaxBytes: 1, Pids: 1, CPUWeight: 1, IOWeight: 0},
		{MaxBytes: 1, Pids: 1, CPUWeight: 10001, IOWeight: 1},
		{MaxBytes: 1, Pids: 1, CPUWeight: 1, IOWeight: 10001},
		{MaxBytes: 1, Pids: 1, CPUWeight: -1, IOWeight: 1},
	} {
		if _, err := g.Child("m3", l); err == nil {
			t.Errorf("Child accepted weights %d/%d outside 1..10000", l.CPUWeight, l.IOWeight)
		}
	}
	for _, w := range []int{1, 10000} {
		if _, err := g.Child("m4", Limits{MaxBytes: 1, Pids: 1, CPUWeight: w, IOWeight: w}); err != nil {
			t.Errorf("Child refused weight %d: %v", w, err)
		}
	}
}

// A kernel built without iocost has no io.weight:
// the machine still starts, as without swap accounting, and the CPU weight
// and process cap still hold. Any other failure is fatal.
func TestRES2ChildToleratesAKernelWithoutIOWeight(t *testing.T) {
	g := fakeV2(t)
	p := filepath.Join(g.Path, "m1")
	must(t, os.Mkdir(p, 0o755))
	// A dangling link into a missing directory makes the write ENOENT, as
	// the kernel does for a file it does not provide.
	must(t, os.Symlink(filepath.Join(t.TempDir(), "absent", "io.weight"), filepath.Join(p, "io.weight")))
	c, err := g.Child("m1", Limits{MaxBytes: 1 << 30, CPUWeight: 7, IOWeight: 9, Pids: 512})
	must(t, err)
	if got := read(t, filepath.Join(c.Path, "pids.max")); got != "512" {
		t.Errorf("pids.max = %q", got)
	}
	// pids.max cannot be skipped the same way.
	p = filepath.Join(g.Path, "m2")
	must(t, os.Mkdir(p, 0o755))
	must(t, os.Symlink(filepath.Join(t.TempDir(), "absent", "pids.max"), filepath.Join(p, "pids.max")))
	if _, err := g.Child("m2", Limits{MaxBytes: 1 << 30, CPUWeight: 7, IOWeight: 9, Pids: 512}); err == nil {
		t.Error("machine started without its process cap")
	}
}

// Components carry weights when given them; the broker's group gets no
// process cap, so it can always fork.
func TestRES2ComponentWeights(t *testing.T) {
	g := fakeV2(t)
	c, err := g.Component("broker", Limits{MinBytes: 1 << 30, CPUWeight: 1000, IOWeight: 1000})
	must(t, err)
	if got := read(t, filepath.Join(c.Path, "cpu.weight")); got != "1000" {
		t.Errorf("cpu.weight = %q", got)
	}
	if got := read(t, filepath.Join(c.Path, "io.weight")); got != "default 1000" {
		t.Errorf("io.weight = %q", got)
	}
	if _, err := os.Stat(filepath.Join(c.Path, "pids.max")); err == nil {
		t.Error("pids.max written on the broker's group")
	}
	// Without weights the kernel defaults stay untouched.
	c, err = g.Component("floor", Limits{MaxBytes: 1 << 30})
	must(t, err)
	for _, f := range []string{"cpu.weight", "io.weight", "pids.max"} {
		if _, err := os.Stat(filepath.Join(c.Path, f)); err == nil {
			t.Errorf("%s written without being asked", f)
		}
	}
	if _, err := g.Component("bad", Limits{MaxBytes: 1, CPUWeight: 10001}); err == nil {
		t.Error("Component accepted cpu.weight 10001")
	}
	if _, err := g.Component("bad", Limits{MaxBytes: 1, IOWeight: -1}); err == nil {
		t.Error("Component accepted io.weight -1")
	}
	c, err = g.Component("pool", Limits{MaxBytes: 1 << 30, Pids: 64})
	must(t, err)
	if got := read(t, filepath.Join(c.Path, "pids.max")); got != "64" {
		t.Errorf("component pids.max = %q", got)
	}
}
