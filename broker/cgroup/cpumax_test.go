package cgroup

// REQ: RES-2

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestChildSetsCPUCeiling (#3614 item 3): a set CPUMilli is written as
// cpu.max over a 100ms period, a ceiling that holds when the host is
// idle; zero writes none, and one under the kernel's 1ms floor or
// negative is refused before the group is made.
func TestChildSetsCPUCeiling(t *testing.T) {
	g := fakeV2(t)
	c, err := g.Child("m1", Limits{MaxBytes: 1 << 30, CPUWeight: 100, IOWeight: 100, Pids: 64, CPUMilli: 250})
	must(t, err)
	if got := read(t, filepath.Join(c.Path, "cpu.max")); got != "25000 100000" {
		t.Errorf("cpu.max = %q, want %q", got, "25000 100000")
	}
	c, err = g.Child("m2", Limits{MaxBytes: 1 << 30, CPUWeight: 100, IOWeight: 100, Pids: 64})
	must(t, err)
	if _, err := os.Stat(filepath.Join(c.Path, "cpu.max")); err == nil {
		t.Error("cpu.max written with no ceiling set")
	}
	for i, bad := range []int64{-1, 1, 9} {
		name := "bad" + strconv.Itoa(i)
		if _, err := g.Child(name, Limits{MaxBytes: 1 << 30, CPUWeight: 100, IOWeight: 100, Pids: 64, CPUMilli: bad}); err == nil {
			t.Errorf("CPUMilli %d accepted", bad)
		}
		if _, err := os.Stat(filepath.Join(g.Path, name)); err == nil {
			t.Errorf("CPUMilli %d left a group behind", bad)
		}
	}
}
