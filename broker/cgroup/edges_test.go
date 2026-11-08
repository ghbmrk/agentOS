package cgroup

// REQ: RES-1, RES-2

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"testing"
	"time"
)

// TestRES2ThrottlePointIsKeptOnlyWhenItFits: a HighBytes up to and
// including MaxBytes is written as given; zero, or one above MaxBytes,
// becomes MaxBytes minus 1/16. Child and Component agree.
func TestRES2ThrottlePointIsKeptOnlyWhenItFits(t *testing.T) {
	g := fakeV2(t)
	const max = 1 << 30
	for i, tc := range []struct{ high, want int64 }{
		{0, max - max/16}, {max / 2, max / 2}, {max, max}, {max + 1, max - max/16},
	} {
		l := mem(max)
		l.HighBytes = tc.high
		c, err := g.Child("c"+strconv.Itoa(i), l)
		must(t, err)
		k, err := g.Component("k"+strconv.Itoa(i), Limits{MaxBytes: max, HighBytes: tc.high})
		must(t, err)
		for _, grp := range []*Group{c, k} {
			if got := read(t, filepath.Join(grp.Path, "memory.high")); got != strconv.FormatInt(tc.want, 10) {
				t.Errorf("%s: HighBytes %d gave memory.high %s, want %d", grp.Path, tc.high, got, tc.want)
			}
		}
	}
}

// TestRES2CPUCeilingBoundsAreInclusive: the kernel's 10 floor and the
// largest ceiling that fits cpu.max are both accepted.
func TestRES2CPUCeilingBoundsAreInclusive(t *testing.T) {
	g := fakeV2(t)
	for i, m := range []int64{10, math.MaxInt64 / cpuUnit} {
		l := mem(1 << 30)
		l.CPUMilli = m
		c, err := g.Child("cpu"+strconv.Itoa(i), l)
		if err != nil {
			t.Fatalf("CPUMilli %d refused: %v", m, err)
		}
		if got, want := read(t, filepath.Join(c.Path, "cpu.max")), strconv.FormatInt(m*cpuUnit, 10)+" 100000"; got != want {
			t.Errorf("cpu.max = %q, want %q", got, want)
		}
	}
	l := mem(1 << 30)
	l.CPUMilli = math.MaxInt64/cpuUnit + 1
	if _, err := g.Child("cpu-over", l); err == nil {
		t.Error("a ceiling that overflows cpu.max was accepted")
	}
}

// TestRES2ComponentWritesNoProtectionUnlessAsked: memory.min is written
// only for a set MinBytes.
func TestRES2ComponentWritesNoProtectionUnlessAsked(t *testing.T) {
	g := fakeV2(t)
	c, err := g.Component("pool", Limits{MaxBytes: 1 << 30})
	must(t, err)
	if _, err := os.Stat(filepath.Join(c.Path, "memory.min")); err == nil {
		t.Error("memory.min written with no protection asked for")
	}
}

// TestRES2OpenNeedsSubtreeControl: a group whose subtree_control cannot be
// read is refused, not given a new file.
func TestRES2OpenNeedsSubtreeControl(t *testing.T) {
	d := t.TempDir()
	must(t, os.WriteFile(filepath.Join(d, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644))
	if _, err := Open(d); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open without cgroup.subtree_control = %v, want ErrNotExist", err)
	}
}

// TestRES1MissingKernelFilesAreErrors: each reader reports a missing file
// as that error, and a wait on a group with no cgroup.events fails at once
// instead of polling until its deadline.
func TestRES1MissingKernelFilesAreErrors(t *testing.T) {
	g := &Group{Path: filepath.Join(t.TempDir(), "gone")}
	if _, err := g.PidsMax(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("PidsMax = %v", err)
	}
	if _, err := g.OOMKills(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("OOMKills = %v", err)
	}
	if _, err := g.Populated(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Populated = %v", err)
	}
	if _, err := g.Pressure(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Pressure = %v", err)
	}
	if err := g.Remove(); err != nil {
		t.Errorf("Remove of a missing group = %v, want nil", err)
	}

	d := fakeV2(t)
	c, err := d.Child("w", mem(1<<30))
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Freeze(ctx); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Freeze with no cgroup.events = %v, want ErrNotExist before the deadline", err)
	}
}

// TestRES1KillWritesCgroupKill: Kill asks the kernel to kill the group,
// not only waits for it to empty.
func TestRES1KillWritesCgroupKill(t *testing.T) {
	g := fakeV2(t)
	c, err := g.Child("k", mem(1<<30))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(c.Path, "cgroup.events"), []byte("populated 0\nfrozen 0\n"), 0o644))
	must(t, c.Kill(context.Background()))
	if got := read(t, filepath.Join(c.Path, "cgroup.kill")); got != "1" {
		t.Errorf("cgroup.kill = %q, want 1", got)
	}
}

// TestRES2PressureSkipsOtherLinesAndAcceptsZero: "some" is found after a
// "full" line and a blank one, and an idle 0.00 is a reading.
func TestRES2PressureSkipsOtherLinesAndAcceptsZero(t *testing.T) {
	p := filepath.Join(t.TempDir(), "memory.pressure")
	must(t, os.WriteFile(p, []byte("\nfull avg10=7.00 avg60=0.00 avg300=0.00 total=5\nsome avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"), 0o644))
	v, err := ReadPressure(p)
	must(t, err)
	if v != 0 {
		t.Fatalf("pressure = %v, want 0 (some avg10)", v)
	}
}

// TestRES2PressureClosesItsFile: admission reads PSI on every decision, so
// a read that kept its file open would run the broker out of descriptors.
func TestRES2PressureClosesItsFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "memory.pressure")
	must(t, os.WriteFile(p, []byte("some avg10=1.00\n"), 0o644))
	open := func() int {
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skipf("no /proc/self/fd: %v", err)
		}
		return len(fds)
	}
	// With the collector off, only Close can release a file.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	before := open()
	for range 200 {
		if _, err := ReadPressure(p); err != nil {
			t.Fatal(err)
		}
	}
	if after := open(); after > before+50 {
		t.Fatalf("open files went from %d to %d over 200 reads", before, after)
	}
}
