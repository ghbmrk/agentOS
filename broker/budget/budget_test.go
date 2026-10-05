package budget

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/cgroup"
)

// REQ: RES-2, RES-4

func TestRES2FloorBudgetMatchesTheSpecTable(t *testing.T) {
	f := Floor()
	if f.HostMB != 1000 || f.InferenceMB != 2000 || f.BrowserMB != 500 || f.HeadroomMB != 600 {
		t.Fatalf("floor = %+v, want SPEC RES-2's 1.0 / 2.0 / 0.5 GB and 0.6 GB headroom", f)
	}
}

func TestRES2PoolIsWhatTheDeclaredComponentsLeave(t *testing.T) {
	// An 8 GB N95 reports about 7.6 GiB: firmware and the iGPU take the rest.
	m, err := ForHost(7680, Floor())
	must(t, err)
	if m.PoolMB != 7680-4100 {
		t.Fatalf("pool = %d MiB", m.PoolMB)
	}
	if m.Total() != 7680 {
		t.Fatalf("components sum to %d, want the host's memory", m.Total())
	}
	// Two OpenClaw-sized machines (S3, S4) fit at the floor; three do not.
	if n := m.PoolMB / OpenClawMB; n != 2 {
		t.Fatalf("pool holds %d OpenClaw machines, want 2", n)
	}
	a := m.Admission()
	if a.CapacityMB-a.HeadroomMB != m.PoolMB || a.HeadroomMB != 600 {
		t.Fatalf("admission %+v: admitted memory must be exactly the pool", a)
	}
}

func TestRES2LargerHostsOnlyGrowThePool(t *testing.T) {
	// HW-4: a larger host adds throughput, never changes the other budgets.
	small, err := ForHost(7680, Floor())
	must(t, err)
	big, err := ForHost(32768, Floor())
	must(t, err)
	if big.HostMB != small.HostMB || big.InferenceMB != small.InferenceMB || big.BrowserMB != small.BrowserMB || big.HeadroomMB != small.HeadroomMB {
		t.Fatalf("components changed with host size: %+v vs %+v", small, big)
	}
	if big.PoolMB-small.PoolMB != 32768-7680 {
		t.Fatalf("pool grew by %d", big.PoolMB-small.PoolMB)
	}
}

func TestRES2HostTooSmallForOneMachineIsRefused(t *testing.T) {
	if _, err := ForHost(5000, Floor()); !errors.Is(err, ErrTooSmall) {
		t.Fatalf("5000 MiB host: %v, want ErrTooSmall", err)
	}
	bad := Floor()
	bad.HeadroomMB = 0
	if _, err := ForHost(7680, bad); err == nil {
		t.Fatal("zero headroom accepted (S3: a group at its limit stalls)")
	}
}

func TestRES2MemTotalReadsMeminfo(t *testing.T) {
	p := filepath.Join(t.TempDir(), "meminfo")
	must(t, os.WriteFile(p, []byte("MemTotal:        7864320 kB\nMemFree:  100 kB\n"), 0o644))
	mb, err := MemTotalMB(p)
	must(t, err)
	if mb != 7680 {
		t.Fatalf("MemTotal = %d MiB", mb)
	}
}

func fakeV2(t *testing.T) *cgroup.Group {
	t.Helper()
	d := t.TempDir()
	must(t, os.WriteFile(filepath.Join(d, "cgroup.controllers"), []byte("cpu memory pids\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(d, "cgroup.subtree_control"), nil, 0o644))
	g, err := cgroup.Open(d)
	must(t, err)
	return g
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	must(t, err)
	return strings.TrimSpace(string(b))
}

// Every component's limit is enforced by its own cgroup, and the limits plus
// the broker's protection plus the headroom never exceed the host (RES-2).
func TestRES2ApplyGivesEachComponentItsOwnGroup(t *testing.T) {
	root := fakeV2(t)
	m, err := ForHost(7680, Floor())
	must(t, err)
	// The pool's group must accept per-machine children: the kernel lists
	// the memory controller in its cgroup.controllers once the parent's
	// subtree_control enables it, which the fake plays here.
	pool := filepath.Join(root.Path, "machines")
	must(t, os.MkdirAll(pool, 0o755))
	must(t, os.WriteFile(filepath.Join(pool, "cgroup.controllers"), []byte("memory\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(pool, "cgroup.subtree_control"), nil, 0o644))

	gs, err := m.Apply(root)
	must(t, err)
	mib := func(n int64) string { return strconv.FormatInt(n<<20, 10) }
	for _, c := range []struct{ group, file, want string }{
		{"broker", "memory.min", mib(1000)},
		{"broker", "memory.max", "max"},
		{"inference", "memory.max", mib(2000)},
		{"browser", "memory.max", mib(500)},
		{"machines", "memory.max", mib(m.PoolMB)},
	} {
		if got := read(t, filepath.Join(root.Path, c.group, c.file)); got != c.want {
			t.Errorf("%s/%s = %s, want %s", c.group, c.file, got, c.want)
		}
	}
	if gs.Machines == nil || gs.Machines.Path != pool {
		t.Fatalf("machines group = %+v", gs.Machines)
	}
	if got := read(t, filepath.Join(pool, "cgroup.subtree_control")); got != "+memory" {
		t.Fatalf("pool children cannot use the memory controller: %q", got)
	}
}

func TestRES4DiskReserveCoversReleaseJournalAndRecall(t *testing.T) {
	d := FloorDisk()
	if d.ReleaseMB < 1100 {
		t.Fatalf("release reserve %d MiB is smaller than one S7 release (1.0 GiB erofs + verity)", d.ReleaseMB)
	}
	if d.JournalMB <= 0 || d.RecallMB <= 0 {
		t.Fatalf("disk reserve %+v leaves out the journal or the recall index", d)
	}
	if d.ReserveBytes() != (d.ReleaseMB+d.JournalMB+d.RecallMB)<<20 {
		t.Fatalf("reserve = %d", d.ReserveBytes())
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
