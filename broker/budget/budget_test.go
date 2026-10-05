package budget

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/cgroup"
)

// REQ: RES-2, RES-4, CAP-1

func TestRES2FloorBudgetMatchesTheSpecTable(t *testing.T) {
	f := Floor()
	if f.HostMB != 1024 || f.InferenceMB != 2048 || f.BrowserMB != 512 || f.HeadroomMB != 600 {
		t.Fatalf("floor = %+v, want SPEC RES-2's 1.0 / 2.0 / 0.5 GB and 0.6 GB headroom", f)
	}
}

func TestRES2PoolIsWhatTheDeclaredComponentsLeave(t *testing.T) {
	// An 8 GB N95 reports about 7.6 GiB: firmware and the iGPU take the rest.
	m, err := ForHost(7680, 4, Floor())
	must(t, err)
	if m.PoolMB != 7680-4184 {
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

func TestRES2LargerHostsKeepEveryOtherBudget(t *testing.T) {
	// HW-4: a larger host never changes the other budgets. Its pool grows
	// up to CapMB for its cores (RES-2c), no further.
	small, err := ForHost(7680, 4, Floor())
	must(t, err)
	big, err := ForHost(32768, 4, Floor())
	must(t, err)
	if big.HostMB != small.HostMB || big.InferenceMB != small.InferenceMB || big.BrowserMB != small.BrowserMB || big.HeadroomMB != small.HeadroomMB {
		t.Fatalf("components changed with host size: %+v vs %+v", small, big)
	}
	if big.PoolMB != BaseCapMB-big.HeadroomMB || big.PoolMB <= small.PoolMB {
		t.Fatalf("pool %d MiB on a large host, %d at the floor", big.PoolMB, small.PoolMB)
	}
}

// RES-2c (budget R2): the cap on capacity is max(4500, headroom +
// floor(cores/2) × OpenClawMB), one OpenClaw machine per two cores, so a
// box with more memory and cores runs more machines. At four cores or
// fewer it is the 4500 MiB it was, so the N95 floor is unchanged.
func TestRES2cCapGrowsWithCores(t *testing.T) {
	h := Floor().HeadroomMB
	for cores, want := range map[int]int64{
		0: BaseCapMB, 1: BaseCapMB, 4: BaseCapMB, 5: BaseCapMB,
		6:  h + 3*OpenClawMB, // 5256
		8:  h + 4*OpenClawMB,
		16: h + 8*OpenClawMB,
		-2: BaseCapMB,
	} {
		if got := CapMB(cores, h); got != want {
			t.Errorf("%d cores: cap %d MiB, want %d", cores, got, want)
		}
	}
	// N95: 4 cores, about 7.5 GiB. Memory binds, as before (4096).
	n95, err := ForHost(7680, 4, Floor())
	must(t, err)
	if n95.PoolMB+n95.HeadroomMB != 4096 {
		t.Fatalf("N95 capacity %d MiB", n95.PoolMB+n95.HeadroomMB)
	}
	// 32 GiB with 16 cores: cores bind, eight OpenClaw machines fit.
	big, err := ForHost(32768, 16, Floor())
	must(t, err)
	if big.PoolMB != 8*OpenClawMB || big.PoolMB/OpenClawMB != 8 {
		t.Fatalf("16-core 32 GiB pool %d MiB", big.PoolMB)
	}
	// 16 GiB with 16 cores: memory binds (16384 - 3584 = 12800 < 13016).
	mid, err := ForHost(16384, 16, Floor())
	must(t, err)
	if mid.PoolMB+mid.HeadroomMB != 16384-1024-2048-512 || mid.Total() != 16384 {
		t.Fatalf("16-core 16 GiB: %+v", mid)
	}
	// A larger headroom setting raises the cap with it, so the machines
	// a box's cores allow still fit.
	if CapMB(16, 1000) != 1000+8*OpenClawMB {
		t.Fatalf("cap with 1000 MiB headroom: %d", CapMB(16, 1000))
	}
}

func TestRES2SmallHostPoolAndBadBudgets(t *testing.T) {
	// A host too small for one machine gets the pool it has; agentosd turns
	// the agent off and says so.
	m, err := ForHost(5000, 4, Floor())
	must(t, err)
	if m.PoolMB >= OpenClawMB {
		t.Fatalf("5000 MiB host: pool %d MiB holds a machine", m.PoolMB)
	}
	bad := Floor()
	bad.HeadroomMB = 0
	if _, err := ForHost(7680, 4, bad); err == nil {
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
	m, err := ForHost(7680, 4, Floor())
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
		{"broker", "memory.min", mib(1024)},
		{"broker", "memory.max", "max"},
		{"inference", "memory.max", mib(2048)},
		{"browser", "memory.max", mib(512)},
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

// The S1 test kit's floor_fit reports the same floor budget the broker
// applies (P2-5r: one source for it), so the N95 reading checks the real
// figures.
func TestRES2TestKitUsesTheSameFloor(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "spikes", "S1S2-testkit", "mkosi", "mkosi.extra", "usr", "lib", "testkit", "testkit.py"))
	must(t, err)
	f := Floor()
	want := fmt.Sprintf(`FLOOR = {"host": %d, "inference": %d, "browser": %d, "headroom": %d}`, f.HostMB, f.InferenceMB, f.BrowserMB, f.HeadroomMB)
	if !strings.Contains(string(b), want) {
		t.Fatalf("testkit.py has no %s", want)
	}
	if !strings.Contains(string(b), fmt.Sprintf("max(%d, FLOOR[\"headroom\"] + cores // 2 * OPENCLAW_MB)", BaseCapMB)) {
		t.Fatalf("testkit.py does not cap capacity as CapMB does")
	}
	if !strings.Contains(string(b), fmt.Sprintf("OPENCLAW_MB = %d", OpenClawMB)) {
		t.Fatalf("testkit.py has no OPENCLAW_MB = %d", OpenClawMB)
	}
}

// MemAvailable is read the same way, for how many forks fit (CAP-1).
func TestMemAvailableFromMeminfo(t *testing.T) {
	p := filepath.Join(t.TempDir(), "meminfo")
	os.WriteFile(p, []byte("MemTotal:       16000000 kB\nMemFree:          100 kB\nMemAvailable:    2097152 kB\n"), 0o644)
	mb, err := MemAvailableMB(p)
	if err != nil || mb != 2048 {
		t.Fatalf("MemAvailableMB = %d, %v; want 2048", mb, err)
	}
	os.WriteFile(p, []byte("MemTotal: 16000000 kB\n"), 0o644)
	if _, err := MemAvailableMB(p); err == nil {
		t.Fatal("no MemAvailable line read as a value")
	}
}
