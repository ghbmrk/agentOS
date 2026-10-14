package main

// REQ: RES-2

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/budget"
)

// fakeCgroupfs is a cgroup v2 mount with the broker in /system.slice/agentos.service.
func fakeCgroupfs(t *testing.T, marked bool) (cgroupHost, string) {
	t.Helper()
	dir := t.TempDir()
	fsRoot := filepath.Join(dir, "cgroup")
	own := filepath.Join(fsRoot, "system.slice", "agentos.service")
	if err := os.MkdirAll(own, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"cgroup.controllers", "cgroup.subtree_control"} {
		if err := os.WriteFile(filepath.Join(own, f), []byte("cpu io memory pids"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(own, "pids.max"), []byte("9830"), 0o644); err != nil {
		t.Fatal(err)
	}
	self := filepath.Join(dir, "self-cgroup")
	if err := os.WriteFile(self, []byte("0::/system.slice/agentos.service\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return cgroupHost{FS: fsRoot, ProcSelf: self, Delegated: func(p string) bool { return marked && p == own }}, own
}

// tree lists every path under root, so a test can prove nothing was made.
func tree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
		return nil
	})
	return out
}

func TestRES2NoDelegationNoCgroupWrites(t *testing.T) {
	cases := []struct {
		name    string
		marked  bool
		root    string
		vouched bool
	}{
		{"own group without the delegate mark", false, "", false},
		{"vouched without an explicit root", false, "", true},
		{"explicit root outside its own group", true, "/sys/fs/cgroup/agentos.slice", true},
		{"sibling with a shared prefix", true, "{own}-evil", true},
		{"parent of its own group", true, "{fs}/system.slice", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, own := fakeCgroupfs(t, c.marked)
			root := strings.NewReplacer("{own}", own, "{fs}", h.FS).Replace(c.root)
			before := tree(t, h.FS)
			g, err := openMachines(h, root, c.vouched, budget.Floor())
			if !errors.Is(err, errNotDelegated) || g != nil {
				t.Fatalf("openMachines = %v, %v; want errNotDelegated", g, err)
			}
			if after := tree(t, h.FS); strings.Join(after, "\n") != strings.Join(before, "\n") {
				t.Fatalf("cgroupfs changed without delegation:\n%s", strings.Join(after, "\n"))
			}
		})
	}
}

func TestRES2NoCgroupV2EntryIsRefused(t *testing.T) {
	h, _ := fakeCgroupfs(t, true)
	os.WriteFile(h.ProcSelf, []byte("1:memory:/foo\n"), 0o644)
	if _, err := delegatedRoot(h, "", false); !errors.Is(err, errNotDelegated) {
		t.Fatalf("err = %v, want errNotDelegated", err)
	}
}

func TestRES2DelegatedRootIsOwnGroupOrBelow(t *testing.T) {
	h, own := fakeCgroupfs(t, true)
	if r, err := delegatedRoot(h, "", false); err != nil || r != own {
		t.Fatalf("marked own group: %q, %v; want %q", r, err, own)
	}
	below := filepath.Join(own, "pool")
	if r, err := delegatedRoot(h, below, false); err != nil || r != below {
		t.Fatalf("below a marked group: %q, %v", r, err)
	}
	h.Delegated = nil
	if r, err := delegatedRoot(h, own, true); err != nil || r != own {
		t.Fatalf("vouched explicit root: %q, %v", r, err)
	}
}

func TestRES2DelegatedRootGetsTheBrokerAndPool(t *testing.T) {
	h, own := fakeCgroupfs(t, true)
	// The fake cgroupfs is files, so the component groups a kernel would
	// populate are seeded ahead.
	for _, c := range []string{"broker", "machines"} {
		os.MkdirAll(filepath.Join(own, c), 0o755)
	}
	os.WriteFile(filepath.Join(own, "machines", "cgroup.controllers"), []byte("cpu io memory pids"), 0o644)
	os.WriteFile(filepath.Join(own, "machines", "cgroup.subtree_control"), []byte("cpu io memory pids"), 0o644)
	mem, err := budget.ForHost(7680, 4, budget.Floor())
	if err != nil {
		t.Fatal(err)
	}
	g, err := openMachines(h, "", false, mem)
	if err != nil {
		t.Fatal(err)
	}
	if g.Path != filepath.Join(own, "machines") {
		t.Fatalf("pool at %s", g.Path)
	}
	if b, _ := os.ReadFile(filepath.Join(own, "broker", "cgroup.procs")); strings.TrimSpace(string(b)) == "" {
		t.Fatal("broker did not join its group")
	}
}

// A delegated group without the pids controller cannot cap a machine's
// processes, so no pool opens and the agent stays off (RES-2, SR2-4).
func TestRES2DelegatedRootWithoutPidsOpensNoPool(t *testing.T) {
	h, own := fakeCgroupfs(t, true)
	os.WriteFile(filepath.Join(own, "cgroup.controllers"), []byte("cpu io memory"), 0o644)
	mem, err := budget.ForHost(7680, 4, budget.Floor())
	if err != nil {
		t.Fatal(err)
	}
	if g, err := openMachines(h, "", false, mem); err == nil {
		t.Fatalf("pool opened without a process cap: %+v", g)
	}
	if _, err := os.Stat(filepath.Join(own, "machines")); err == nil {
		t.Fatal("machines group made without a process cap")
	}
}

// Whichever controller is missing, the owner reads one line that names
// none of them, and the log lists every missing one (UX ruling on #155).
func TestRES2MissingControllerSaysSoInStatus(t *testing.T) {
	const want = "Your agent is off: I can't yet keep it within its limits, so I need an update."
	mem, err := budget.ForHost(7680, 4, budget.Floor())
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range [][]string{{"cpu"}, {"io"}, {"memory"}, {"pids"}, {"cpu", "pids"}} {
		h, own := fakeCgroupfs(t, true)
		var have []string
		for _, c := range []string{"cpu", "io", "memory", "pids"} {
			if !slices.Contains(missing, c) {
				have = append(have, c)
			}
		}
		os.WriteFile(filepath.Join(own, "cgroup.controllers"), []byte(strings.Join(have, " ")), 0o644)
		_, err := openMachines(h, "", false, mem)
		if err == nil || !strings.Contains(err.Error(), "lacks "+strings.Join(missing, ", ")) {
			t.Errorf("missing %v: log error %v, want it to list them", missing, err)
		}
		if s := (&lateStatus{off: agentNoLimits}).Status(); s != want {
			t.Errorf("missing %v: status %q", missing, s)
		}
	}
	if strings.Contains(agentNoLimits, "memory") || strings.Contains(agentNoLimits, "cgroup") {
		t.Errorf("owner text names a mechanism: %q", agentNoLimits)
	}
}

// I/O weights are inert without iocost: the broker says so once at start
// (L3 S1 on #155, budget R12).
func TestRES2IOWeightNote(t *testing.T) {
	fsRoot := t.TempDir()
	root := filepath.Join(fsRoot, "agentos.service")
	os.MkdirAll(filepath.Join(root, "broker"), 0o755)
	if n := ioWeightNote(fsRoot, root); !strings.Contains(n, "no iocost") {
		t.Errorf("no io.weight: note %q", n)
	}
	os.WriteFile(filepath.Join(root, "broker", "io.weight"), []byte("default 1000\n"), 0o644)
	if n := ioWeightNote(fsRoot, root); !strings.Contains(n, "io.cost.qos") {
		t.Errorf("no io.cost.qos: note %q", n)
	}
	qos := filepath.Join(fsRoot, "io.cost.qos")
	os.WriteFile(qos, []byte("8:0 enable=0 ctrl=auto rpct=0.00 rlat=250000 wpct=0.00 wlat=250000 min=1.00 max=10000.00\n"), 0o644)
	if n := ioWeightNote(fsRoot, root); !strings.Contains(n, "io.cost.qos") {
		t.Errorf("iocost disabled: note %q", n)
	}
	os.WriteFile(qos, []byte("8:0 enable=0 ctrl=auto\n259:0 enable=1 ctrl=auto rpct=0.00\n"), 0o644)
	if n := ioWeightNote(fsRoot, root); n != "" {
		t.Errorf("iocost on: note %q, want none", n)
	}
}
