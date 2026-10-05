package main

// REQ: RES-2

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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
		if err := os.WriteFile(filepath.Join(own, f), []byte("cpu memory"), 0o644); err != nil {
			t.Fatal(err)
		}
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
	os.WriteFile(filepath.Join(own, "machines", "cgroup.controllers"), []byte("memory"), 0o644)
	os.WriteFile(filepath.Join(own, "machines", "cgroup.subtree_control"), []byte("memory"), 0o644)
	mem, err := budget.ForHost(7680, budget.Floor())
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

func TestRES2NoMemoryControlsSaysSoInStatus(t *testing.T) {
	if s := (&lateStatus{off: agentNoMemControls}).Status(); s != "Agent: off, the box's memory controls are not set up; it needs an update." {
		t.Fatalf("status = %q", s)
	}
}
