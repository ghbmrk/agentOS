package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

// REQ: RES-1, RES-2

// tree makes a cgroup v2 chain under a temp dir: one level per cap, the
// first the topmost. "" leaves that level without a pids.max (the mount
// root has none).
func tree(t *testing.T, caps ...string) *Group {
	t.Helper()
	d := t.TempDir()
	for i, c := range caps {
		if i > 0 {
			d = filepath.Join(d, "l"+string(rune('a'+i)))
			must(t, os.Mkdir(d, 0o755))
		}
		must(t, os.WriteFile(filepath.Join(d, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644))
		must(t, os.WriteFile(filepath.Join(d, "cgroup.subtree_control"), nil, 0o644))
		if c != "" {
			must(t, os.WriteFile(filepath.Join(d, "pids.max"), []byte(c+"\n"), 0o644))
		}
	}
	return &Group{Path: d}
}

// SR2-4i L3 carry: a root whose own pids.max reads "max" under a capped
// ancestor slice is capped by that slice. EffectivePidsMax reads the
// tightest cap up the tree to the cgroup mount root, so the reserve is
// taken from what the kernel will actually allow.
func TestSR24iEffectivePidsMaxReadsUpTheTree(t *testing.T) {
	for _, c := range []struct {
		name string
		caps []string
		want int64
	}{
		{"own cap only", []string{"", "max", "9830"}, 9830},
		{"ancestor caps a max root", []string{"", "4096", "max"}, 4096},
		{"tightest wins", []string{"", "3000", "max", "5000"}, 3000},
		{"own tighter than ancestor", []string{"", "8000", "2048"}, 2048},
		{"none capped", []string{"", "max", "max"}, 0},
	} {
		g := tree(t, c.caps...)
		n, err := g.EffectivePidsMax()
		if err != nil || n != c.want {
			t.Errorf("%s: EffectivePidsMax = %d, %v; want %d", c.name, n, err, c.want)
		}
		if own, _ := g.PidsMax(); c.caps[len(c.caps)-1] == "max" && own != 0 {
			t.Errorf("%s: PidsMax changed meaning: %d", c.name, own)
		}
	}
}

// The walk stops at the mount root: a directory above it without
// cgroup.controllers is not a cgroup, so its files are never read.
func TestSR24iEffectivePidsMaxStopsAtTheMountRoot(t *testing.T) {
	g := tree(t, "", "max")
	above := filepath.Dir(filepath.Dir(g.Path))
	// A stray pids.max above the cgroup tree must not count.
	stray := filepath.Join(above, "pids.max")
	if err := os.WriteFile(stray, []byte("10\n"), 0o644); err == nil {
		defer os.Remove(stray)
	}
	if n, err := g.EffectivePidsMax(); err != nil || n != 0 {
		t.Fatalf("EffectivePidsMax = %d, %v; want 0", n, err)
	}
}

// A bad value anywhere up the tree fails closed, as PidsMax does; the
// group's own pids.max must exist.
func TestSR24iEffectivePidsMaxFailsClosed(t *testing.T) {
	for _, bad := range []string{"0", "-1", "lots"} {
		g := tree(t, "", bad, "max")
		if _, err := g.EffectivePidsMax(); err == nil {
			t.Errorf("ancestor pids.max %q accepted", bad)
		}
	}
	g := tree(t, "", "4096", "")
	if _, err := g.EffectivePidsMax(); err == nil {
		t.Error("a group without its own pids.max accepted")
	}
}
