package budget

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ghbmrk/agentos/broker/cgroup"
)

// REQ: RES-1, RES-2

// SR2-4i L3 carry: the pool's cap comes from the effective cap up the
// tree, so a root reading "max" under a capped slice still leaves the host
// its reserve of the slice's cap.
func TestSR24iPoolPidsFollowAnAncestorCap(t *testing.T) {
	slice := t.TempDir()
	must(t, os.WriteFile(filepath.Join(slice, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(slice, "cgroup.subtree_control"), nil, 0o644))
	must(t, os.WriteFile(filepath.Join(slice, "pids.max"), []byte("4096\n"), 0o644))
	dir := filepath.Join(slice, "agentos.service")
	must(t, os.Mkdir(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), nil, 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "pids.max"), []byte("max\n"), 0o644))
	root, err := cgroup.Open(dir)
	must(t, err)
	m, err := ForHost(7680, 4, Floor())
	must(t, err)
	pool := filepath.Join(dir, "machines")
	must(t, os.MkdirAll(pool, 0o755))
	must(t, os.WriteFile(filepath.Join(pool, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(pool, "cgroup.subtree_control"), nil, 0o644))
	_, err = m.Apply(root)
	must(t, err)
	if got, want := read(t, filepath.Join(pool, "pids.max")), strconv.Itoa(4096-HostPidsReserve); got != want {
		t.Fatalf("pool pids.max = %s under a 4096 slice, want %s", got, want)
	}
	// A slice too small for the reserve opens no pool.
	must(t, os.WriteFile(filepath.Join(slice, "pids.max"), []byte(strconv.Itoa(HostPidsReserve)), 0o644))
	if _, err := m.Apply(root); err == nil {
		t.Fatal("a pool opened under a slice that leaves no reserve")
	}
}
