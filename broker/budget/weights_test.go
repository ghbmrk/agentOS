package budget

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// REQ: RES-1, RES-2

// Under CPU or disk contention the broker comes first, local inference
// (speech for calls) next, and the agent-machine pool and the browser
// after it (RES-2: agent machines weigh less than the broker and
// foreground; budget R12).
func TestRES2ApplyWeighsTheBrokerAboveTheMachines(t *testing.T) {
	root := fakeV2(t)
	m, err := ForHost(7680, 4, Floor())
	must(t, err)
	pool := filepath.Join(root.Path, "machines")
	must(t, os.MkdirAll(pool, 0o755))
	must(t, os.WriteFile(filepath.Join(pool, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(pool, "cgroup.subtree_control"), nil, 0o644))
	_, err = m.Apply(root)
	must(t, err)
	for _, c := range []struct{ group, cpu, io string }{
		{"broker", "1000", "default 1000"},
		{"inference", "500", "default 500"},
		{"browser", "100", "default 100"},
		{"machines", "100", "default 100"},
	} {
		if got := read(t, filepath.Join(root.Path, c.group, "cpu.weight")); got != c.cpu {
			t.Errorf("%s cpu.weight = %s, want %s", c.group, got, c.cpu)
		}
		if got := read(t, filepath.Join(root.Path, c.group, "io.weight")); got != c.io {
			t.Errorf("%s io.weight = %s, want %s", c.group, got, c.io)
		}
	}
	if BrokerWeight <= InferenceWeight || InferenceWeight <= PoolWeight || PoolWeight > BrowserWeight {
		t.Fatalf("weights out of order: broker %d, inference %d, pool %d, browser %d", BrokerWeight, InferenceWeight, PoolWeight, BrowserWeight)
	}
	// The broker's group has no process cap: it must always be able to
	// start its helpers.
	if _, err := os.Stat(filepath.Join(root.Path, "broker", "pids.max")); err == nil {
		t.Error("pids.max on the broker's group")
	}
}

// The pool's process cap leaves the host a reserve under the root's cap
// (systemd TasksMax), so machines at their caps can never take the last
// task the broker needs for a thread (L3 MUST-1 on #155, budget R14).
func TestRES2PoolPidsLeaveTheBrokerAReserve(t *testing.T) {
	for _, c := range []struct {
		root string
		want int64
	}{
		{"9830", 9830 - HostPidsReserve},
		{"max", MaxPoolPids},
		{"100000", MaxPoolPids},
	} {
		root := fakeV2(t)
		must(t, os.WriteFile(filepath.Join(root.Path, "pids.max"), []byte(c.root), 0o644))
		m, err := ForHost(7680, 4, Floor())
		must(t, err)
		pool := filepath.Join(root.Path, "machines")
		must(t, os.MkdirAll(pool, 0o755))
		must(t, os.WriteFile(filepath.Join(pool, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644))
		must(t, os.WriteFile(filepath.Join(pool, "cgroup.subtree_control"), nil, 0o644))
		_, err = m.Apply(root)
		must(t, err)
		if got := read(t, filepath.Join(pool, "pids.max")); got != strconv.FormatInt(c.want, 10) {
			t.Errorf("root pids.max %s: pool pids.max = %s, want %d", c.root, got, c.want)
		}
	}
	// A root too small for the reserve opens no pool; so does a root
	// whose cap cannot be read.
	for _, rootMax := range []string{strconv.Itoa(HostPidsReserve), ""} {
		root := fakeV2(t)
		if rootMax != "" {
			must(t, os.WriteFile(filepath.Join(root.Path, "pids.max"), []byte(rootMax), 0o644))
		} else {
			must(t, os.Remove(filepath.Join(root.Path, "pids.max")))
		}
		m, _ := ForHost(7680, 4, Floor())
		if _, err := m.Apply(root); err == nil {
			t.Errorf("root pids.max %q: pool opened without room for the broker", rootMax)
		}
		if _, err := os.Stat(filepath.Join(root.Path, "broker")); err == nil {
			t.Errorf("root pids.max %q: groups made before the cap was checked", rootMax)
		}
	}
}
