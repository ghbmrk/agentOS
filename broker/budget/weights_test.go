package budget

import (
	"os"
	"path/filepath"
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
