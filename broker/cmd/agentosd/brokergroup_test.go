package main

// REQ: RES-2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/budget"
)

// A broker/ an earlier run left may carry a kill count from systemd's
// stop, and clone3 children of a starter in such a group die at birth
// (CGROUP-kc3-1). So the broker's group is removed and made new at each
// start, never reused (#5143).
func TestRES2BrokerGroupIsNewAtEachStart(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "broker")
	if err := os.Mkdir(old, 0o755); err != nil {
		t.Fatal(err)
	}
	var removed []string
	removeBrokerDir = func(p string) error {
		removed = append(removed, p)
		return os.Remove(p)
	}
	defer func() { removeBrokerDir = os.Remove }()
	b, err := newBrokerGroup(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != old || b.Path != old {
		t.Fatalf("removed %v, group %s; want %s removed and made again", removed, b.Path, old)
	}
	if fi, err := os.Stat(old); err != nil || !fi.IsDir() {
		t.Fatalf("broker/ not made again: %v", err)
	}
	// With nothing left over, the group is simply made.
	root2 := t.TempDir()
	if _, err := newBrokerGroup(root2); err != nil {
		t.Fatalf("no leftover: %v", err)
	}
}

// A leftover that will not go (a process or a group still in it) is an
// error that names the cause; the broker does not join it.
func TestRES2BrokerGroupLeftoverThatWillNotGoIsAnError(t *testing.T) {
	own := t.TempDir()
	old := filepath.Join(own, "broker")
	if err := os.MkdirAll(filepath.Join(old, "held"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newBrokerGroup(own); err == nil || !strings.Contains(err.Error(), "left by an earlier run, cannot be removed") {
		t.Fatalf("leftover that will not go: %v", err)
	}
	mem, err := budget.ForHost(7680, 4, budget.Floor())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openPool(own, mem); err == nil {
		t.Fatal("openPool joined a leftover broker group")
	}
	if _, err := os.Stat(filepath.Join(old, "cgroup.procs")); !os.IsNotExist(err) {
		t.Fatalf("the broker joined the leftover group: %v", err)
	}
}
