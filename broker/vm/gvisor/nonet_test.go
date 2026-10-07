package gvisor

// REQ: A14, ARC-6

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
)

// A page can ask a model to fetch an internal address. The guest has no
// network, so that fetch cannot be dialed from the machine. The broker is
// the only process that dials, and it dials its own sockets.
func TestAGuestCannotDial(t *testing.T) {
	dir := t.TempDir()
	l := vm.Launch{ID: "m1", Dir: dir, Root: filepath.Join(dir, "root"), Argv: []string{"/bin/true"}}
	if err := writeBundle(filepath.Join(dir, "bundle"), l); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "bundle", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Linux struct {
			Namespaces []struct{ Type string }
		}
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	netns := false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == "network" {
			netns = true
		}
	}
	if !netns {
		t.Fatal("bundle has no private network namespace")
	}
	args := (&Runtime{Bin: "runsc", StateDir: dir}).cmd(t.Context(), "run").Args
	if !strings.Contains(strings.Join(args, " "), "--network=none") {
		t.Fatalf("runsc is not started with --network=none: %q", args)
	}
	for _, a := range args {
		if a == "--network=host" || strings.HasPrefix(a, "--network=sandbox") {
			t.Fatalf("runsc would give the guest a network: %q", a)
		}
	}
}
