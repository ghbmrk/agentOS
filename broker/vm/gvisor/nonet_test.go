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
		Annotations map[string]string
		Linux       struct {
			Namespaces []struct{ Type, Path string }
		}
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	// With --allow-flag-override, runsc takes dev.gvisor.flag.<name>
	// annotations as flags, so dev.gvisor.flag.network could undo
	// --network=none. Neither may appear.
	for k := range spec.Annotations {
		if strings.HasPrefix(k, "dev.gvisor.flag.") {
			t.Fatalf("bundle overrides a runsc flag: %q", k)
		}
	}
	netns := false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == "network" {
			if ns.Path != "" {
				t.Fatalf("bundle joins an existing network namespace %q", ns.Path)
			}
			netns = true
		}
	}
	if !netns {
		t.Fatal("bundle has no private network namespace")
	}
	r := &Runtime{Bin: "runsc", StateDir: dir}
	for sub, image := range map[string]string{"run": "", "restore": filepath.Join(dir, "image")} {
		args := r.launchArgs(l, image)
		// A flag before the subcommand is a global flag runsc applies.
		if args[0] != sub {
			t.Fatalf("%s: runsc gets %q before the subcommand", sub, args[0])
		}
		noNetwork(t, r.argv(args...))
	}
}

// noNetwork fails unless runsc argv args leaves the guest without a
// network and cannot be overridden from the bundle.
func noNetwork(t *testing.T, args []string) {
	t.Helper()
	// runsc parses flags with Go's flag package: the last --network wins,
	// in either the --network=x or the --network x form.
	network := ""
	for i, a := range args {
		if name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "="); strings.HasPrefix(a, "-") && name == "allow-flag-override" {
			t.Fatalf("runsc lets the bundle override its flags: %q", args)
		}
		switch {
		case a == "--network" || a == "-network":
			if i+1 < len(args) {
				network = args[i+1]
			}
		case strings.HasPrefix(a, "--network=") || strings.HasPrefix(a, "-network="):
			network = a[strings.Index(a, "=")+1:]
		}
	}
	if network != "none" {
		t.Fatalf("runsc is not started with --network=none (got %q): %q", network, args)
	}
}
