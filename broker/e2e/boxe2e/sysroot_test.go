package main

import (
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem/at"
)

// The bridge finds the simulated modem through its own discovery, under
// -sys-root, exactly as it finds a SIM7600G-H's AT port on the box.
func TestFakeSysrootIsDiscovered(t *testing.T) {
	root := t.TempDir()
	if err := buildSysroot(root, "/dev/pts/7"); err != nil {
		t.Fatal(err)
	}
	found := at.Discover(root)
	if len(found) != 1 || found[0].Profile != at.SIMCom {
		t.Fatalf("found %+v", found)
	}
	if found[0].ATPort != filepath.Join(root, "dev/ttyUSB2") {
		t.Fatalf("AT port %q", found[0].ATPort)
	}
	if dst, err := filepath.EvalSymlinks(filepath.Join(root, "dev")); err != nil || dst != filepath.Join(root, "dev") {
		t.Fatal(dst, err)
	}
	if err := buildSysroot(root, "/dev/pts/8"); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
}
