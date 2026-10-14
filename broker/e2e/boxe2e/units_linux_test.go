package main

import (
	"os"
	"strings"
	"testing"
)

// execStart returns the last non-empty ExecStart= line of a unit or drop-in.
func execStart(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	last := ""
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "ExecStart="); ok && v != "" {
			last = v
		}
	}
	return last
}

// The e2e boot's modem drop-in runs the image's own bridge command with only
// the fake sysfs root added, so the run tests the shipped command line.
func TestModemDropInKeepsTheShippedCommand(t *testing.T) {
	unit := execStart(t, "../../cmd/agentos-modem/agentos-modem.service")
	drop := execStart(t, "../../../image/e2e/agentos-modem.conf")
	if want := unit + " -sys-root " + sysroot; drop != want {
		t.Fatalf("drop-in ExecStart\n %s\nwant\n %s", drop, want)
	}
}
