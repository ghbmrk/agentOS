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

// The bridge runs as agentos-modem, so its fake sysfs must not sit under the
// seal unit's directory, which that unit makes root-only (UMask=0077) for the
// claim code: the bridge could not reach the tree and found no modem.
func TestSysrootIsOutsideTheRootOnlyDirectory(t *testing.T) {
	b, err := os.ReadFile("../../../image/e2e/agentos-e2e-seal.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\nUMask=0077\n") || !strings.Contains(string(b), "mkdir -p /run/agentos-e2e/") {
		t.Fatal("seal unit no longer makes /run/agentos-e2e root-only; revisit this test")
	}
	if strings.HasPrefix(sysroot, "/run/agentos-e2e/") {
		t.Fatalf("sysroot %s is under the root-only /run/agentos-e2e", sysroot)
	}
}

// REQ: HW-10. The steps not driven yet fail with the text the xfail table
// expects, so they read XFAIL and not FAIL.
func TestNotDrivenStepsFailWithTheExpectedText(t *testing.T) {
	d := &driver{}
	for name, run := range map[string]func() error{"guest-task": d.guestTask, "phone-control": d.phoneControl} {
		err := run()
		if err == nil || !strings.HasPrefix(err.Error(), xfail[name].want) {
			t.Errorf("%s: %v does not start with %q", name, err, xfail[name].want)
		}
	}
}
