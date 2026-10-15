package main

import (
	"os"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
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

// REQ: HW-10. The step not driven yet fails with the text the xfail table
// expects, so it reads XFAIL and not FAIL; phone-control is driven, so it
// is off the list and an unpassed run reads FAIL.
func TestNotDrivenStepsFailWithTheExpectedText(t *testing.T) {
	d := &driver{}
	if err := d.guestTask(); err == nil || !strings.HasPrefix(err.Error(), xfail["guest-task"].want) {
		t.Errorf("guest-task: %v does not start with %q", err, xfail["guest-task"].want)
	}
	if _, ok := xfail["phone-control"]; ok {
		t.Error("phone-control is driven (#1714) but still on the expected-failure list")
	}
	if err := d.phoneControl(); err == nil || strings.HasPrefix(err.Error(), notDriven) {
		t.Errorf("phone-control without a paired phone: %v", err)
	}
}

// REQ: HW-10. The e2e boot's vault drop-in changes only which binary runs:
// it binds the driver share's agentos_e2e build over the shipped path the
// unit's own command line runs, orders after the unit that mounts the
// share, and keeps the shipped command and sandbox (ASSUMPTIONS E10).
func TestVaultDropInSwapsOnlyTheBinary(t *testing.T) {
	const shipped = "/usr/lib/agentos/agentos-egress"
	unit := execStart(t, "../../../image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-egress.service")
	if !strings.Contains(unit, " "+shipped+" serve ") {
		t.Fatalf("shipped ExecStart %q no longer runs %s", unit, shipped)
	}
	b, err := os.ReadFile("../../../image/e2e/agentos-egress.conf")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			got = append(got, l)
		}
	}
	want := []string{
		"[Unit]", "Requires=agentos-e2e-seal.service", "After=agentos-e2e-seal.service",
		"[Service]", "BindReadOnlyPaths=/run/agentos-e2e/share/agentos-egress:" + shipped,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("drop-in:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The workflow builds the tagged binary where the share's bind reads it,
	// and ci_boot.sh passes the drop-in.
	wf, err := os.ReadFile("../../../.github/workflows/image.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wf), `go build -tags agentos_e2e -trimpath -ldflags=-buildid= -o "$RUNNER_TEMP/e2e/agentos-egress" ./cmd/agentos-egress`) {
		t.Fatal("image.yml does not build the agentos_e2e vault process into the driver share")
	}
	boot, err := os.ReadFile("../../../image/ci_boot.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(boot), "$(cred systemd.unit-dropin.agentos-egress.service agentos-egress.conf)") {
		t.Fatal("ci_boot.sh does not pass the vault drop-in")
	}
}

// The stub's socket is outside the seal unit's root-only directory, which
// the vault's user cannot traverse.
func TestStubSocketIsOutsideTheRootOnlyDirectory(t *testing.T) {
	if strings.HasPrefix(codexstub.Socket, "/run/agentos-e2e/") {
		t.Fatalf("stub socket %s is under the root-only /run/agentos-e2e", codexstub.Socket)
	}
}

func TestHasTag(t *testing.T) {
	bi := &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "-tags", Value: "netgo,agentos_e2e"}}}
	if !hasTag(bi, "agentos_e2e") || hasTag(bi, "agentos") || hasTag(&debug.BuildInfo{}, "agentos_e2e") {
		t.Fatal("hasTag")
	}
	// This test binary is not the tagged build.
	if own, ok := debug.ReadBuildInfo(); ok && hasTag(own, e2eTag) {
		t.Fatal("test binary built with the e2e tag")
	}
}
