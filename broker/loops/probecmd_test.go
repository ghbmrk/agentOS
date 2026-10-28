package loops_test

// REQ: LOOP-7, LOOP-9

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/probecmd"
)

// canaryRound runs the repository's canary harness in round mode over one
// registry target whose command is tools/canary_controls.py in mode.
// The harness runs from a release-listed wrapper in release, as probecmd
// requires (P3-4b-3a).
func canaryRound(t *testing.T, release, mode string, contain map[string]string) []string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	target := map[string]any{"name": "planted-leak", "cmd": []string{py, filepath.Join(root, "tools", "canary_controls.py"), mode}}
	if contain != nil {
		target["contain"] = contain
	}
	reg := filepath.Join(t.TempDir(), "targets.json")
	b, _ := json.Marshal(map[string]any{"targets": []any{target}})
	if err := os.WriteFile(reg, b, 0o600); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(release, "canary")
	body := "#!/bin/sh\nexec " + py + " " + filepath.Join(root, "tools", "canary.py") + ` "$@"` + "\n"
	if err := os.WriteFile(wrapper, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return []string{wrapper, "round", "--targets", reg}
}

// LOOP-7 acceptance, canary rounds: a planted leak in a product target is
// a High finding naming the registry's target to pause; a clean round
// reports nothing and lists the target as checked. No canary value
// reaches the finding.
func TestCanaryRoundsReportAPlantedLeakAndCloseOnACleanRound(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the canary harness")
	}
	release := t.TempDir()
	leaky := &probecmd.CommandProbe{For: loops.CheckCanary, Interval: time.Hour, Timeout: 5 * time.Minute, Release: release,
		Cmd: canaryRound(t, release, "leaky", map[string]string{"kind": "grant", "name": "G9", "label": "pre-allowance G9"})}
	res, err := leaky.Run(context.Background())
	if err != nil || len(res.Found) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	f := res.Found[0]
	if f.Subject != "planted-leak" || f.Severity != loops.High || f.Contain == nil || f.Contain.Name != "G9" {
		t.Fatalf("finding %+v", f)
	}
	// The harness self-scans its output; what reaches the finding is kinds only.
	if !strings.HasPrefix(f.Detail, "kinds: ") {
		t.Fatalf("detail %q", f.Detail)
	}
	leaky.Cmd = canaryRound(t, release, "clean", nil)
	res, err = leaky.Run(context.Background())
	if err != nil || len(res.Found) != 0 || !slices.Contains(res.Checked, "planted-leak") {
		t.Fatalf("clean round %+v %v", res, err)
	}
}
