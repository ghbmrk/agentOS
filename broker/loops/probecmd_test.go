package loops_test

// REQ: LOOP-7, LOOP-9

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
// a High finding through Report that pauses the registry's target; a
// clean round reports nothing and closes it. No canary value reaches the
// record or the owner.
func TestCanaryRoundsReportAPlantedLeakAndCloseOnACleanRound(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the canary harness")
	}
	release := t.TempDir()
	leaky := &probecmd.CommandProbe{For: loops.CheckCanary, Interval: time.Hour, Timeout: 5 * time.Minute, Release: release,
		Cmd: canaryRound(t, release, "leaky", map[string]string{"kind": "grant", "name": "G9", "label": "pre-allowance G9"})}
	r := loops.NewProbeRig(t, leaky)
	r.Run(t)
	if name, res := r.Run(t); name != "probe:canary" || res.Err != nil || res.Value != 1 {
		t.Fatalf("%q %+v", name, res)
	}
	ev := r.Evidence()
	if len(ev) != 1 || ev[0].Finding.Subject != "planted-leak" || ev[0].Finding.Severity != loops.High || ev[0].Contained != "paused" {
		t.Fatalf("evidence %+v", ev)
	}
	if c := r.Contained(); len(c) != 1 || c[0] != "G9" {
		t.Fatalf("contained %v", c)
	}
	// The harness self-scans its output; what reached Guard is kinds only.
	if !strings.HasPrefix(ev[0].Finding.Detail, "kinds: ") {
		t.Fatalf("detail %q", ev[0].Finding.Detail)
	}
	leaky.Cmd = canaryRound(t, release, "clean", nil)
	r.Advance(time.Hour)
	if name, res := r.Run(t); name != "probe:canary" || res.Err != nil || res.Value != 0 {
		t.Fatalf("%q %+v", name, res)
	}
	if r.Open(ev[0].Finding.ID) {
		t.Fatal("a clean round left the leak open")
	}
}
