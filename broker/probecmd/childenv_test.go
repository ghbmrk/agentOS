package probecmd

// REQ: LOOP-7, CRED-1

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// P3-4b-3r-env-r8: a probe command starts through childproc, whose
// run-time check refuses an environment carrying the daemon's owner
// number, here smuggled through TMPDIR into the probe's HOME. The command
// never runs.
func TestAProbeCarryingTheOwnersNumberIsNotStarted(t *testing.T) {
	const owner = "+15550100777" // synthetic
	ran := filepath.Join(t.TempDir(), "ran")
	p := script(t, 5*time.Second, "touch "+ran)
	tmp := filepath.Join(t.TempDir(), owner)
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	t.Setenv("AGENTOS_OWNER", owner)
	_, err := p.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "childproc") {
		t.Fatalf("run: %v, want childproc's refusal", err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("the command ran")
	}
}
