package loop7

// REQ: LOOP-7, CRED-1

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P3-4b-3r-env-r8: a fuzz child starts through childproc, whose run-time
// check refuses an environment carrying the daemon's owner number, here
// smuggled through the cache path into HOME. The target never runs.
func TestAFuzzChildCarryingTheOwnersNumberIsNotStarted(t *testing.T) {
	const owner = "+15550100777" // synthetic
	t.Setenv("AGENTOS_OWNER", owner)
	release, ran := t.TempDir(), filepath.Join(t.TempDir(), "ran")
	cache := filepath.Join(t.TempDir(), owner)
	tg := fakeTarget(t, release, "touch "+ran)
	s := newSource(t, newFake(), Config{Targets: []Target{tg}, Release: release, CacheDir: cache})
	_, err := s.run(context.Background(), tg)
	if err == nil || !strings.Contains(err.Error(), "childproc") || exited(err) {
		t.Fatalf("run: %v, want childproc's refusal", err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("the target ran")
	}
}
