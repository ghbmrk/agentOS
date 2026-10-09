package loop7

// REQ: LOOP-7, CRED-1

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
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

// P3-4b-3r-env-r8b (#651 Security 4a point 4): a fuzz child that runs sees
// exactly the pairs childEnv built for its scratch directory, nothing
// more, nothing less. The target dumps its environment.
func TestARunningFuzzChildSeesExactlyTheBuiltPairs(t *testing.T) {
	t.Setenv("AGENTOS_OWNER", "+15550100777") // synthetic
	release, out, cache := t.TempDir(), filepath.Join(t.TempDir(), "env"), t.TempDir()
	tg := fakeTarget(t, release, "env > "+out)
	s := newSource(t, newFake(), Config{Targets: []Target{tg}, Release: release, CacheDir: cache})
	if _, err := s.Fuzz(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the child wrote no environment: %v", err)
	}
	var got []string
	home := ""
	for _, kv := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, _ := strings.Cut(kv, "=")
		if k == "PWD" { // the target's shell sets PWD itself
			continue
		}
		if k == "HOME" {
			home = v
		}
		got = append(got, kv)
	}
	if !strings.HasPrefix(home, cache) {
		t.Fatalf("HOME %q is not a scratch directory under %s", home, cache)
	}
	want := childEnv(home)
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("child env %q, want %q", got, want)
	}
}
