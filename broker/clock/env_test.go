package clock

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// REQ: ARC-2, CRED-1
//
// P3-4b-3r-env requirement 1 (#560 Security 4) and r8b: chronyc starts
// through childproc with exactly a fixed PATH, so the owner's number in
// agentosd's environment (AGENTOS_OWNER, from its EnvironmentFile) never
// reaches it. A fake chronyc dumps the environment it was given.
func TestChronycGetsExactlyItsEnvironment(t *testing.T) {
	const canary = "+15550100999-chronyc-canary"
	t.Setenv("AGENTOS_OWNER", canary)
	fake := filepath.Join(t.TempDir(), "chronyc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec env\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	defer func(old string) { chronyc = old }(chronyc)
	chronyc = fake
	out, err := chronycCmd(context.Background(), "tracking").Output()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, kv := range strings.Fields(string(out)) {
		if !strings.HasPrefix(kv, "PWD=") { // the fake's shell sets PWD itself
			got = append(got, kv)
		}
	}
	if want := []string{"PATH=/usr/bin:/bin"}; !slices.Equal(got, want) {
		t.Fatalf("chronyc env %q, want %q", got, want)
	}
}
