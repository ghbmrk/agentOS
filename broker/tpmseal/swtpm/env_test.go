package swtpm

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// REQ: CRED-1
//
// P3-4b-3r-env-r8b: swtpm starts through childproc with
// exactly a fixed PATH, nothing from the test's environment. A fake dumps
// the environment it was given.
func TestSwtpmGetsExactlyItsEnvironment(t *testing.T) {
	t.Setenv("AGENTOS_OWNER", "+15550100999") // synthetic
	fake := filepath.Join(t.TempDir(), "swtpm")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec env\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := command(fake, childproc.Options{}).Output()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, kv := range strings.Fields(string(out)) {
		if !strings.HasPrefix(kv, "PWD=") { // the fake's shell sets PWD itself
			got = append(got, kv)
		}
	}
	if want := []string{toolPath}; !slices.Equal(got, want) {
		t.Fatalf("env %q, want %q", got, want)
	}
}
