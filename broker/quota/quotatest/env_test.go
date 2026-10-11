package quotatest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// REQ: CRED-1
//
// P3-4b-3r-env-r8b: mkfs, mount and umount start through childproc with
// exactly a fixed PATH, nothing from the test's environment. A fake dumps
// the environment it was given.
func TestToolsGetExactlyTheirEnvironment(t *testing.T) {
	t.Setenv("AGENTOS_OWNER", "+15550100999") // synthetic
	fake := filepath.Join(t.TempDir(), "mkfs")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec env\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := command(fake).CombinedOutput()
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
