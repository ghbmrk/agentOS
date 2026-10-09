package clock

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: ARC-2
//
// P3-4b-3r-env requirement 1 (#560 Security 4): chronyc gets a fixed PATH
// and nothing else, so the owner's number in agentosd's environment
// (AGENTOS_OWNER, from its EnvironmentFile) never reaches it. A fake
// chronyc dumps the environment it was given.
func TestChronycGetsNoInheritedEnvironment(t *testing.T) {
	const canary = "+15550100999-chronyc-canary"
	t.Setenv("AGENTOS_OWNER", canary)
	fake := filepath.Join(t.TempDir(), "chronyc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec env\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := chronycCmd(context.Background(), "tracking")
	if c.Path != chronyc {
		t.Fatalf("chronyc at %q", c.Path)
	}
	c.Path, c.Args[0] = fake, fake
	out, err := c.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), canary) || strings.Contains(string(out), "AGENTOS_OWNER") {
		t.Fatalf("chronyc sees the daemon's environment:\n%s", out)
	}
	if got := strings.Join(c.Env, " "); got != "PATH=/usr/bin:/bin" {
		t.Fatalf("chronyc env %q", got)
	}
}
