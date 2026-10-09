package gvisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: ARC-2
//
// P3-4b-3r-env requirement 1: runsc gets a fixed PATH and nothing from
// agentosd's environment, which carries the owner's number; the guest's
// own environment is the OCI spec's (writeBundle). A fake runsc dumps the
// environment it was given.
func TestRunscGetsNoInheritedEnvironment(t *testing.T) {
	const canary = "+15550100999-runsc-canary"
	t.Setenv("AGENTOS_OWNER", canary)
	bin := filepath.Join(t.TempDir(), "runsc")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec env\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &Runtime{Bin: bin, StateDir: t.TempDir()}
	c := r.cmd(context.Background(), "state", "wk-1")
	out, err := c.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), canary) {
		t.Fatalf("runsc sees the daemon's environment:\n%s", out)
	}
	if got := strings.Join(c.Env, " "); got != "PATH=/usr/sbin:/usr/bin:/sbin:/bin" {
		t.Fatalf("runsc env %q", got)
	}
}

// fakeRunsc is testdata/fakerunsc.sh behind a wrapper that sets its
// variables, since runsc inherits none: FAKE_RUNSC_CANARY and env, which
// are NAME=value pairs.
func fakeRunsc(t *testing.T, env ...string) *Runtime {
	t.Helper()
	bin, err := filepath.Abs("testdata/fakerunsc.sh")
	if err != nil {
		t.Fatal(err)
	}
	sh := "#!/bin/sh\nexport FAKE_RUNSC_CANARY='" + runscCanary + "'\n"
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		sh += "export " + k + "='" + v + "'\n"
	}
	wrap := filepath.Join(t.TempDir(), "runsc")
	if err := os.WriteFile(wrap, []byte(sh+"exec '"+bin+"' \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return &Runtime{Bin: wrap, StateDir: filepath.Join(t.TempDir(), "runsc")}
}
