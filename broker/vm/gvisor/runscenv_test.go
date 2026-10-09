package gvisor

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// REQ: ARC-2, CRED-1
//
// P3-4b-3r-env requirement 1 and r8b: runsc starts through childproc with
// exactly a fixed PATH, nothing from agentosd's environment, which carries
// the owner's number; the guest's own environment is the OCI spec's
// (writeBundle). A fake runsc dumps the environment it was given.
func TestRunscGetsExactlyItsEnvironment(t *testing.T) {
	const canary = "+15550100999-runsc-canary"
	t.Setenv("AGENTOS_OWNER", canary)
	bin := filepath.Join(t.TempDir(), "runsc")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec env\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &Runtime{Bin: bin, StateDir: t.TempDir()}
	out, err := r.cmd(context.Background(), childproc.Options{}, "state", "wk-1").Output()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, kv := range strings.Fields(string(out)) {
		if !strings.HasPrefix(kv, "PWD=") { // the fake's shell sets PWD itself
			got = append(got, kv)
		}
	}
	if want := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}; !slices.Equal(got, want) {
		t.Fatalf("runsc env %q, want %q", got, want)
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
