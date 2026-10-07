package gvisor

// REQ: RES-4, CAP-8

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
)

// SR2-3h: a runsc that fails before the guest starts must not put its own
// text, including a host path, in the tool result or the error.
func TestRunscDiagnosticsStayOutOfTheGuest(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "runsc")
	script := "#!/bin/sh\necho 'CANARY /var/lib/agentos/host-secret' >&2\nexit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	r := &Runtime{Bin: bin, StateDir: state}
	res, err := r.Exec(context.Background(), "m1", vm.Command{Argv: []string{"/bin/true"}})
	blob := err.Error() + string(res.Stdout) + string(res.Stderr)
	if err == nil || strings.Contains(blob, "CANARY") || strings.Contains(blob, "host-secret") {
		t.Fatalf("diagnostic reached the guest: %v stdout %q stderr %q", err, res.Stdout, res.Stderr)
	}
	if !strings.Contains(err.Error(), "ref ") {
		t.Fatalf("error has no ref: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(state, "exec.log"))
	if err != nil || !strings.Contains(string(b), "CANARY /var/lib/agentos/host-secret") {
		t.Fatalf("log: %v %q", err, b)
	}
	fi, err := os.Stat(filepath.Join(state, "exec.log"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("log mode: %v %v", fi, err)
	}
	// The debug log flag is on the exec line, before the verb.
	args := r.cmd(context.Background(), "--debug-log="+filepath.Join(state, "exec.log"), "exec").Args
	if !strings.Contains(strings.Join(args, " "), "--debug-log=") {
		t.Fatalf("args: %v", args)
	}
}
