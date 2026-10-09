package workers

// REQ: CAP-8, RES-4

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// runscExec is the rig's runtime with commands run by gVisor's Exec,
// against a fake runsc (SR2-3h).
type runscExec struct {
	*runtime
	g *gvisor.Runtime
}

func (r runscExec) Exec(ctx context.Context, id string, c vm.Command) (vm.ExecResult, error) {
	return r.g.Exec(ctx, id, c)
}

// SR2-3h: a runsc that writes a host path to its stderr, failing before
// the guest's command starts, after it started, or in a panic before or
// after the command started (SR2-3m), or finding no program (SR2-3p), shows the guest neither the path
// nor any of runsc's text, in worker_exec's answer or its error; a
// command that runs answers its own output. The error says only whether
// the command may have run (SR2-3j).
func TestRunscMessagesNeverReachTheGuest(t *testing.T) {
	bin, err := filepath.Abs("../vm/gvisor/testdata/fakerunsc.sh")
	if err != nil {
		t.Fatal(err)
	}
	// runsc inherits no environment (P3-4b-3r-env): a wrapper sets the
	// fake's canary.
	wrap := filepath.Join(t.TempDir(), "runsc")
	if err := os.WriteFile(wrap, []byte("#!/bin/sh\nexport FAKE_RUNSC_CANARY='"+canary+"'\nexec '"+bin+"' \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	rt := runscExec{&runtime{running: map[string]vm.Launch{}}, &gvisor.Runtime{Bin: wrap, StateDir: filepath.Join(t.TempDir(), "runsc")}}
	r := newRigOn(t, 8000, 0, rt)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w", "mem_mb": 256}, nil)
	mc, _ := r.m.Get("agent")
	call := func(mode string) (string, error) {
		b, _ := json.Marshal(m{"name": "w", "argv": []string{mode}})
		text, _, err := r.tools.Call(context.Background(), "agent", mc.Lineage, toolExec, b)
		return text, err
	}
	for _, mode := range []string{"prestart", "panic", "wait", "latepanic", "fullpanic", "nope-tool"} {
		text, err := call(mode)
		if err == nil {
			t.Fatalf("%s: runsc's failure answered %s", mode, text)
		}
		noLeak(t, mode+" error", err.Error())
		noLeak(t, mode+" answer", text)
		// Fixed text that says whether the command may have run
		// (SR2-3j, release finding 362-2).
		want := "worker w: the command did not start; retry it"
		// A panic after the start may have run too (SR2-3m, L3 on #396),
		// and so may any failure runsc does not show was before the start
		// (SR2-3q). A missing program advises no retry (SR2-3p).
		switch mode {
		case "panic", "wait", "latepanic", "fullpanic":
			want = "worker w: the runtime failed after the command started, so it may have run; check what it changed before running it again"
		case "nope-tool":
			want = "worker w: the command did not start: its program was not found or cannot run; check its path and that it is executable, since a retry fails the same way"
		}
		if err.Error() != want {
			t.Fatalf("%s: %q, want %q", mode, err, want)
		}
	}
	text, err := call("ok")
	if err != nil {
		t.Fatal(err)
	}
	var ex execOut
	if err := json.Unmarshal([]byte(text), &ex); err != nil {
		t.Fatal(err)
	}
	if ex.ExitCode != 3 || ex.Stdout != "guest out\n" || ex.Stderr != "guest err\n" {
		t.Fatalf("a command that ran: %+v", ex)
	}
}
