package workers

// REQ: CAP-8, RES-4

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
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
// the guest's command starts, after it started, or in a panic, shows the
// guest neither the path nor any of runsc's text, in worker_exec's
// answer or its error; a command that runs answers its own output.
func TestRunscMessagesNeverReachTheGuest(t *testing.T) {
	bin, err := filepath.Abs("../vm/gvisor/testdata/fakerunsc.sh")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_RUNSC_CANARY", canary)
	rt := runscExec{&runtime{running: map[string]vm.Launch{}}, &gvisor.Runtime{Bin: bin, StateDir: filepath.Join(t.TempDir(), "runsc")}}
	r := newRigOn(t, 8000, 0, rt)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w", "mem_mb": 256}, nil)
	mc, _ := r.m.Get("agent")
	call := func(mode string) (string, error) {
		b, _ := json.Marshal(m{"name": "w", "argv": []string{mode}})
		text, _, err := r.tools.Call(context.Background(), "agent", mc.Lineage, toolExec, b)
		return text, err
	}
	for _, mode := range []string{"prestart", "panic", "wait"} {
		text, err := call(mode)
		if err == nil {
			t.Fatalf("%s: runsc's failure answered %s", mode, text)
		}
		noLeak(t, mode+" error", err.Error())
		noLeak(t, mode+" answer", text)
		if !strings.Contains(err.Error(), "(ref ") || strings.Contains(err.Error(), "guest") {
			t.Fatalf("%s: want a ref and nothing of the command's output: %v", mode, err)
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
