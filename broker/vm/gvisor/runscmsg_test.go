package gvisor

// REQ: RES-4, CAP-8
//
// SR2-3h: runsc's own messages never reach the guest. runsc's Errorf
// writes to stderr, which runsc exec shares with the guest's command, so
// when runsc fails (its --log names an error, or the guest never
// started) Exec answers an error and no output; runsc's messages, the
// error log, debug log and stderr, go only to the broker's exec log.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
)

const runscCanary = "/canary-host/agentos/state/runsc/wk-c4n4ry_"

func fakeRunsc(t *testing.T) *Runtime {
	t.Helper()
	bin, err := filepath.Abs("testdata/fakerunsc.sh")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_RUNSC_CANARY", runscCanary)
	return &Runtime{Bin: bin, StateDir: filepath.Join(t.TempDir(), "runsc")}
}

func TestRunscFailureAnswersNoOutputAndNoRunscText(t *testing.T) {
	r := fakeRunsc(t)
	for _, mode := range []string{"prestart", "panic", "wait"} {
		res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{mode}})
		if err == nil {
			t.Fatalf("%s: runsc's failure read as a result: %+v", mode, res)
		}
		if strings.Contains(err.Error(), "canary") {
			t.Fatalf("%s: error carries runsc's text: %v", mode, err)
		}
		if len(res.Stdout) > 0 || len(res.Stderr) > 0 || res.ExitCode != 0 {
			t.Fatalf("%s: runsc's failure answered output: %+v", mode, res)
		}
	}
	b, err := os.ReadFile(filepath.Join(r.StateDir, "exec.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"loading container failed: " + runscCanary, "panic: open " + runscCanary, "waiting on pid 7: " + runscCanary, "I runsc exec"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("exec log lacks %q:\n%s", want, b)
		}
	}
	fi, err := os.Stat(filepath.Join(r.StateDir, "exec.log"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("exec log mode: %v %v", fi.Mode(), err)
	}
	left, _ := filepath.Glob(filepath.Join(r.StateDir, "exec-*"))
	if len(left) > 0 {
		t.Fatalf("per-exec files left behind: %v", left)
	}
}

func TestGuestExitIsAResultAndLogsNothing(t *testing.T) {
	r := fakeRunsc(t)
	res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"ok"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || string(res.Stdout) != "guest out\n" || string(res.Stderr) != "guest err\n" {
		t.Fatalf("guest's own exit: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(r.StateDir, "exec.log")); !os.IsNotExist(err) {
		t.Fatalf("a guest's exit was logged as runsc's failure: %v", err)
	}
}

func TestExecLogStaysWithinItsCap(t *testing.T) {
	r := fakeRunsc(t)
	defer func(n int64) { execLogMax = n }(execLogMax)
	execLogMax = 4 << 10
	for i := 0; i < 100; i++ {
		if _, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"prestart"}}); err == nil {
			t.Fatal("no error")
		}
	}
	var total int64
	for _, p := range []string{"exec.log", "exec.log.1"} {
		fi, err := os.Stat(filepath.Join(r.StateDir, p))
		if err != nil {
			t.Fatal(err)
		}
		total += fi.Size()
	}
	if total > 2*execLogMax {
		t.Fatalf("exec logs hold %d bytes, cap %d", total, 2*execLogMax)
	}
}
