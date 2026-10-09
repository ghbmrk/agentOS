package gvisor

// REQ: RES-4, CAP-8
//
// SR2-3m: a Go runtime panic in runsc after the guest started writes its
// trace to runsc's stderr with no --log line and exits 2. The guest's
// stderr is a stream apart from runsc's (SR2-3n), so when an exec fails
// with anything on runsc's own stderr, Exec treats it as runsc's failure:
// an error, no output, and the trace only in the broker's exec log.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/vm"
)

func TestRunscPanicAfterStartAnswersNoOutput(t *testing.T) {
	r := fakeRunsc(t)
	for _, mode := range []string{"latepanic", "fullpanic"} {
		res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{mode}, MaxOutput: 4096})
		if err == nil {
			t.Fatalf("%s: runsc's panic read as a result: %+v", mode, res)
		}
		if strings.Contains(err.Error(), "canary") {
			t.Fatalf("%s: error carries runsc's text: %v", mode, err)
		}
		// The command started, so it may have run; the error is the bare
		// sentinel that says so, naming no path (SR2-3j, L3 on #396).
		if err != vm.ErrExecFailed {
			t.Fatalf("%s: error %v, want %v", mode, err, vm.ErrExecFailed)
		}
		if len(res.Stdout) > 0 || len(res.Stderr) > 0 || res.ExitCode != 0 {
			t.Fatalf("%s: runsc's panic answered output: %+v", mode, res)
		}
	}
	b, err := os.ReadFile(filepath.Join(r.StateDir, "exec.log"))
	if err != nil {
		t.Fatal(err)
	}
	// The trace is logged even when the guest's stderr filled the cap.
	for _, want := range []string{"panic: open " + runscCanary, "fatal error: " + runscCanary} {
		if !strings.Contains(string(b), want) {
			t.Errorf("exec log lacks %q:\n%s", want, b)
		}
	}
}

// execAtMark runs mode and ends Exec's context once the fake creates its
// mark, then removes the mark, which lets deadpanic's leftover process
// exit. Exec checks only ctx.Err(), so a cancel stands for the deadline,
// at a point that does not depend on the runner's speed (P1-4-flake: a
// 100ms deadline raced runsc's exit on a slow CI runner).
func execAtMark(t *testing.T, mode string) (*Runtime, vm.ExecResult, error) {
	t.Helper()
	mark := filepath.Join(t.TempDir(), "mark")
	r := fakeRunsc(t, "FAKE_RUNSC_MARK="+mark)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := make(chan bool, 1)
	go func() {
		defer cancel()
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
			if _, err := os.Stat(mark); err == nil {
				cancel()
				os.Remove(mark)
				seen <- true
				return
			}
		}
		seen <- false
	}()
	res, err := r.Exec(ctx, "wk-1", vm.Command{Argv: []string{mode}, MaxOutput: 4096})
	if !<-seen {
		t.Fatalf("%s: the fake never reached its mark; the case is not exercised", mode)
	}
	return r, res, err
}

func wantPanicLogged(t *testing.T, r *Runtime) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.StateDir, "exec.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "panic: open "+runscCanary) {
		t.Errorf("exec log lacks runsc's trace:\n%s", b)
	}
}

// A panic at the deadline, read only after the context ended, still
// answers no output (Security S1 on #391): runsc exited 2 before the
// context ended, and its stderr is read after.
func TestRunscPanicAtTheDeadlineAnswersNoOutput(t *testing.T) {
	r, res, err := execAtMark(t, "deadpanic")
	if err == nil {
		t.Fatalf("runsc's panic read as a result: %+v", res)
	}
	if len(res.Stdout) > 0 || len(res.Stderr) > 0 || res.ExitCode != 0 {
		t.Fatalf("runsc's panic answered output: %+v", res)
	}
	wantPanicLogged(t, r)
}

// runsc wrote its trace, but the context ended before it exited, so Exec
// killed it and its exit is the kill's, not 2 (P1-4-flake). What it wrote
// on its own stderr still makes it runsc's failure: no output.
func TestRunscPanicKilledAtTheDeadlineAnswersNoOutput(t *testing.T) {
	r, res, err := execAtMark(t, "killpanic")
	if err == nil {
		t.Fatalf("runsc's panic read as a result: %+v", res)
	}
	if len(res.Stdout) > 0 || len(res.Stderr) > 0 || res.ExitCode != 0 {
		t.Fatalf("runsc's panic answered output: %+v", res)
	}
	wantPanicLogged(t, r)
}

// A guest still running at the deadline, with nothing from runsc, keeps
// what it wrote: the error is the context's, and vm.Manager answers the
// partial output as TimedOut (CAP-8). Only runsc's own text withholds it.
func TestDeadlineWithoutRunscTextKeepsPartialOutput(t *testing.T) {
	_, res, err := execAtMark(t, "killquiet")
	if err == nil {
		t.Fatalf("a killed exec read as a result: %+v", res)
	}
	if string(res.Stdout) != "guest out\n" {
		t.Fatalf("partial output lost at the deadline: %+v", res)
	}
}

func TestGuestExitTwoWithoutPanicIsAResult(t *testing.T) {
	r := fakeRunsc(t)
	res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"exit2"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 2 || string(res.Stdout) != "guest out\n" {
		t.Fatalf("guest's own exit 2: %+v", res)
	}
}

// SR2-3n: the guest's stderr is a stream apart from runsc's own, so a
// guest writing inside or between the pieces of runsc's trace cannot hide
// it (Security S2 on #391), a Go fatal signal trace is caught as well as
// a panic (S3), and the guest cannot push runsc's trace out of the exec
// log (S4).
func TestGuestWritesCannotHideRunscTrace(t *testing.T) {
	r := fakeRunsc(t)
	for _, mode := range []string{"splitmarker", "splitgap", "splitheader", "sigpanic"} {
		res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{mode}, MaxOutput: 4096})
		if err != vm.ErrExecFailed {
			t.Fatalf("%s: error %v, want %v; result %+v", mode, err, vm.ErrExecFailed, res)
		}
		if len(res.Stdout) > 0 || len(res.Stderr) > 0 || res.ExitCode != 0 {
			t.Fatalf("%s: runsc's crash answered output: %+v", mode, res)
		}
	}
	b, err := os.ReadFile(filepath.Join(r.StateDir, "exec.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "GUEST") {
		t.Errorf("guest bytes in runsc's logged trace:\n%s", b)
	}
	for _, want := range []string{"panic: open " + runscCanary, "SIGSEGV: segmentation violation\nPC="} {
		if strings.Count(string(b), want) < 1 {
			t.Errorf("exec log lacks %q:\n%s", want, b)
		}
	}
}

func TestGuestFillerKeepsRunscTraceInLog(t *testing.T) {
	r := fakeRunsc(t)
	if _, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"fillerpanic"}, MaxOutput: 4096}); err != vm.ErrExecFailed {
		t.Fatalf("error %v, want %v", err, vm.ErrExecFailed)
	}
	b, err := os.ReadFile(filepath.Join(r.StateDir, "exec.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "panic: open "+runscCanary) || strings.Contains(string(b), "ffff") {
		t.Fatalf("exec log lost runsc's trace to guest filler:\n%.512s", b)
	}
}

// A guest that writes a whole Go panic trace and exits 2 keeps its output:
// its stderr is not runsc's.
func TestGuestPanicTextIsAResult(t *testing.T) {
	r := fakeRunsc(t)
	res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"guestpanic"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 2 || string(res.Stdout) != "guest out\n" || !strings.HasPrefix(string(res.Stderr), "panic: boom\n") {
		t.Fatalf("guest's own panic: %+v", res)
	}
}

// runsc's own stderr carries only its text (SR2-3n), so any failed exec
// with anything on it is runsc's failure, whatever the exit and whether
// or not the context ended (P1-4-flake-crashed). Each case below writes
// the pid first, so the command started and only that text decides.

// runsc killed by something other than Exec (a cgroup OOM kill) after
// writing its trace exits -1 with the context alive.
func TestRunscKilledFromOutsideAfterTraceAnswersNoOutput(t *testing.T) {
	r := fakeRunsc(t)
	res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"oompanic"}, MaxOutput: 4096})
	if err != vm.ErrExecFailed {
		t.Fatalf("error %v, want %v; result %+v", err, vm.ErrExecFailed, res)
	}
	if len(res.Stdout) > 0 || len(res.Stderr) > 0 || res.ExitCode != 0 {
		t.Fatalf("runsc's trace answered output: %+v", res)
	}
	wantPanicLogged(t, r)
}

func TestRunscTextOnAnyFailedExitAnswersNoOutput(t *testing.T) {
	r := fakeRunsc(t)
	res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"exit1text"}, MaxOutput: 4096})
	if err != vm.ErrExecFailed {
		t.Fatalf("error %v, want %v; result %+v", err, vm.ErrExecFailed, res)
	}
	if len(res.Stdout) > 0 || len(res.Stderr) > 0 || res.ExitCode != 0 {
		t.Fatalf("runsc's text answered output: %+v", res)
	}
	b, err := os.ReadFile(filepath.Join(r.StateDir, "exec.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "W runsc: "+runscCanary) {
		t.Errorf("exec log lacks runsc's line:\n%s", b)
	}
}

// runsc exits 0 after a trace, but a process it left holds the pipes past
// ExecWaitDelay, so the wait fails with ErrWaitDelay, not an exit. That is
// a failed exec too. The same exit 0 and text with nothing holding the
// pipes is err == nil and reads as a result; the code keeps both rows.
func TestRunscTextPastWaitDelayAnswersNoOutput(t *testing.T) {
	mark := filepath.Join(t.TempDir(), "mark")
	r := fakeRunsc(t, "FAKE_RUNSC_MARK="+mark)
	defer os.Remove(mark)
	res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"waitdelaytext"}, MaxOutput: 4096})
	if _, serr := os.Stat(mark); serr != nil {
		t.Fatalf("the leftover did not hold the pipes; the case is not exercised: %v", serr)
	}
	if err != vm.ErrExecFailed {
		t.Fatalf("error %v, want %v; result %+v", err, vm.ErrExecFailed, res)
	}
	if len(res.Stdout) > 0 || len(res.Stderr) > 0 || res.ExitCode != 0 {
		t.Fatalf("runsc's trace answered output: %+v", res)
	}
	wantPanicLogged(t, r)
}

// The exit-0 row of the same rule: runsc writes to its stderr but the
// exec succeeds (err == nil), so it stays a result and nothing is logged.
// This pins `err != nil` in crashed: without it, this test fails.
func TestRunscTextOnSuccessIsAResult(t *testing.T) {
	r := fakeRunsc(t)
	res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"exit0text"}, MaxOutput: 4096})
	if err != nil {
		t.Fatalf("a successful exec with runsc text read as a failure: %v", err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != "guest out\n" {
		t.Fatalf("a successful exec with runsc text: %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(r.StateDir, "exec.log")); len(b) > 0 {
		t.Fatalf("a successful exec was logged:\n%s", b)
	}
}

// A guest's own non-zero exit, with nothing on runsc's stderr, stays a
// result: only runsc's text withholds output.
func TestGuestNonZeroExitWithoutRunscTextIsAResult(t *testing.T) {
	r := fakeRunsc(t)
	res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"quiet"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || string(res.Stdout) != "guest out\n" || string(res.Stderr) != "guest err\n" {
		t.Fatalf("guest's own exit 3: %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(r.StateDir, "exec.log")); len(b) > 0 {
		t.Fatalf("a guest's exit was logged:\n%s", b)
	}
}
