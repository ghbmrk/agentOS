package vm

// REQ: RES-4, PLN-6

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
)

// #5091 item 2: a runtime that keeps refusing Kill because an earlier
// kill in the machine still runs (gvisor's pending in-sandbox kill, V37)
// leaves the machine Running for good. From the wedgedAfter-th refusal in
// a row the failure says so (ErrWedged); a different outcome resets the
// count, and a kill that finally works stops the machine as usual.
func TestRepeatedPendingKillReportsWedged(t *testing.T) {
	if wedgedAfter != 3 {
		t.Fatalf("wedgedAfter is %d, V37 says the third failure in a row", wedgedAfter)
	}
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	e := newEnv(t, 2000)
	e.create("exp", admission.Experiment, 1500)
	pending := fmt.Errorf("fake: %w", ErrKillPending)
	setRefuse := func(err error) {
		e.rt.mu.Lock()
		e.rt.refuseKill = err
		e.rt.mu.Unlock()
	}
	preempt := func(i int, wantWedged bool) {
		t.Helper()
		err := e.m.Preempt("exp")
		if !errors.Is(err, ErrKillPending) {
			t.Fatalf("preemption %d: %v, want ErrKillPending", i, err)
		}
		if errors.Is(err, ErrWedged) != wantWedged {
			t.Fatalf("preemption %d: %v, wedged reported %v, want %v", i, err, !wantWedged, wantWedged)
		}
	}
	snap, err := e.m.Checkpoint(bg, "exp")
	must(t, err)
	setRefuse(pending)
	for i := 1; i < wedgedAfter; i++ {
		preempt(i, false)
	}
	// A kill that works resets the count: the rollback stops this life.
	setRefuse(nil)
	must(t, e.m.Rollback(bg, "exp", snap.ID))
	setRefuse(pending)
	for i := 1; i < wedgedAfter; i++ {
		preempt(i, false)
	}
	// A failure of another kind means the runtime got past its wait.
	setRefuse(errors.New("fake: kill refused"))
	if err := e.m.Preempt("exp"); err == nil || errors.Is(err, ErrWedged) {
		t.Fatalf("other kill failure: %v, want a failure not reported wedged", err)
	}
	setRefuse(pending)
	for i := 1; i <= wedgedAfter+1; i++ {
		preempt(i, i >= wedgedAfter)
	}
	// The wedged line is logged once, at the wedgedAfter-th failure.
	if n := strings.Count(logged.String(), "exp: wedged"); n != 1 {
		t.Fatalf("wedged logged %d times, want once:\n%s", n, logged.String())
	}
	if _, ok := e.rt.memOf("exp"); !ok {
		t.Fatal("fake: the machine should still be running")
	}
	setRefuse(nil)
	if err := e.m.Preempt("exp"); err != nil {
		t.Fatal(err)
	}
	waitState(t, e, "exp", Preempted)
}

// #5098: the wedged state reaches the status the owner reads. Wedged lists
// a machine from the wedgedAfter-th pending-kill refusal in a row, while it
// still reads Running and stays counted (RES-4); a refusal of another kind
// or a kill that works takes it off, and a destroyed machine is never
// listed.
func TestWedgedListsTheMachine(t *testing.T) {
	log.SetOutput(new(bytes.Buffer))
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	e := newEnv(t, 4000)
	e.create("exp", admission.Experiment, 1500)
	e.create("other", admission.Experiment, 1500)
	setRefuse := func(err error) {
		e.rt.mu.Lock()
		e.rt.refuseKill = err
		e.rt.mu.Unlock()
	}
	wantWedged := func(step string, want ...string) {
		t.Helper()
		if got := e.m.Wedged(); !slices.Equal(got, want) {
			t.Fatalf("%s: Wedged() = %q, want %q", step, got, want)
		}
	}
	refuse := func(id string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if err := e.m.Preempt(id); !errors.Is(err, ErrKillPending) {
				t.Fatalf("%s preemption %d: %v, want ErrKillPending", id, i+1, err)
			}
		}
	}
	pending := fmt.Errorf("fake: %w", ErrKillPending)
	wantWedged("fresh")
	setRefuse(pending)
	refuse("exp", wedgedAfter-1)
	wantWedged("below the threshold")
	refuse("exp", 1)
	wantWedged("at the threshold", "exp")
	refuse("exp", 1)
	wantWedged("past the threshold", "exp")
	// Still Running and counted: only a host restart frees it.
	if mc, err := e.m.Get("exp"); err != nil || mc.State != Running {
		t.Fatalf("wedged machine: %+v, %v, want Running", mc, err)
	}
	if _, ok := e.adm.Snapshot().Running["exp"]; !ok {
		t.Fatal("wedged machine no longer counted by admission")
	}
	refuse("other", wedgedAfter)
	wantWedged("two wedged", "exp", "other")
	// A refusal of another kind: the runtime got past its wait.
	setRefuse(errors.New("fake: kill refused"))
	if err := e.m.Preempt("other"); err == nil || errors.Is(err, ErrKillPending) {
		t.Fatalf("other kill failure: %v", err)
	}
	wantWedged("after another failure", "exp")
	// A kill that works.
	setRefuse(nil)
	must(t, e.m.Preempt("exp"))
	waitState(t, e, "exp", Preempted)
	wantWedged("after a kill that works")
	// Wedged again, then destroyed once a kill works: never listed after.
	setRefuse(pending)
	refuse("other", wedgedAfter)
	wantWedged("other wedged", "other")
	if err := e.m.Destroy(bg, "other"); !errors.Is(err, ErrWedged) {
		t.Fatalf("destroy of a wedged machine: %v, want ErrWedged", err)
	}
	wantWedged("destroy refused", "other")
	setRefuse(nil)
	must(t, e.m.Destroy(bg, "other"))
	wantWedged("destroyed")
}
