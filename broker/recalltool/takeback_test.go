package recalltool

// REQ: CAP-3

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/recall"
)

// W3-forget-b2b: the owner's forget of a task takes the agent machine's
// work since the task back on the ask-first rule (Mark, 2026-10-05). Work
// is the rule's measure; TakeBack is the same reset a recall rollback
// runs, and tells the owner nothing (the forget's own texts do).
func TestCAP3ForgetTakesTheAgentBackOnTheAskFirstRule(t *testing.T) {
	x, read := newReachRig(t)
	if worked, ok := x.reach.Work("root", read); !ok || worked {
		t.Fatalf("no work since: worked %v ok %v", worked, ok)
	}
	x.vm.plan.Changes = 2
	if worked, _ := x.reach.Work("root", read); !worked {
		t.Fatal("files changed since are work")
	}
	x.vm.plan.Changes, x.vm.planErr = 0, errors.New("unmeasured")
	if worked, _ := x.reach.Work("root", read); !worked {
		t.Fatal("an unmeasured plan must count as work")
	}
	x.vm.planErr = nil
	x.j.submitted["late"] = read.Add(time.Second)
	if worked, _ := x.reach.Work("root", read); !worked {
		t.Fatal("an action since is work")
	}
	if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil {
		t.Fatal(err)
	}
	if len(x.vm.calls) != 1 || x.vm.calls[0] != "root" || !x.vm.since[0].Equal(read) {
		t.Fatalf("reset %v %v", x.vm.calls, x.vm.since)
	}
	if !x.j.erased["late"] || x.j.erased["early"] || !x.cs.forgot["late"] || len(x.told) != 0 {
		t.Fatalf("erased %v forgot %v told %v", x.j.erased, x.cs.forgot, x.told)
	}
	if len(x.r.prov.Resets("root")) != 0 || len(x.r.prov.Of("bystander")) == 0 {
		t.Fatal("reset left open, or another lineage touched")
	}
	// Again (a retry): done once, it is not repeated (vm.ForgetSince: a
	// repeat rolls back later work too).
	if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil || len(x.vm.calls) != 1 {
		t.Fatalf("second take-back: %v %v", err, x.vm.calls)
	}
	if _, ok := (&Reach{Prov: x.r.prov}).Work("root", read); ok {
		t.Fatal("without machines nothing can be taken back")
	}
}

// A take-back interrupted after the machines went back is finished by
// Retry, though the lineage holds no deleted record that would revisit it.
func TestCAP3RetryFinishesAnInterruptedTakeBack(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	if err := x.r.prov.MarkReset("root", Reset{Since: read, At: x.clock, Until: x.clock}); err != nil {
		t.Fatal(err)
	}
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !x.j.erased["late"] || len(x.r.prov.Resets("root")) != 0 || len(x.vm.calls) != 0 {
		t.Fatalf("erased %v resets %v machines %v", x.j.erased, x.r.prov.Resets("root"), x.vm.calls)
	}
}

// #327 L3 blocker 1: a take-back whose machines went back but whose reach
// did not finish (an intent still in flight) is not repeated, by a retry
// or after a restart: Retry finishes it, and the machines go back once.
func TestCAP3ATakeBackIsNeverRepeatedOnceItsResetIsRecorded(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.j.inFlight["late"] = true
	if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil {
		t.Fatalf("machines back, reach left to Retry: %v", err)
	}
	if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil || len(x.vm.calls) != 1 {
		t.Fatalf("retried: %v, machines %v", err, x.vm.calls)
	}
	if !x.reach.Owed() {
		t.Fatal("an unfinished reach must keep Retry running")
	}
	x.j.inFlight["late"] = false
	if err := x.reach.Retry(context.Background()); err != nil || !x.j.erased["late"] || len(x.vm.calls) != 1 {
		t.Fatalf("Retry: %v erased %v machines %v", err, x.j.erased, x.vm.calls)
	}
	again, err := OpenProvenance(x.r.prst)
	if err != nil {
		t.Fatal(err)
	}
	x.reach.Prov = again
	if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil || len(x.vm.calls) != 1 || x.reach.Owed() {
		t.Fatalf("after a restart: %v, machines %v", err, x.vm.calls)
	}
}

// #327 L3 blocker 2: an approved take-back that fails is recorded first,
// so recall's Retry carries it through, across a restart too, and tells
// the owner when it is done. One not approved (no work to lose, so no
// ask) is tried once and never later, when the agent may have worked.
func TestCAP3AnApprovedTakeBackIsCarriedThroughByRetry(t *testing.T) {
	x, read := newReachRig(t)
	x.vm.fail = errors.New("machine busy")
	if err := x.reach.TakeBack(context.Background(), "root", read, false); err == nil || errors.Is(err, ErrCarried) {
		t.Fatalf("a failed take-back not approved: %v", err)
	}
	if x.reach.Owed() {
		t.Fatal("a take-back not approved must not be carried later")
	}
	if err := x.reach.TakeBack(context.Background(), "root", read, true); !errors.Is(err, ErrCarried) {
		t.Fatalf("an approved take-back not carried: %v", err)
	}
	again, err := OpenProvenance(x.r.prst)
	if err != nil {
		t.Fatal(err)
	}
	x.reach.Prov = again
	if !x.reach.Owed() {
		t.Fatal("an approved take-back lost by a restart")
	}
	x.vm.fail = nil
	if err := x.reach.Retry(context.Background()); err != nil || len(x.vm.calls) != 1 {
		t.Fatalf("Retry: %v machines %v", err, x.vm.calls)
	}
	if len(x.told) != 1 || x.told[0] != TakenBack || x.reach.Owed() {
		t.Fatalf("told %v owed %v", x.told, x.reach.Owed())
	}
	if err := x.reach.Retry(context.Background()); err != nil || len(x.vm.calls) != 1 || len(x.told) != 1 {
		t.Fatalf("Retry again: %v machines %v told %v", err, x.vm.calls, x.told)
	}
}

// Before recall opens a take-back records nothing and says so; what waits
// on the open runs once it does (FORGET's interrupted item 2s).
func TestCAP3LateTakeBackWaitsForRecallToOpen(t *testing.T) {
	x, read := newReachRig(t)
	var l LateExecutor
	if err := l.TakeBack(context.Background(), "root", read, true); !errors.Is(err, ErrNotOpen) || errors.Is(err, ErrCarried) {
		t.Fatalf("before open: %v", err)
	}
	ran := 0
	l.OnOpen(func() { ran++ })
	if ran != 0 {
		t.Fatal("ran before open")
	}
	l.Set(x.reach)
	l.OnOpen(func() { ran++ })
	if ran != 2 || x.reach.Owed() {
		t.Fatalf("ran %d, owed %v", ran, x.reach.Owed())
	}
	if err := l.TakeBack(context.Background(), "root", read, true); err != nil || len(x.vm.calls) != 1 {
		t.Fatalf("after open: %v %v", err, x.vm.calls)
	}
}

// failAfter accepts n appends, then fails every one (a full disk).
type failAfter struct {
	*recall.MemStore
	n int
}

func (s *failAfter) Append(line []byte) error {
	if s.n <= 0 {
		return errors.New("disk full")
	}
	s.n--
	return s.MemStore.Append(line)
}

// #327 L3 re-review blocker: with provenance writes failing after the owed
// mark, a take-back whose machines went back is still never repeated, and
// the owner is not told it again and again.
func TestCAP3ATakeBackIsNotRepeatedWhenItsMarksCannotBeWritten(t *testing.T) {
	x, read := newReachRig(t)
	x.r.prov.store = &failAfter{MemStore: x.r.prst, n: 1}
	if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil || len(x.vm.calls) != 1 {
		t.Fatalf("take-back: %v machines %v", err, x.vm.calls)
	}
	for i := 0; i < 3; i++ {
		if err := x.reach.Retry(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(x.vm.calls) != 1 || len(x.told) > 1 || x.reach.Owed() {
		t.Fatalf("repeated: machines %v told %v owed %v", x.vm.calls, x.told, x.reach.Owed())
	}
	if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil || len(x.vm.calls) != 1 {
		t.Fatalf("again: %v machines %v", err, x.vm.calls)
	}
}

// #327 UX lens B1: Actions is the work so far that item 2 names, the
// count a recall rollback's line uses; one not known says so (#327 L3
// B-1), never 0.
func TestCAP3ActionsCountsTheWorkSoFar(t *testing.T) {
	x, read := newReachRig(t)
	if n, ok := x.reach.Actions("root", read); n != 0 || !ok {
		t.Fatalf("no actions since: %d %v", n, ok)
	}
	x.j.submitted["late"] = read.Add(time.Second)
	x.j.submitted["later"] = read.Add(2 * time.Second)
	if n, ok := x.reach.Actions("root", read); n != 2 || !ok {
		t.Fatalf("actions since: %d %v", n, ok)
	}
	if _, ok := (&Reach{}).Actions("root", read); ok {
		t.Fatal("no journal: count claimed known")
	}
	if _, ok := (&LateExecutor{}).Actions("root", read); ok {
		t.Fatal("recall not open: count claimed known")
	}
}

// An approved take-back from a task's time is handled once it is
// recorded, owed or done, on any lineage, across a restart: FORGET's item
// 2 that the journal holds as approved runs again only while it is not
// (#327 L3 re-review 2). Before recall opens, it is not known.
func TestCAP3HandledSeesARecordedTakeBack(t *testing.T) {
	x, read := newReachRig(t)
	var l LateExecutor
	if _, ok := l.Handled(read); ok {
		t.Fatal("known before open")
	}
	l.Set(x.reach)
	if handled, ok := l.Handled(read); !ok || handled {
		t.Fatalf("before the take-back: %v %v", handled, ok)
	}
	x.vm.fail = errors.New("machine busy")
	if err := l.TakeBack(context.Background(), "root", read, true); !errors.Is(err, ErrCarried) {
		t.Fatalf("take-back: %v", err)
	}
	again, err := OpenProvenance(x.r.prst)
	if err != nil {
		t.Fatal(err)
	}
	x.reach.Prov = again
	if handled, ok := l.Handled(read); !ok || !handled {
		t.Fatalf("owed, after a restart: %v %v", handled, ok)
	}
	if handled, _ := l.Handled(read.Add(time.Nanosecond)); handled {
		t.Fatal("another task's time reads as handled")
	}
	x.vm.fail = nil
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if handled, ok := l.Handled(read); !ok || !handled {
		t.Fatalf("done: %v %v", handled, ok)
	}
}

// actingMachines is fakeMachines with an agent that acts on its own
// goroutine, as a guest does: it takes no lock of Reach's. act runs the
// agent once, after the first plan is read, and waits for it, so the work
// lands between the caller's Work and its TakeBack.
type actingMachines struct {
	*fakeMachines
	mu      sync.Mutex
	changes int
	act     func()
}

func (m *actingMachines) Plan(lineage string, since time.Time) (Plan, error) {
	m.mu.Lock()
	p, act := m.fakeMachines.plan, m.act
	p.Changes += m.changes
	m.act = nil
	m.mu.Unlock()
	if act != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			act()
		}()
		defer func() { <-done }()
	}
	return p, nil
}

// W3-forget-b2b f1 (Security 327-1): a take-back not approved re-checks
// the work under the lock that serializes it, so work done between the
// caller's check and the take-back is never rolled back unasked (CAP-3).
func TestCAP3ATakeBackNotApprovedRechecksTheWork(t *testing.T) {
	x, read := newReachRig(t)
	if worked, ok := x.reach.Work("root", read); !ok || worked {
		t.Fatalf("no work yet: %v %v", worked, ok)
	}
	x.j.submitted["late"] = read.Add(time.Second) // the agent acts
	err := x.reach.TakeBack(context.Background(), "root", read, false)
	if !errors.Is(err, ErrWorked) || len(x.vm.calls) != 0 || x.j.erased["late"] {
		t.Fatalf("work since the check: %v, machines %v erased %v", err, x.vm.calls, x.j.erased)
	}
	if x.reach.Owed() || len(x.r.prov.Resets("root")) != 0 {
		t.Fatal("a refused take-back left something owed")
	}
	// Approved, the owner settled the work: it goes ahead.
	if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil || len(x.vm.calls) != 1 {
		t.Fatalf("approved: %v machines %v", err, x.vm.calls)
	}
}

// The same race with the agent on its own goroutine, run under -race: the
// files it changes after the caller's check stop the take-back.
func TestCAP3ATakeBackNotApprovedLosesNoConcurrentWork(t *testing.T) {
	x, read := newReachRig(t)
	m := &actingMachines{fakeMachines: x.vm}
	m.act = func() {
		m.mu.Lock()
		m.changes++
		m.mu.Unlock()
	}
	x.reach.Machines = m
	if worked, ok := x.reach.Work("root", read); !ok || worked {
		t.Fatalf("the check ran before the agent acted: %v %v", worked, ok)
	}
	if err := x.reach.TakeBack(context.Background(), "root", read, false); !errors.Is(err, ErrWorked) || len(x.vm.calls) != 0 {
		t.Fatalf("concurrent work: %v machines %v", err, x.vm.calls)
	}
}

// W3-forget-b2b e (#327 L3 r5 #3): an approved take-back that finds an
// unfinished reset from the same time does not repeat it, and is marked,
// so once Retry has finished the reset a later boot still sees it handled
// and takes nothing back again.
func TestCAP3AnApprovedTakeBackOnAnUnfinishedResetIsMarked(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	if err := x.r.prov.MarkReset("root", Reset{Since: read, At: x.clock, Until: x.clock}); err != nil {
		t.Fatal(err)
	}
	if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil || len(x.vm.calls) != 0 {
		t.Fatalf("take-back on the reset: %v machines %v", err, x.vm.calls)
	}
	if err := x.reach.Retry(context.Background()); err != nil || len(x.r.prov.Resets("root")) != 0 {
		t.Fatalf("Retry: %v resets %v", err, x.r.prov.Resets("root"))
	}
	again, err := OpenProvenance(x.r.prst)
	if err != nil {
		t.Fatal(err)
	}
	x.reach.Prov = again
	if handled, ok := x.reach.Handled(read); !ok || !handled {
		t.Fatalf("after a restart: handled %v %v", handled, ok)
	}
	if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil || len(x.vm.calls) != 0 || x.reach.Owed() {
		t.Fatalf("again after a restart: %v machines %v owed %v", err, x.vm.calls, x.reach.Owed())
	}
}
