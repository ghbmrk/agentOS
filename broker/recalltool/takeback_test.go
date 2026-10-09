package recalltool

// REQ: CAP-3

import (
	"context"
	"errors"
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
// the owner is not told it again and again. Since RCH-2 its unrecorded
// reset stays owed, and Retry says so, rather than being dropped; it is
// not told done while it is (RCH-1).
func TestCAP3ATakeBackIsNotRepeatedWhenItsMarksCannotBeWritten(t *testing.T) {
	x, read := newReachRig(t)
	x.r.prov.store = &failAfter{MemStore: x.r.prst, n: 1}
	if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil || len(x.vm.calls) != 1 {
		t.Fatalf("take-back: %v machines %v", err, x.vm.calls)
	}
	for i := 0; i < 3; i++ {
		if err := x.reach.Retry(context.Background()); !errors.Is(err, errUnrecorded) {
			t.Fatalf("retry %d: %v", i, err)
		}
	}
	if st, _ := x.reach.TakeBackOf(read); len(x.vm.calls) != 1 || len(x.told) != 0 || !x.reach.Owed() || st != TakeBackOwed {
		t.Fatalf("repeated: machines %v told %v owed %v state %v", x.vm.calls, x.told, x.reach.Owed(), st)
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

// failOnly fails the appends whose 1-based numbers are in fail (a write
// lost to a transient error), and accepts the rest.
type failOnly struct {
	*recall.MemStore
	n    int
	fail map[int]bool
}

func (s *failOnly) Append(line []byte) error {
	s.n++
	if s.fail[s.n] {
		return errors.New("write failed")
	}
	return s.MemStore.Append(line)
}

// W3-forget-reach RCH-1 (brief IDs; CAP-3 is marked at the top).
// A take-back's state from its time, on any lineage: not recorded, owed
// (recorded, or the machines back with the reset's reach unfinished), done
// (machines back, reset recorded and finished), and not known before
// recall opens (as Handled). Security 4a on #541, P2: an unfinished reset
// is owed, not done.
func TestRCH1TakeBackStateIsDoneOnlyOnceItsReachIsFinished(t *testing.T) {
	x, read := newReachRig(t)
	var l LateExecutor
	if _, ok := l.TakeBackOf(read); ok {
		t.Fatal("known before recall opens")
	}
	l.Set(x.reach)
	if st, ok := l.TakeBackOf(read); !ok || st != TakeBackNone {
		t.Fatalf("before the take-back: %v %v", st, ok)
	}
	// Recorded, machines busy: owed, across a restart.
	x.vm.fail = errors.New("machine busy")
	if err := l.TakeBack(context.Background(), "root", read, true); !errors.Is(err, ErrCarried) {
		t.Fatalf("take-back: %v", err)
	}
	again, err := OpenProvenance(x.r.prst)
	if err != nil {
		t.Fatal(err)
	}
	x.reach.Prov = again
	if st, _ := l.TakeBackOf(read); st != TakeBackOwed {
		t.Fatalf("recorded: %v", st)
	}
	// Machines back, reach unfinished (an intent in flight): owed.
	x.vm.fail = nil
	x.j.submitted["late"] = read.Add(time.Second)
	x.j.inFlight["late"] = true
	if err := x.reach.Retry(context.Background()); err == nil {
		t.Fatal("an intent in flight must keep the reach unfinished")
	}
	if len(x.vm.calls) != 1 {
		t.Fatalf("machines %v", x.vm.calls)
	}
	if st, _ := l.TakeBackOf(read); st != TakeBackOwed {
		t.Fatalf("an unfinished reset reads %v, not owed", st)
	}
	if st, _ := l.TakeBackOf(read.Add(time.Nanosecond)); st != TakeBackNone {
		t.Fatalf("another task's time: %v", st)
	}
	x.j.inFlight["late"] = false
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, _ := l.TakeBackOf(read); st != TakeBackDone {
		t.Fatalf("finished: %v", st)
	}
	again, err = OpenProvenance(x.r.prst)
	if err != nil {
		t.Fatal(err)
	}
	x.reach.Prov = again
	if st, _ := l.TakeBackOf(read); st != TakeBackDone {
		t.Fatalf("finished, after a restart: %v", st)
	}
}

// W3-forget-reach RCH-1 (brief IDs; CAP-3 is marked at the top).
// A take-back not approved (no work to lose) is done only once its reach
// is: its state is what agentBackWithoutAsking's done text reads (RCH-5).
func TestRCH1AnUnaskedTakeBackIsDoneOnlyOnceFinished(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.j.inFlight["late"] = true
	if err := x.reach.TakeBack(context.Background(), "root", read, false); err != nil {
		t.Fatal(err)
	}
	if st, _ := x.reach.TakeBackOf(read); st != TakeBackOwed {
		t.Fatalf("unfinished: %v", st)
	}
	x.j.inFlight["late"] = false
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, _ := x.reach.TakeBackOf(read); st != TakeBackDone {
		t.Fatalf("finished: %v", st)
	}
	y, read2 := newReachRig(t)
	if err := y.reach.TakeBack(context.Background(), "root", read2, false); err != nil {
		t.Fatal(err)
	}
	if st, _ := y.reach.TakeBackOf(read2); st != TakeBackDone {
		t.Fatalf("finished at once: %v", st)
	}
}

// W3-forget-reach RCH-1, RCH-2 (brief IDs; CAP-3 is marked at the top).
// Machines back but the reset not recorded (errUnrecorded): owed, not
// done; a later Retry records the reset and finishes its reach without
// resetting the machines again (#327 L3 1), in this run or after a
// restart once the back mark is on disk.
func TestRCH2AnUnrecordedResetIsCarriedToDoneWithoutARepeat(t *testing.T) {
	for _, restart := range []bool{false, true} {
		x, read := newReachRig(t)
		x.j.submitted["late"] = read.Add(time.Second)
		// Appends: 1 the owed mark, 2 the reset (fails), 3 the back mark.
		st := &failOnly{MemStore: x.r.prst, fail: map[int]bool{2: true}}
		x.r.prov.store = st
		if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil {
			t.Fatalf("restart %v: machines back: %v", restart, err)
		}
		if s, _ := x.reach.TakeBackOf(read); s != TakeBackOwed || !x.reach.Owed() {
			t.Fatalf("restart %v: unrecorded reset reads %v, owed %v", restart, s, x.reach.Owed())
		}
		if x.j.erased["late"] {
			t.Fatal("reach finished without a recorded reset")
		}
		if restart {
			again, err := OpenProvenance(x.r.prst)
			if err != nil {
				t.Fatal(err)
			}
			again.store = st
			x.reach.Prov = again
			if s, _ := x.reach.TakeBackOf(read); s != TakeBackOwed {
				t.Fatalf("after a restart: %v", s)
			}
		}
		if err := x.reach.Retry(context.Background()); err != nil {
			t.Fatalf("restart %v: Retry: %v", restart, err)
		}
		if len(x.vm.calls) != 1 || !x.j.erased["late"] || x.reach.Owed() {
			t.Fatalf("restart %v: machines %v erased %v owed %v", restart, x.vm.calls, x.j.erased, x.reach.Owed())
		}
		if s, _ := x.reach.TakeBackOf(read); s != TakeBackDone {
			t.Fatalf("restart %v: recorded and finished: %v", restart, s)
		}
		if len(x.told) != 1 || x.told[0] != TakenBack {
			t.Fatalf("restart %v: told %v", restart, x.told)
		}
		again, err := OpenProvenance(x.r.prst)
		if err != nil {
			t.Fatal(err)
		}
		x.reach.Prov = again
		if s, _ := x.reach.TakeBackOf(read); s != TakeBackDone {
			t.Fatalf("restart %v: done lost by a restart: %v", restart, s)
		}
		if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil || len(x.vm.calls) != 1 {
			t.Fatalf("restart %v: again: %v machines %v", restart, err, x.vm.calls)
		}
	}
}

// W3-forget-reach RCH-3 (brief IDs; CAP-3 is marked at the top).
// The caller can own the done text: with OnTakenBack set, Retry reports a
// take-back it finished to it and tells the owner nothing; unset, it
// tells TakenBack. Either way one per take-back, across TakeBack (which
// tells nothing) and every Retry, and none for one TakeBack finished.
func TestRCH3RetryReportsAFinishedTakeBackToTheCallerOnce(t *testing.T) {
	for _, hook := range []bool{false, true} {
		x, read := newReachRig(t)
		type rep struct {
			lineage string
			since   time.Time
		}
		var reps []rep
		if hook {
			x.reach.OnTakenBack = func(l string, s time.Time) {
				if st, _ := x.reach.TakeBackOf(s); st != TakeBackDone {
					t.Errorf("reported before done: %v", st)
				}
				reps = append(reps, rep{l, s})
			}
		}
		x.j.submitted["late"] = read.Add(time.Second)
		x.j.inFlight["late"] = true
		if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil {
			t.Fatal(err)
		}
		_ = x.reach.Retry(context.Background()) // still in flight
		x.j.inFlight["late"] = false
		for i := 0; i < 2; i++ {
			if err := x.reach.Retry(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		texts := len(x.told)
		if hook {
			if texts != 0 || len(reps) != 1 || reps[0].lineage != "root" || !reps[0].since.Equal(read) {
				t.Fatalf("hook: told %v reported %v", x.told, reps)
			}
		} else if texts != 1 || x.told[0] != TakenBack {
			t.Fatalf("no hook: told %v", x.told)
		}
		// Finished by TakeBack itself: Retry reports nothing.
		later := read.Add(time.Minute)
		if err := x.reach.TakeBack(context.Background(), "root", later, true); err != nil {
			t.Fatal(err)
		}
		if st, _ := x.reach.TakeBackOf(later); st != TakeBackDone {
			t.Fatalf("finished by TakeBack: %v", st)
		}
		if err := x.reach.Retry(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(x.told) != texts || hook && len(reps) != 1 {
			t.Fatalf("hook %v: a take-back TakeBack finished was reported: told %v reported %v", hook, x.told, reps)
		}
	}
}

// W3-forget-reach RCH-3 and RCH-4 (brief IDs; CAP-3 is marked at the top).
// #569 B1 (L3, Security 4a, Lens): a take-back left owed whose reset a
// deletion's reach finishes, at once or later from Retry's pending
// deletions, is still reported once, and Retry stays owed until it is.
func TestRCH3ATakeBackADeletionFinishesIsReportedOnce(t *testing.T) {
	for _, pending := range []bool{false, true} {
		for _, hook := range []bool{false, true} {
			x, read := newReachRig(t)
			var reps []time.Time
			if hook {
				x.reach.OnTakenBack = func(_ string, s time.Time) { reps = append(reps, s) }
			}
			x.j.submitted["late"] = read.Add(time.Second)
			x.j.inFlight["late"] = true
			if err := x.reach.TakeBack(context.Background(), "root", read, true); err != nil {
				t.Fatal(err)
			}
			if st, _ := x.reach.TakeBackOf(read); st != TakeBackOwed {
				t.Fatalf("in flight: %v", st)
			}
			var early string
			for _, id := range x.r.prov.Of("root") {
				if x.r.prov.Holders(id)["root"].Before(read) {
					early = id
				}
			}
			if early == "" {
				t.Fatal("no item given before the read")
			}
			if !pending {
				x.j.inFlight["late"] = false
			}
			x.clock = x.clock.Add(time.Minute)
			if _, err := x.r.ix.Delete(early); (err != nil) != pending || !x.r.ix.Deleted(early) {
				t.Fatalf("pending %v: delete: %v", pending, err)
			}
			x.j.inFlight["late"] = false
			if !pending {
				if st, _ := x.reach.TakeBackOf(read); st != TakeBackDone {
					t.Fatalf("deletion did not finish the take-back: %v", st)
				}
			}
			if !x.reach.Owed() {
				t.Fatalf("pending %v hook %v: report not owed, so Service would not run Retry", pending, hook)
			}
			for i := 0; i < 3; i++ {
				_ = x.reach.Retry(context.Background())
			}
			if st, _ := x.reach.TakeBackOf(read); st != TakeBackDone {
				t.Fatalf("not done: %v", st)
			}
			n := 0
			for _, s := range x.told {
				if s == TakenBack {
					n++
				}
			}
			if hook && (len(reps) != 1 || !reps[0].Equal(read) || n != 0) || !hook && n != 1 {
				t.Fatalf("pending %v hook %v: reported %v told %v", pending, hook, reps, x.told)
			}
			if x.reach.Owed() {
				t.Fatalf("pending %v hook %v: still owed once reported", pending, hook)
			}
		}
	}
}

// W3-forget-reach RCH-2 (brief IDs; CAP-3 is marked at the top).
// An unrecorded reset kept by MarkBack survives a compaction and a
// reopen, so Retry still finishes it.
func TestRCH2AnUnrecordedResetSurvivesACompaction(t *testing.T) {
	st := &recall.MemStore{}
	p, err := OpenProvenance(st)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	rs := Reset{Since: t0, At: t0.Add(2 * time.Minute), Until: t0.Add(150 * time.Second)}
	if err := p.MarkBack("l", rs); err != nil {
		t.Fatal(err)
	}
	if err := p.compact(); err != nil {
		t.Fatal(err)
	}
	p2, err := OpenProvenance(st)
	if err != nil {
		t.Fatal(err)
	}
	bs := p2.Backs()
	if len(bs) != 1 || bs[0].Lineage != "l" || !bs[0].Since.Equal(t0) || !bs[0].At.Equal(rs.At) || !bs[0].Until.Equal(rs.Until) {
		t.Fatalf("backs after reopen: %+v", bs)
	}
	if s := p2.TakeBackOf(t0); s != TakeBackOwed {
		t.Fatalf("state after reopen: %v", s)
	}
}
