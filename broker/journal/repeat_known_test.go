package journal

import (
	"context"
	"sync"
	"testing"
	"time"
)

// REQ: OP-2, OP-6

// B11 (Security on #1433): Use.Known is when a success became known. A
// check that proves an unknown attempt went 30 hours after its dispatch
// makes Known the proof's time while Went stays the dispatch's, and
// InUse lists the success while the proof is in the window although its
// dispatch is not.
func TestUseKnownIsWhenTheSuccessWasProved(t *testing.T) {
	r := newModelRun(t)
	e, x := r.e, r.x
	in := intent("a", "mail")
	must(e.Submit(in))
	must(e.Authorize(ctx, "a"))
	x.next = mDropAck
	must(e.Dispatch(ctx, "a"))
	sent := e.intents["a"].attempts[0].Dispatched
	proved := mNow.Add(30 * time.Hour)
	e.now = func() time.Time { return proved }
	must(e.Resolve("a", 1, Outcome{Result: ResultSucceeded, Evidence: "found"}, "check"))
	us := e.InUse(in.Account, in.Action, proved.Add(-24*time.Hour))
	if len(us) != 1 || !us[0].Went.Equal(sent) || !us[0].Known.Equal(proved) {
		t.Fatalf("in use %+v, want a went at %v, known at %v", us, sent, proved)
	}
	if us := e.InUse(in.Account, in.Action, proved.Add(time.Second)); len(us) != 0 {
		t.Fatalf("in use after the window %+v", us)
	}
}

// P14 (Potency on #1433), wentAt's first branch: a same-key retry of the
// latest attempt that then succeeds went when it was re-dispatched, not
// at the attempt's first dispatch.
func TestUseWentIsTheSameKeyRetrysDispatch(t *testing.T) {
	r := newModelRun(t)
	e, x := r.e, r.x
	in := intent("a", "mail")
	must(e.Submit(in))
	must(e.Authorize(ctx, "a"))
	x.next = mTimeout
	must(e.Dispatch(ctx, "a"))
	again := mNow.Add(2 * time.Hour)
	e.now = func() time.Time { return again }
	e.mu.Lock()
	err := e.commit(Record{Type: RecDispatched, ID: "a", Attempt: 1, Source: DispatchKey})
	if err == nil {
		err = e.commit(Record{Type: RecObserved, ID: "a", Attempt: 1, Result: ResultSucceeded, Source: "executor", Evidence: "receipt"})
	}
	e.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	us := e.InUse(in.Account, in.Action, time.Time{})
	if len(us) != 1 || !us[0].Went.Equal(again) || us[0].Went.Equal(e.intents["a"].attempts[0].Dispatched) {
		t.Fatalf("in use %+v, want a went at %v", us, again)
	}
}

// P14 (Potency on #1433), wentAt's second branch: an earlier attempt
// proved succeeded after a later one was dispatched went at its own
// dispatch, not the later attempt's.
func TestUseWentIsTheEarlierAttemptsDispatch(t *testing.T) {
	r := newModelRun(t)
	e, x := r.e, r.x
	in := intent("a", "mail")
	must(e.Submit(in))
	must(e.Authorize(ctx, "a"))
	x.next = mDropAck
	must(e.Dispatch(ctx, "a"))
	first := e.intents["a"].attempts[0].Dispatched
	if !e.park("a", 1, true) {
		t.Fatal("park")
	}
	e.now = func() time.Time { return mNow.Add(3 * time.Hour) }
	x.next = mTimeout
	must(e.Retry(ctx, "a", 1))
	e.now = func() time.Time { return mNow.Add(5 * time.Hour) }
	must(e.Resolve("a", 1, Outcome{Result: ResultSucceeded, Evidence: "found"}, "check"))
	us := e.InUse(in.Account, in.Action, time.Time{})
	if len(us) != 1 || !us[0].Went.Equal(first) || !us[0].Known.Equal(mNow.Add(5*time.Hour)) {
		t.Fatalf("in use %+v, want a went at %v", us, first)
	}
}

// R22 (Security on #1433): attempt 1 is unknown and parked, and the
// owner's retry (attempt 2) succeeds, so the intent has succeeded and
// left the open set. Attempt 1 may still take effect, so STOP cancels it
// and reports the intent, after a restart too.
func TestStopCancelsAnEarlierUnknownAttemptOfASucceededIntent(t *testing.T) {
	st := &MemStore{}
	x := &cancelExec{mExec: &mExec{applied: map[string]bool{}}}
	open := func() *Engine {
		e, err := Open(st, &mPolicy{deny: map[string]bool{}}, map[string]Executor{"svc": x}, testRedact,
			WithClock(func() time.Time { return mNow }))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := open()
	must(e.Submit(intent("a", "mail")))
	must(e.Authorize(ctx, "a"))
	x.next = mTimeout
	must(e.Dispatch(ctx, "a"))
	if !e.park("a", 1, true) {
		t.Fatal("park 1")
	}
	x.next = mOK
	if s := must(e.Retry(ctx, "a", 1)); s.State != Succeeded || s.Attempts[0].Result != ResultUnknown {
		t.Fatalf("a: %+v", s)
	}
	for i, e := range []*Engine{e, open()} {
		x.cancelled = nil
		rep, err := e.Stop(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Unresolved) != 1 || rep.Unresolved[0] != "a" || len(rep.Cancels) != 1 || rep.Cancels[0].Attempt != 1 ||
			len(x.cancelled) != 1 || x.cancelled[0] != 1 {
			t.Fatalf("run %d: stop %+v, cancelled %v; want attempt 1 cancelled", i, rep, x.cancelled)
		}
		if err := e.Resume(); err != nil {
			t.Fatal(err)
		}
	}
}

// blockExec holds every Execute until release is closed, and records
// cancellations.
type blockExec struct {
	release chan struct{}
	started chan struct{}
	mu      sync.Mutex
	cancels []int
}

func (b *blockExec) Execute(context.Context, Intent, int) Outcome {
	close(b.started)
	<-b.release
	return Outcome{Result: ResultSucceeded, Evidence: "receipt"}
}

func (b *blockExec) Reconcile(context.Context, Intent, int) Outcome {
	return Outcome{Result: ResultUnknown}
}

func (b *blockExec) Cancel(_ context.Context, _ Intent, n int) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cancels = append(b.cancels, n)
	return false, "too late"
}

// P13 (Potency on #1433): STOP while an executor call is still running
// cancels that in-flight attempt and reports it (OP-6, Security R18).
func TestStopCancelsAnAttemptStillInFlight(t *testing.T) {
	x := &blockExec{release: make(chan struct{}), started: make(chan struct{})}
	e, err := Open(&MemStore{}, &mPolicy{deny: map[string]bool{}}, map[string]Executor{"svc": x}, testRedact,
		WithClock(func() time.Time { return mNow }))
	if err != nil {
		t.Fatal(err)
	}
	must(e.Submit(intent("a", "mail")))
	must(e.Authorize(ctx, "a"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = e.Dispatch(ctx, "a")
	}()
	<-x.started
	if st := must(e.Get("a")); st.State != InFlight || st.Attempts[0].Result != ResultInFlight {
		t.Fatalf("a: %+v", st)
	}
	rep, err := e.Stop(ctx)
	close(x.release)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(rep.Unresolved) != 1 || rep.Unresolved[0] != "a" || len(rep.Cancels) != 1 || rep.Cancels[0].Attempt != 1 ||
		len(x.cancels) != 1 || x.cancels[0] != 1 {
		t.Fatalf("stop %+v, cancels %v; want attempt 1 cancelled", rep, x.cancels)
	}
}
