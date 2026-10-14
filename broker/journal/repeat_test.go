package journal

import (
	"context"
	"testing"
	"time"
)

// REQ: OP-2

// newModelRun is an empty engine on the model's service and policy.
func newModelRun(t *testing.T) *mRun {
	t.Helper()
	return restore(t, &mState{fence: map[string][]string{}, applied: map[string]bool{}}, true)
}

// Confirm repeats (D-116) reads when a send went from InUse: Went is the
// dispatch of the attempt that went, and an intent that has not gone has
// none.
func TestUseWentIsWhenTheAttemptThatWentWasSent(t *testing.T) {
	r := newModelRun(t)
	e, x := r.e, r.x
	sent := mNow.Add(-3 * time.Hour)
	e.now = func() time.Time { return sent }
	in := intent("a", "mail")
	must(e.Submit(in))
	must(e.Authorize(ctx, "a"))
	x.next = mOK
	must(e.Dispatch(ctx, "a"))
	e.now = func() time.Time { return mNow }
	b := in
	b.ID = "b"
	must(e.Submit(b))
	must(e.Authorize(ctx, "b"))
	us := e.InUse(in.Account, in.Action, mNow.Add(-24*time.Hour))
	if len(us) != 2 || !us[0].Went.Equal(sent) || !us[0].Tried.IsZero() || !us[1].Went.IsZero() || us[1].Started {
		t.Fatalf("in use %+v, want a went at %v and b waiting", us, sent)
	}
}

// R19: an unclear intent (its parked first try may have gone, the owner's
// retry was refused) is marked with the parked try's time, not the
// refused retry's.
func TestUnclearUseIsMarkedWithTheParkedTrysTime(t *testing.T) {
	r := newModelRun(t)
	e, x := r.e, r.x
	in := intent("a", "mail")
	must(e.Submit(in))
	must(e.Authorize(ctx, "a"))
	x.next = mDropAck
	must(e.Dispatch(ctx, "a"))
	if !e.park("a", 1, true) {
		t.Fatal("park")
	}
	first := e.intents["a"].attempts[0].Dispatched
	e.now = func() time.Time { return mNow.Add(5 * time.Hour) }
	x.next = mRefuse
	must(e.Retry(ctx, "a", 1))
	if st, _ := e.Get("a"); st.State != OutcomeUnknown || st.Unclear() != 1 {
		t.Fatalf("a: %+v", st)
	}
	us := e.InUse(in.Account, in.Action, time.Time{})
	if len(us) != 1 || !us[0].Tried.Equal(first) || !us[0].Went.IsZero() || !us[0].Started {
		t.Fatalf("in use %+v, want tried at %v", us, first)
	}
}

// R18: when an intent has several attempts that may still take effect
// (two parked unknown tries, then a refused third), STOP cancels each of
// them, not only the first.
func TestStopCancelsEveryAttemptThatMayStillTakeEffect(t *testing.T) {
	x := &cancelExec{mExec: &mExec{applied: map[string]bool{}}}
	e, err := Open(&MemStore{}, &mPolicy{deny: map[string]bool{}}, map[string]Executor{"svc": x}, testRedact,
		WithClock(func() time.Time { return mNow }))
	if err != nil {
		t.Fatal(err)
	}
	in := intent("a", "mail")
	must(e.Submit(in))
	must(e.Authorize(ctx, "a"))
	x.next = mTimeout
	must(e.Dispatch(ctx, "a"))
	if !e.park("a", 1, true) {
		t.Fatal("park 1")
	}
	x.next = mDropAck
	must(e.Retry(ctx, "a", 1))
	if !e.park("a", 2, true) {
		t.Fatal("park 2")
	}
	x.next = mRefuse
	must(e.Retry(ctx, "a", 2))
	rep, err := e.Stop(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Unresolved) != 1 || len(rep.Cancels) != 2 || rep.Cancels[0].Attempt != 1 || rep.Cancels[1].Attempt != 2 {
		t.Fatalf("stop %+v", rep)
	}
	if len(x.cancelled) != 2 || x.cancelled[0] != 1 || x.cancelled[1] != 2 {
		t.Fatalf("cancelled attempts %v, want 1 and 2", x.cancelled)
	}
	st, _ := e.Get("a")
	if len(st.Attempts[0].Cancels) != 1 || len(st.Attempts[1].Cancels) != 1 || len(st.Attempts[2].Cancels) != 0 {
		t.Fatalf("cancel records %+v", st.Attempts)
	}
}

// walk follows path through the model's steps, checking the invariants
// after each as the search does, and returns a run at its end.
func (m *mModel) walk(t *testing.T, path []string) *mRun {
	t.Helper()
	s := &mState{fence: map[string][]string{}, applied: map[string]bool{}, confirm: m.confirm(), confirmed: map[string]uint64{}}
	for _, name := range path {
		r := restore(t, s, true)
		var st *mStep
		for _, c := range m.steps(r.e) {
			if c.name == name {
				c := c
				st = &c
				break
			}
		}
		if st == nil {
			t.Fatalf("%v: no step %q", s.path, name)
		}
		r2 := restore(t, s, !st.restart)
		_ = st.do(r2)
		ns := r2.snapshot(append(append([]string(nil), s.path...), name))
		m.follow(t, s, ns)
		m.check(t, r2, ns)
		s = ns
	}
	return restore(t, s, true)
}

// X9 (Security round 7 on #1433): Release answers an authorized request
// only when the effect went under a rival after it was made (R15). b is
// made after a went, while a's later owner retry is still unknown: b is
// held behind a, not answered, so Release leaves it alone.
func TestReleaseLeavesARequestMadeAfterTheEffectWent(t *testing.T) {
	m := mModel{ids: []string{"a", "b"}, owner: true}
	r := m.walk(t, []string{"submit a", "approve a", "dispatch a refuse", "dispatch a dropack", "park a",
		"retry a timeout", "resolve a#2", "submit b", "confirm b", "approve b"})
	a, b := r.e.intents["a"], r.e.intents["b"]
	if a.state != OutcomeUnknown || a.wentSeq == 0 || b.state != Authorized || b.seq < a.wentSeq {
		t.Fatalf("a %s went %d, b %s at %d", a.state, a.wentSeq, b.state, b.seq)
	}
	if o := r.e.sameEffect(b); o != a {
		t.Fatalf("b is not held behind a: %v", o)
	}
	var called []string
	got := r.e.Release(ctx, func(ctx context.Context, id string) (Status, error) {
		called = append(called, id)
		return r.e.Dispatch(ctx, id)
	})
	if len(called) != 0 || len(got) != 0 || r.e.intents["b"].state != Authorized {
		t.Fatalf("Release dispatched %v (%v); b %s", called, got, r.e.intents["b"].state)
	}
}

// I5 at a pinned path: b approved before a went did not see the repeat
// (Security B10 on #1433), so after a went b is refused at its dispatch
// and never applied; approved or confirmed after a went, it goes.
func TestModelRepeatGoesOnlyOnceConfirmed(t *testing.T) {
	m := mModel{ids: []string{"a", "b"}}
	r := m.walk(t, []string{"submit a", "approve a", "submit b", "approve b", "dispatch a ok", "dispatch b ok"})
	if st := r.e.intents["b"].state; st != Denied || len(r.x.log) != 1 {
		t.Fatalf("repeat approved before the send went: b %s, applied %+v", st, r.x.log)
	}
	r = m.walk(t, []string{"submit a", "approve a", "dispatch a ok", "submit b", "approve b", "dispatch b ok"})
	if st := r.e.intents["b"].state; st != Succeeded || len(r.x.log) != 2 {
		t.Fatalf("repeat approved after the send went: b %s, applied %+v", st, r.x.log)
	}
	r = m.walk(t, []string{"submit a", "approve a", "dispatch a ok", "submit b", "confirm b", "approve b", "dispatch b ok"})
	if st := r.e.intents["b"].state; st != Succeeded || len(r.x.log) != 2 {
		t.Fatalf("confirmed repeat: b %s, applied %+v", st, r.x.log)
	}
}
