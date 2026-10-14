package journal

import (
	"context"
	"errors"
	"testing"
	"time"
)

// REQ: OP-2, ADP-9, CAP-3

// An intent whose owner's retry the service refused while its parked
// first try is still unknown (unclear) may have gone. It is
// outcome_unknown, so every reader of the state treats it as such (B9):
// Erase holds it, InUse charges its place as started, STOP reports it as
// unresolved and cancels its parked try, a restart keeps it unresolved
// without fencing it, and a rival refused behind it is told it may have
// gone.

// cancelExec is the model's service with a Canceller that records which
// attempt STOP asked to cancel.
type cancelExec struct {
	*mExec
	cancelled []int
}

func (c *cancelExec) Cancel(_ context.Context, _ Intent, n int) (bool, string) {
	c.cancelled = append(c.cancelled, n)
	return false, "too late"
}

// unclearA leaves a unclear: attempt 1 went but its acknowledgment was
// lost, it was parked, and the owner's retry (attempt 2) was refused.
func unclearA(t *testing.T) *mRun {
	t.Helper()
	r := restore(t, &mState{fence: map[string][]string{}, applied: map[string]bool{}}, true)
	must(r.e.Submit(intent("a", "mail")))
	must(r.e.Authorize(ctx, "a"))
	r.x.next, r.x.via = mDropAck, "dispatch"
	_, _ = r.e.Dispatch(ctx, "a")
	if !r.e.park("a", 1, true) {
		t.Fatal("a not parked")
	}
	r.x.next, r.x.via = mRefuse, "retry"
	st, err := r.e.Retry(ctx, "a", 1)
	if err != nil || st.State != OutcomeUnknown || st.Unclear() != 1 || st.Outstanding() != 1 {
		t.Fatalf("retry of a: %+v %v", st, err)
	}
	return r
}

// B9, E1: an erase (the owner's, or a recall reset's) holds an unclear
// intent, as it holds any outcome_unknown one, so its hold on the effect
// stays and a resubmission waits.
func TestOP2EraseHoldsAnIntentWhoseParkedTryMayHaveGone(t *testing.T) {
	r := unclearA(t)
	erased, held, err := r.e.Erase([]string{"a"})
	if err != nil || len(erased) != 0 || len(held) != 1 || held[0] != "a" {
		t.Fatalf("erase: erased %v held %v err %v", erased, held, err)
	}
	if st := must(r.e.Get("a")); st.State != OutcomeUnknown {
		t.Fatalf("a after the erase: %+v", st)
	}
	must(r.e.Submit(intent("b", "mail")))
	must(r.e.Authorize(ctx, "b"))
	r.x.next, r.x.via = mOK, "dispatch"
	var held2 *HeldError
	if _, err := r.e.Dispatch(ctx, "b"); !errors.As(err, &held2) || held2.BlockedBy != "a" {
		t.Fatalf("b: %v", err)
	}
	if len(r.x.log) != 1 {
		t.Fatalf("applied %+v", r.x.log)
	}
}

// B9, E2 (ADP-9): the scope bound charges an unclear intent's place as
// started, whatever its age, so the bound counts the try that may have
// gone (and grants' near-miss check sees it).
func TestOP2InUseCountsAnIntentWhoseParkedTryMayHaveGone(t *testing.T) {
	r := unclearA(t)
	u := r.e.InUse("mail", "send", mNow.Add(time.Hour))
	if len(u) != 1 || u[0].Intent.ID != "a" || !u[0].Started {
		t.Fatalf("in use %+v", u)
	}
}

// B9, R13: STOP reports an unclear intent as one that may have reached
// the service, not as held for RESUME, and asks to cancel its parked try.
func TestOP2StopReportsAnIntentWhoseParkedTryMayHaveGone(t *testing.T) {
	r := unclearA(t)
	c := &cancelExec{mExec: r.x}
	r.e.execs["svc"] = c
	rep, err := r.e.Stop(ctx)
	if err != nil || len(rep.Held) != 0 || len(rep.Unresolved) != 1 || rep.Unresolved[0] != "a" {
		t.Fatalf("stop: %+v %v", rep, err)
	}
	if len(c.cancelled) != 1 || c.cancelled[0] != 1 {
		t.Fatalf("cancelled attempts %v, want [1]", c.cancelled)
	}
}

// B9: a restart replays an unclear intent as outcome_unknown, still
// parked, so it neither fences its account nor is redispatched, and the
// owner's RETRY still offers it.
func TestOP2RestartKeepsAnIntentWhoseParkedTryMayHaveGone(t *testing.T) {
	r := unclearA(t)
	r2 := restore(t, r.snapshot(nil), false)
	st := must(r2.e.Get("a"))
	if st.State != OutcomeUnknown || st.Unclear() != 1 {
		t.Fatalf("a after a restart: %+v", st)
	}
	if f := r2.e.Fenced("mail"); len(f) != 0 {
		t.Fatalf("fenced %v", f)
	}
	if ps := r2.e.Parked(); len(ps) != 1 || ps[0].Attempt != 2 || !ps[0].Dispatched.Equal(st.Attempts[0].Dispatched) {
		t.Fatalf("parked %+v", ps)
	}
	if _, err := r2.e.Dispatch(ctx, "a"); !errors.Is(err, ErrState) {
		t.Fatalf("guest repeat of a: %v", err)
	}
}

// U13: the resend of a not-done effect, refused behind a rival whose
// owner's retry was refused while its parked try is still unknown, says
// that rival may have gone.
func TestOP2ResendRefusedBehindAnUnclearRivalSaysItMayHaveGone(t *testing.T) {
	svc, _, _, e := notDoneOriginal(t)
	svc.mu.Lock()
	svc.mode = func(key string) execMode {
		switch key {
		case AttemptKey("a", 1), AttemptKey("b", 1):
			return modeTimeout
		case AttemptKey("b", 2):
			return modeRefuse
		}
		return modeOK
	}
	svc.knows = func(key string) bool { return key != AttemptKey("b", 1) }
	svc.mu.Unlock()
	must(e.Submit(mailSend("b")))
	must(e.Authorize(ctx, "b"))
	if s, _ := e.Dispatch(ctx, "b"); s.State != OutcomeUnknown {
		t.Fatalf("b: %+v", s)
	}
	for i := 0; i < parkAfter; i++ {
		e.Reconcile(ctx)
	}
	if s, err := e.Retry(ctx, "b", 1); err != nil || s.State != OutcomeUnknown || s.Unclear() != 1 {
		t.Fatalf("retry b: %+v %v", s, err)
	}
	_, err := e.Resend(ctx, "a", 1)
	var se *SupersededError
	if !errors.As(err, &se) || se.By != "b" || se.Rival != OutcomeUnknown {
		t.Fatalf("resend a: %v (%+v)", err, se)
	}
}

// R14: the settle loop's check of a parked try was gathered before the
// owner's retry started attempt 2; it finds attempt 1 went while attempt 2
// is in flight, and the service then refuses attempt 2. The effect went:
// a is succeeded (derive), and b, made before it went, is answered.
func TestOP2StaleCheckThatFindsTheParkedTryWentMakesItSucceeded(t *testing.T) {
	r := restore(t, &mState{fence: map[string][]string{}, applied: map[string]bool{}}, true)
	e, x := r.e, r.x
	must(e.Submit(intent("a", "mail")))
	must(e.Authorize(ctx, "a"))
	x.next = mDropAck
	_, _ = e.Dispatch(ctx, "a")
	e.park("a", 1, true)
	must(e.Submit(intent("b", "mail")))
	must(e.Authorize(ctx, "b"))
	if _, err := e.Dispatch(ctx, "b"); err == nil {
		t.Fatal("b went while a was parked")
	}
	ownerRetryStarts(t, e, "a", 2)
	must(e.Resolve("a", 1, Outcome{Result: ResultSucceeded, Evidence: "found"}, SourceReconcile))
	if st := must(e.Get("a")); st.State != InFlight {
		t.Fatalf("a while attempt 2 is in flight: %+v", st)
	}
	e.mu.Lock()
	err := e.commit(Record{Type: RecObserved, ID: "a", Attempt: 2, Result: ResultNotApplied, Source: "executor"})
	e.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if st := must(e.Get("a")); st.State != Succeeded {
		t.Fatalf("a: %+v", st)
	}
	if ps := e.Parked(); len(ps) != 0 {
		t.Fatalf("parked %+v", ps)
	}
	if out := e.Release(ctx, e.Dispatch); len(out) != 0 {
		t.Fatalf("released %v", out)
	}
	if st := must(e.Get("b")); st.State != Denied || st.Permission.GuestReason != supersededGuest {
		t.Fatalf("b: %+v", st)
	}
	if u := e.InUse("mail", "send", time.Time{}); len(u) != 1 || u[0].Intent.ID != "a" || !u[0].Started {
		t.Fatalf("in use %+v", u)
	}
}

// ownerRetryStarts commits attempt n of id as the owner's retry, as Retry
// does before it calls the executor.
func ownerRetryStarts(t *testing.T, e *Engine, id string, n int) {
	t.Helper()
	if _, err := e.rechecked(ctx, id, func(en *entry) (Record, error) {
		return Record{Type: RecDispatched, ID: id, Attempt: n, Source: DispatchOwner}, e.mayDispatch(en, true)
	}); err != nil {
		t.Fatal(err)
	}
}

// R14, T2: in the same race, while the owner's retry of a is still in
// flight, a not-done resubmission b that a held back is answered at once
// as superseded by a send that went, not as one that may have gone: the
// effect went after b was made, which is final.
func TestOP2RivalThatWentByAStaleCheckIsFinalWhileItsRetryIsInFlight(t *testing.T) {
	r := restore(t, &mState{fence: map[string][]string{}, applied: map[string]bool{}}, true)
	e, x := r.e, r.x
	// b goes first and is lost; a is requested after it.
	must(e.Submit(intent("b", "mail")))
	must(e.Authorize(ctx, "b"))
	x.next = mTimeout
	_, _ = e.Dispatch(ctx, "b")
	must(e.Submit(intent("a", "mail")))
	must(e.Authorize(ctx, "a"))
	// A check proves b not done; its resend is refused behind a, which
	// waits to go, and the settle loop's Release sends a, whose
	// acknowledgment is lost.
	x.check = "b"
	e.Reconcile(ctx)
	if st := must(e.Get("b")); st.State != NotApplied {
		t.Fatalf("b: %+v", st)
	}
	x.check, x.next = "", mDropAck
	if out := e.Release(ctx, e.Dispatch); len(out) != 1 || out[0] != "a" {
		t.Fatalf("released %v", out)
	}
	e.park("a", 1, true)
	ownerRetryStarts(t, e, "a", 2)
	must(e.Resolve("a", 1, Outcome{Result: ResultSucceeded, Evidence: "found"}, SourceReconcile))
	st, err := e.Dispatch(ctx, "b")
	var se *SupersededError
	if !errors.As(err, &se) || se.By != "a" || se.Rival != Succeeded || st.State != Denied {
		t.Fatalf("b: %+v %v", st, err)
	}
	if len(x.log) != 1 {
		t.Fatalf("applied %+v", x.log)
	}
}

// R15: c went after b was requested; b, authorized, is answered (denied)
// by the settle loop's Release, so it holds no scope-bound place and does
// not keep the sleeper awake until someone dispatches it.
func TestOP2ReleaseAnswersARequestWhoseEffectWentAsAnother(t *testing.T) {
	r := restore(t, &mState{fence: map[string][]string{}, applied: map[string]bool{}}, true)
	e, x := r.e, r.x
	must(e.Submit(intent("a", "mail")))
	must(e.Authorize(ctx, "a"))
	x.next = mRefuse
	_, _ = e.Dispatch(ctx, "a")
	for _, id := range []string{"b", "c"} {
		in := intent(id, "mail")
		in.Origin = "guest:agent"
		must(e.Submit(in))
		must(e.Authorize(ctx, id))
	}
	x.next = mOK
	if st, err := e.Dispatch(ctx, "c"); err != nil || st.State != Succeeded {
		t.Fatalf("c: %+v %v", st, err)
	}
	if !e.GuestActive() {
		t.Fatal("b is not active before the release")
	}
	if out := e.Release(ctx, e.Dispatch); len(out) != 0 {
		t.Fatalf("released %v", out)
	}
	if st := must(e.Get("b")); st.State != Denied || st.Permission.GuestReason != supersededGuest {
		t.Fatalf("b: %+v", st)
	}
	if e.GuestActive() {
		t.Fatal("still active after the release")
	}
	if u := e.InUse("mail", "send", time.Time{}); len(u) != 1 || u[0].Intent.ID != "c" {
		t.Fatalf("in use %+v", u)
	}
	if len(x.log) != 1 {
		t.Fatalf("applied %+v", x.log)
	}
}

// B9: the journal refuses, on replay as live, any record that would treat
// an unclear intent as one that did nothing or as plainly unknown: a
// recheck denial (an erase's), a plain dispatch, a key retry or a park
// of the owner's settled retry.
func TestOP2JournalRefusesRecordsThatTreatAnUnclearIntentAsDone(t *testing.T) {
	r := unclearA(t)
	for _, rec := range []Record{
		{Type: RecRecheckFailed, ID: "a", Reason: ErasedReason},
		{Type: RecDispatched, ID: "a", Attempt: 3},
		{Type: RecDispatched, ID: "a", Attempt: 2, Source: DispatchKey},
		{Type: RecParked, ID: "a", Attempt: 2},
	} {
		r.e.mu.Lock()
		err := r.e.commit(rec)
		r.e.mu.Unlock()
		if !errors.Is(err, ErrState) {
			t.Fatalf("%s %s: %v", rec.Type, rec.Source, err)
		}
	}
}

// B9: a restart fences an owner's retry left in flight; a check then
// proves that retry not done while the parked attempt before it is still
// unknown. The intent is unclear and parked, so its account's fence
// lifts: other work on the account resumes, as for any parked intent.
func TestOP2FenceLiftsWhenARetryIsProvedNotDoneBehindAParkedTry(t *testing.T) {
	r := restore(t, &mState{fence: map[string][]string{}, applied: map[string]bool{}}, true)
	must(r.e.Submit(intent("a", "mail")))
	must(r.e.Authorize(ctx, "a"))
	r.x.next = mDropAck
	_, _ = r.e.Dispatch(ctx, "a")
	r.e.park("a", 1, true)
	ownerRetryStarts(t, r.e, "a", 2) // the broker stops with attempt 2 in flight
	r2 := restore(t, r.snapshot(nil), false)
	if f := r2.e.Fenced("mail"); len(f) != 1 {
		t.Fatalf("fenced after the restart: %v", f)
	}
	r2.x.check = "a" // attempt 2 never reached the service
	r2.e.Reconcile(ctx)
	if st := must(r2.e.Get("a")); st.State != OutcomeUnknown || st.Unclear() != 1 {
		t.Fatalf("a: %+v", st)
	}
	if f := r2.e.Fenced("mail"); len(f) != 0 {
		t.Fatalf("fenced after the check: %v", f)
	}
}

// An intent the owner's evidence shows went by its parked first try,
// while the owner's retry of it is itself parked, is not offered for
// RETRY again: nothing would send it (mayDispatch), so the offer could
// only be refused.
func TestOP2ParkedRetryOfAnIntentThatWentIsNotOffered(t *testing.T) {
	r := restore(t, &mState{fence: map[string][]string{}, applied: map[string]bool{}}, true)
	must(r.e.Submit(intent("a", "mail")))
	must(r.e.Authorize(ctx, "a"))
	r.x.next = mDropAck
	_, _ = r.e.Dispatch(ctx, "a")
	r.e.park("a", 1, true)
	r.x.next = mTimeout
	must(r.e.Retry(ctx, "a", 1))
	must(r.e.Resolve("a", 1, Outcome{Result: ResultSucceeded, Evidence: "statement"}, "owner"))
	if !r.e.park("a", 2, true) {
		t.Fatal("attempt 2 not parked")
	}
	if ps := r.e.Parked(); len(ps) != 0 {
		t.Fatalf("parked %+v", ps)
	}
	if _, err := r.e.Retry(ctx, "a", 2); !errors.Is(err, ErrState) {
		t.Fatalf("retry: %v", err)
	}
}
