package journal

import (
	"errors"
	"testing"
)

// REQ: OP-2

// superseded checks that a, proved not done, is neither offered nor sent
// again because its rival by went, may have gone, or waits to go: NotResent
// leaves it out and Resend refuses it with a SupersededError that matches
// ErrState, running nothing (OP-2).
func superseded(t *testing.T, e *Engine, svc *fakeService, by string) {
	t.Helper()
	for _, p := range e.NotResent() {
		if p.Intent.ID == "a" {
			t.Fatalf("a still offered after %s went: %+v", by, p)
		}
	}
	before := svc.executeCount()
	_, err := e.Resend(ctx, "a", 1)
	var se *SupersededError
	if !errors.As(err, &se) || se.ID != "a" || se.By != by || !errors.Is(err, ErrState) {
		t.Fatalf("resend of a: %v", err)
	}
	if svc.executeCount() != before || svc.effectCount("a") != 0 {
		t.Fatalf("resend ran: executes %v, effects of a %d", svc.executes, svc.effectCount("a"))
	}
	if s := must(e.Get("a")); s.State != NotApplied || len(s.Attempts) != 1 {
		t.Fatalf("a: %+v", s)
	}
}

// B6: a check proves a was not done after a restart, and its resend is
// refused because the approval lived in memory, so a is listed as not
// resent. The agent then resubmits the same effect as b, which is
// approved and goes. a is no longer offered, and the owner's RETRY of it
// (Resend) is refused, also after a restart: the effect happened once.
func TestOP2NotDoneIsNotResentAfterTheSameEffectWent(t *testing.T) {
	svc := notDoneService()
	st := killedBetween(t, svc, mailSend("a"))
	p := newPolicy()
	e := mustOpen(t, st, p, svc)
	p.revoke("a", true)
	refusedResend(t, e, e.Reconcile(ctx), svc, 1)

	must(e.Submit(mailSend("b")))
	must(e.Authorize(ctx, "b"))
	if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != Succeeded {
		t.Fatalf("b: %+v %v", s, err)
	}
	p.revoke("a", false) // the owner approves the RETRY line
	superseded(t, e, svc, "b")

	e = mustOpen(t, st, p, svc)
	superseded(t, e, svc, "b")
	if svc.effectCount("a")+svc.effectCount("b") != 1 {
		t.Fatalf("effect applied %d times", svc.effectCount("a")+svc.effectCount("b"))
	}
}

// A same-effect intent dispatched after a's not-done check holds a back
// while its own outcome is unknown, since it may have gone. Once a check
// proves it was not done too, both are offered; the owner's Resend of a
// sends the effect, and b is then the one superseded.
func TestOP2NotDoneIsOfferedAgainWhenTheLaterSendIsProvedNotDone(t *testing.T) {
	svc := notDoneService()
	st := killedBetween(t, svc, mailSend("a"))
	p := newPolicy()
	e := mustOpen(t, st, p, svc)
	p.revoke("a", true)
	refusedResend(t, e, e.Reconcile(ctx), svc, 1)

	svc.mu.Lock()
	svc.mode = func(key string) execMode {
		if key == AttemptKey("a", 1) || key == AttemptKey("b", 1) {
			return modeTimeout
		}
		return modeOK
	}
	svc.knows = func(key string) bool { return key != AttemptKey("b", 1) }
	svc.mu.Unlock()
	must(e.Submit(mailSend("b")))
	must(e.Authorize(ctx, "b"))
	if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != OutcomeUnknown {
		t.Fatalf("b: %+v %v", s, err)
	}
	p.revoke("a", false)
	superseded(t, e, svc, "b") // b may have gone

	svc.mu.Lock()
	svc.knows = func(string) bool { return true }
	svc.mu.Unlock()
	p.revoke("b", true) // b's own resend is refused, as a's was
	e.Reconcile(ctx)
	if s := must(e.Get("b")); s.State != NotApplied {
		t.Fatalf("b: %+v", s)
	}
	ns := e.NotResent()
	if len(ns) != 2 || ns[0].Intent.ID != "a" || ns[1].Intent.ID != "b" {
		t.Fatalf("not resent %+v", ns)
	}
	if s, err := e.Resend(ctx, "a", 1); err != nil || s.State != Succeeded {
		t.Fatalf("resend of a: %+v %v", s, err)
	}
	p.revoke("b", false)
	ns = e.NotResent()
	if len(ns) != 0 {
		t.Fatalf("not resent %+v", ns)
	}
	_, err := e.Resend(ctx, "b", 1)
	var se *SupersededError
	if !errors.As(err, &se) || se.ID != "b" || se.By != "a" {
		t.Fatalf("resend of b: %v", err)
	}
	if svc.effectCount("a") != 1 || svc.effectCount("b") != 0 {
		t.Fatalf("effects a=%d b=%d", svc.effectCount("a"), svc.effectCount("b"))
	}
}

// A different effect dispatched after the check does not supersede a.
func TestOP2NotDoneStaysOfferedAfterAnotherEffect(t *testing.T) {
	svc := notDoneService()
	st := killedBetween(t, svc, mailSend("a"))
	p := newPolicy()
	e := mustOpen(t, st, p, svc)
	p.revoke("a", true)
	refusedResend(t, e, e.Reconcile(ctx), svc, 1)
	other := mailSend("c")
	other.Params = map[string]any{"subject": "another", "n": 2}
	must(e.Submit(other))
	must(e.Authorize(ctx, "c"))
	if s, err := e.Dispatch(ctx, "c"); err != nil || s.State != Succeeded {
		t.Fatalf("c: %+v %v", s, err)
	}
	if ns := e.NotResent(); len(ns) != 1 || ns[0].Intent.ID != "a" {
		t.Fatalf("not resent %+v", ns)
	}
	p.revoke("a", false)
	if s, err := e.Resend(ctx, "a", 1); err != nil || s.State != Succeeded || svc.effectCount("a") != 1 {
		t.Fatalf("resend of a: %+v %v", s, err)
	}
}

// The same effect sent earlier, before a was dispatched, is not a
// resubmission of a: a goes on being offered and its resend goes.
func TestOP2NotDoneStaysOfferedAfterAnEarlierSameEffect(t *testing.T) {
	svc := notDoneService()
	cs := &crashStore{MemStore: &MemStore{}, budget: 7}
	e := mustOpen(t, cs, newPolicy(), svc)
	must(e.Submit(mailSend("c")))
	must(e.Authorize(ctx, "c"))
	if s, err := e.Dispatch(ctx, "c"); err != nil || s.State != Succeeded {
		t.Fatalf("c: %+v %v", s, err)
	}
	must(e.Submit(mailSend("a")))
	must(e.Authorize(ctx, "a"))
	_, _ = e.Dispatch(ctx, "a")
	if !cs.crashed {
		t.Fatal("not killed between a's intent and outcome")
	}
	p := newPolicy()
	e = mustOpen(t, cs.MemStore, p, svc)
	p.revoke("a", true)
	refusedResend(t, e, e.Reconcile(ctx), svc, 2)
	p.revoke("a", false)
	if s, err := e.Resend(ctx, "a", 1); err != nil || s.State != Succeeded || svc.effectCount("a") != 1 {
		t.Fatalf("resend of a: %+v %v", s, err)
	}
}
