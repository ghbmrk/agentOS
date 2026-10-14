package journal

import (
	"errors"
	"sync"
	"testing"
)

// REQ: OP-2, ADP-9

// B8, P6, R11, R12: same-effect rivalry is bounded. A rival that went
// holds back only requests made before it went; narrowing intents are
// exempt; a parked retry and a held resubmission never wait for each
// other; and a held resubmission that a not-done effect waits for is
// dispatched by the settle loop, not left to the agent.

// sendNow submits, approves and dispatches in.
func sendNow(t *testing.T, e *Engine, in Intent) (Status, error) {
	t.Helper()
	must(e.Submit(in))
	must(e.Authorize(ctx, in.ID))
	return e.Dispatch(ctx, in.ID)
}

// revoke is an owner REVOKE of grant g: intents that differ only in
// GrantRef share one effect fingerprint.
func revoke(id, g string) Intent {
	in := intent(id, BrokerAccount)
	in.Action, in.Params, in.Recipients, in.Visibility, in.GrantRef = ActionGrantRevoke, nil, nil, "", g
	return in
}

// B8: one transient refusal of a monthly payment, then the guest's
// repeat goes. Each later identical payment is a deliberate new send and
// goes, also after a restart.
func TestOP2RecurringPaymentGoesAfterOneRefusal(t *testing.T) {
	svc := newService()
	svc.mode = func(key string) execMode {
		if key == AttemptKey("m1", 1) {
			return modeRefuse
		}
		return modeOK
	}
	st, p := &MemStore{}, newPolicy()
	e := mustOpen(t, st, p, svc)
	if s, _ := sendNow(t, e, paymentStub("m1")); s.State != NotApplied {
		t.Fatalf("m1: %+v", s)
	}
	if s, err := e.Dispatch(ctx, "m1"); err != nil || s.State != Succeeded {
		t.Fatalf("m1 again: %+v %v", s, err)
	}
	for _, id := range []string{"m2", "m3"} {
		e = mustOpen(t, st, p, svc)
		if s, err := sendNow(t, e, paymentStub(id)); err != nil || s.State != Succeeded {
			t.Fatalf("%s: %+v %v", id, s, err)
		}
	}
	if svc.effectCount("m1") != 1 || svc.effectCount("m2") != 1 || svc.effectCount("m3") != 1 {
		t.Fatalf("effects %v", svc.effects)
	}
}

// B8: a send cut off by a restart, proved not done and sent again by the
// engine, does not hold back a later identical send.
func TestOP2SendAfterARecoveredOneGoes(t *testing.T) {
	svc := notDoneService()
	st := killedBetween(t, svc, mailSend("a"))
	e := mustOpen(t, st, newPolicy(), svc)
	if rep := e.Reconcile(ctx); len(rep.Redispatched) != 1 || svc.effectCount("a") != 1 {
		t.Fatalf("report %+v, a=%d", rep, svc.effectCount("a"))
	}
	if s, err := sendNow(t, e, mailSend("later")); err != nil || s.State != Succeeded {
		t.Fatalf("later: %+v %v", s, err)
	}
}

// B8, narrowing: revokes differ only in GrantRef. After one is refused by
// its executor and another goes, every later revoke still goes: an intent
// that only takes authority away is never held back as the same effect.
func TestOP2RevokesAreNeverSuperseded(t *testing.T) {
	svc := newService()
	svc.mode = func(key string) execMode {
		if key == AttemptKey("r9", 1) {
			return modeRefuse // "no grant G9"
		}
		return modeOK
	}
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	if s, _ := sendNow(t, e, revoke("r9", "G9")); s.State != NotApplied {
		t.Fatalf("r9: %+v", s)
	}
	for _, g := range []string{"G2", "G3", "G4"} {
		if s, err := sendNow(t, e, revoke("r-"+g, g)); err != nil || s.State != Succeeded {
			t.Fatalf("revoke %s: %+v %v", g, s, err)
		}
	}
	// The guest's (here the owner's) repeat of the refused one goes too.
	if s, err := e.Dispatch(ctx, "r9"); err != nil || s.State != Succeeded {
		t.Fatalf("r9 again: %+v %v", s, err)
	}
}

// B8, narrowing after a restart: a pause proved not done is offered for
// RETRY even while an identical pause waits for approval, and its resend
// goes; so does the waiting one.
func TestOP2NotDonePauseIsOfferedWhileAnotherWaits(t *testing.T) {
	pause := func(id string) Intent {
		in := revoke(id, "G1")
		in.Action = ActionGrantPause
		return in
	}
	svc := newService()
	svc.mode = func(key string) execMode {
		if key == AttemptKey("a", 1) {
			return modeTimeout
		}
		return modeOK
	}
	st := killedBetween(t, svc, pause("a"))
	p := newPolicy()
	e := mustOpen(t, st, p, svc)
	p.revoke("a", true)
	e.Reconcile(ctx)
	p.revoke("a", false)
	must(e.Submit(pause("b")))
	if ns := e.NotResent(); len(ns) != 1 || ns[0].Intent.ID != "a" {
		t.Fatalf("not resent %+v", ns)
	}
	if s, err := e.Resend(ctx, "a", 1); err != nil || s.State != Succeeded {
		t.Fatalf("resend of a: %+v %v", s, err)
	}
	must(e.Authorize(ctx, "b"))
	if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != Succeeded {
		t.Fatalf("b: %+v %v", s, err)
	}
}

// R11, as found: a's first attempt was proved not done and its resend
// ended unclear and was parked; the agent's resubmission b is held
// behind it. The owner's RETRY of a goes, and b, made before a went, is
// then refused.
func TestOP2ParkedRetryIsNotHeldByAHeldResubmission(t *testing.T) {
	svc := newService()
	svc.mode = func(key string) execMode {
		if key == AttemptKey("a", 1) || key == AttemptKey("a", 2) {
			return modeTimeout
		}
		return modeOK
	}
	svc.knows = func(key string) bool { return key != AttemptKey("a", 2) }
	st := killedBetween(t, svc, mailSend("a"))
	e := mustOpen(t, st, newPolicy(), svc)
	e.Reconcile(ctx)
	for i := 0; i < parkAfter && len(e.Parked()) == 0; i++ {
		e.Reconcile(ctx)
	}
	if ps := e.Parked(); len(ps) != 1 || ps[0].Attempt != 2 {
		t.Fatalf("parked %+v", ps)
	}
	var held *HeldError
	if _, err := sendNow(t, e, mailSend("b")); !errors.As(err, &held) || held.BlockedBy != "a" {
		t.Fatalf("b: %v", err)
	}
	if s, err := e.Retry(ctx, "a", 2); err != nil || s.State != Succeeded {
		t.Fatalf("retry of a: %+v %v", s, err)
	}
	_, err := e.Dispatch(ctx, "b")
	refusedAs(t, err, "b", "a")
	once(t, svc, 1, 0)
}

// A request made before z was first dispatched is a separate send, from
// z and from z's resubmission alike: c made before a was tried, x made
// after a was submitted but before it was tried. b, a's resubmission,
// goes in a's place, and c and x go too.
func TestOP2RequestsMadeBeforeTheFirstWasTriedAreNotRivalsOfItsResubmission(t *testing.T) {
	svc := notDoneService()
	cs := &crashStore{MemStore: &MemStore{}, budget: 5}
	p := newPolicy()
	e := mustOpen(t, cs, p, svc)
	must(e.Submit(mailSend("c")))
	must(e.Submit(mailSend("a")))
	must(e.Submit(mailSend("x")))
	must(e.Authorize(ctx, "a"))
	_, _ = e.Dispatch(ctx, "a") // killed
	if !cs.crashed {
		t.Fatal("not killed")
	}
	e = mustOpen(t, cs.MemStore, p, svc)
	p.revoke("a", true)
	e.Reconcile(ctx)
	p.revoke("a", false)
	if s, err := sendNow(t, e, mailSend("b")); err != nil || s.State != Succeeded {
		t.Fatalf("b: %+v %v", s, err)
	}
	for _, id := range []string{"c", "x"} {
		must(e.Authorize(ctx, id))
		if s, err := e.Dispatch(ctx, id); err != nil || s.State != Succeeded {
			t.Fatalf("%s: %+v %v", id, s, err)
		}
	}
	_, err := e.Resend(ctx, "a", 1)
	refusedAs(t, err, "a", "b")
	if svc.effectCount("a") != 0 || svc.effectCount("b") != 1 || svc.effectCount("c") != 1 || svc.effectCount("x") != 1 {
		t.Fatalf("effects %v", svc.effects)
	}
}

// R12: a was unclear at the restart and the agent resubmitted it as b,
// which is held by the fence. The check proves a not done; b wins over
// a's resend, so a is not offered, and the settle loop's Release then
// dispatches b: the effect does not wait on the agent asking again.
func TestOP2HeldResubmissionIsReleasedWhenTheOriginalIsProvedNotDone(t *testing.T) {
	svc := notDoneService()
	st := killedBetween(t, svc, mailSend("a"))
	e := mustOpen(t, st, newPolicy(), svc)
	if _, err := sendNow(t, e, mailSend("b")); !errors.Is(err, ErrUnreconciled) {
		t.Fatalf("b before the check: %v", err)
	}
	if rep := e.Reconcile(ctx); len(rep.Redispatched) != 0 {
		t.Fatalf("report %+v", rep)
	}
	if ns := e.NotResent(); len(ns) != 0 {
		t.Fatalf("not resent %+v", ns)
	}
	if got := e.Release(ctx, e.Dispatch); len(got) != 1 || got[0] != "b" {
		t.Fatalf("released %v", got)
	}
	if s := must(e.Get("b")); s.State != Succeeded {
		t.Fatalf("b: %+v", s)
	}
	_, err := e.Resend(ctx, "a", 1)
	refusedAs(t, err, "a", "b")
	if got := e.Release(ctx, e.Dispatch); len(got) != 0 {
		t.Fatalf("released again %v", got)
	}
	once(t, svc, 0, 1)
}

// R12, refused: a released resubmission the recheck refuses is denied,
// and the not-done original is offered again.
func TestOP2RefusedReleaseOffersTheOriginalAgain(t *testing.T) {
	svc := notDoneService()
	st := killedBetween(t, svc, mailSend("a"))
	p := newPolicy()
	e := mustOpen(t, st, p, svc)
	_, _ = sendNow(t, e, mailSend("b"))
	e.Reconcile(ctx)
	p.revoke("b", true)
	if got := e.Release(ctx, e.Dispatch); len(got) != 0 {
		t.Fatalf("released %v", got)
	}
	if s := must(e.Get("b")); s.State != Denied {
		t.Fatalf("b: %+v", s)
	}
	if ns := e.NotResent(); len(ns) != 1 || ns[0].Intent.ID != "a" {
		t.Fatalf("not resent %+v", ns)
	}
	if s, err := e.Resend(ctx, "a", 1); err != nil || s.State != Succeeded {
		t.Fatalf("resend of a: %+v %v", s, err)
	}
	once(t, svc, 1, 0)
}

// SettleUnknown does not dispatch anything itself: Release is the settle
// loop's separate step, which the daemon runs through the gate.
func TestOP2SettleUnknownDoesNotRelease(t *testing.T) {
	svc := notDoneService()
	st := killedBetween(t, svc, mailSend("a"))
	e := mustOpen(t, st, newPolicy(), svc)
	_, _ = sendNow(t, e, mailSend("b"))
	settle(e)
	if s := must(e.Get("b")); s.State != Authorized {
		t.Fatalf("b: %+v", s)
	}
}

// The model's finding: a parked attempt that went after all, whose
// owner's retry the service then refused. The intent is not done by its
// latest attempt but may have gone by the parked one, so neither the
// guest's repeat nor a resubmission may send it again; it stays offered
// for RETRY, and a check that finds the parked attempt went closes it.
func TestOP2RefusedRetryLeavesTheParkedAttemptUnresolved(t *testing.T) {
	svc := newService()
	svc.mode = func(key string) execMode {
		switch key {
		case AttemptKey("a", 1):
			return modeDropAck // went; the acknowledgment was lost
		case AttemptKey("a", 2):
			return modeRefuse
		}
		return modeOK
	}
	svc.knows = func(string) bool { return false }
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	if s, _ := sendNow(t, e, mailSend("a")); s.State != OutcomeUnknown {
		t.Fatalf("a: %+v", s)
	}
	if !e.park("a", 1, true) {
		t.Fatal("a not parked")
	}
	// The retry did not go, but attempt 1 may have: a stays
	// outcome_unknown (B9), and Unclear names the parked attempt.
	if s, err := e.Retry(ctx, "a", 1); err != nil || s.State != OutcomeUnknown || s.Unclear() != 1 || s.Outstanding() != 1 {
		t.Fatalf("retry of a: %+v %v", s, err)
	}
	if _, err := e.Dispatch(ctx, "a"); !errors.Is(err, ErrState) {
		t.Fatalf("guest repeat of a: %v", err)
	}
	var held *HeldError
	if _, err := sendNow(t, e, mailSend("b")); !errors.As(err, &held) || held.BlockedBy != "a" {
		t.Fatalf("b: %v", err)
	}
	if ps := e.Parked(); len(ps) != 1 || ps[0].Intent.ID != "a" || ps[0].Attempt != 2 {
		t.Fatalf("parked %+v", ps)
	}
	if ns := e.NotResent(); len(ns) != 0 {
		t.Fatalf("not resent %+v", ns)
	}
	if svc.effectCount("a") != 1 || svc.effectCount("b") != 0 {
		t.Fatalf("effects %v", svc.effects)
	}
	svc.mu.Lock()
	svc.knows = func(string) bool { return true }
	svc.mu.Unlock()
	e.Reconcile(ctx)
	if s := must(e.Get("a")); s.State != Succeeded {
		t.Fatalf("a after the check: %+v", s)
	}
	_, err := e.Dispatch(ctx, "b")
	refusedAs(t, err, "b", "a")
	if svc.effectCount("a")+svc.effectCount("b") != 1 {
		t.Fatalf("effects %v", svc.effects)
	}
}

// Races: a proved not done; b and c are resubmissions; the owner's
// resend, their dispatches, a guest repeat of a, NotResent and Reconcile
// race, with and without a restart first. The effect goes once.
func TestOP2RaceOfThreeRivalsGoesOnce(t *testing.T) {
	for i := 0; i < 200; i++ {
		svc := notDoneService()
		st := killedBetween(t, svc, mailSend("a"))
		p := newPolicy()
		e := mustOpen(t, st, p, svc)
		p.revoke("a", true)
		e.Reconcile(ctx)
		p.revoke("a", false)
		for _, id := range []string{"b", "c"} {
			must(e.Submit(mailSend(id)))
			must(e.Authorize(ctx, id))
		}
		if i%2 == 1 {
			e = mustOpen(t, st, p, svc)
		}
		var wg sync.WaitGroup
		for _, f := range []func(){
			func() { _, _ = e.Resend(ctx, "a", 1) },
			func() { _, _ = e.Dispatch(ctx, "b") },
			func() { _, _ = e.Dispatch(ctx, "c") },
			func() { _, _ = e.Dispatch(ctx, "a") },
			func() { e.NotResent() },
			func() { e.Reconcile(ctx) },
			func() { e.Release(ctx, e.Dispatch) },
		} {
			wg.Add(1)
			go func(f func()) { defer wg.Done(); f() }(f)
		}
		wg.Wait()
		_, _ = e.Resend(ctx, "a", 1)
		_, _ = e.Dispatch(ctx, "b")
		_, _ = e.Dispatch(ctx, "c")
		if n := svc.effectCount("a") + svc.effectCount("b") + svc.effectCount("c"); n != 1 {
			t.Fatalf("iteration %d: effects %v", i, svc.effects)
		}
	}
}

// b's service refuses it; then a's resend and c race. Exactly one more
// goes.
func TestOP2RaceAfterARefusedResubmissionGoesOnce(t *testing.T) {
	for i := 0; i < 200; i++ {
		svc := notDoneService()
		svc.mode = func(key string) execMode {
			switch key {
			case AttemptKey("a", 1):
				return modeTimeout
			case AttemptKey("b", 1):
				return modeRefuse
			}
			return modeOK
		}
		st := killedBetween(t, svc, mailSend("a"))
		p := newPolicy()
		e := mustOpen(t, st, p, svc)
		p.revoke("a", true)
		e.Reconcile(ctx)
		p.revoke("a", false)
		_, _ = sendNow(t, e, mailSend("b"))
		must(e.Submit(mailSend("c")))
		must(e.Authorize(ctx, "c"))
		var wg sync.WaitGroup
		for _, f := range []func(){
			func() { _, _ = e.Resend(ctx, "a", 1) },
			func() { _, _ = e.Dispatch(ctx, "b") },
			func() { _, _ = e.Dispatch(ctx, "c") },
		} {
			wg.Add(1)
			go func(f func()) { defer wg.Done(); f() }(f)
		}
		wg.Wait()
		_, _ = e.Resend(ctx, "a", 1)
		_, _ = e.Dispatch(ctx, "c")
		if n := svc.effectCount("a") + svc.effectCount("b") + svc.effectCount("c"); n != 1 {
			t.Fatalf("iteration %d: effects %v", i, svc.effects)
		}
	}
}

// The guest's repeat of a refused request while its resubmission waits
// for approval is refused, not denied: the resubmission may still be
// denied, and the request is then free to go.
func TestOP2RepeatWhileTheResubmissionWaitsIsRefusedNotDenied(t *testing.T) {
	svc := newService()
	svc.mode = func(key string) execMode {
		if key == AttemptKey("a", 1) {
			return modeRefuse
		}
		return modeOK
	}
	p := newPolicy()
	e := mustOpen(t, &MemStore{}, p, svc)
	if s, _ := sendNow(t, e, mailSend("a")); s.State != NotApplied {
		t.Fatalf("a: %+v", s)
	}
	must(e.Submit(mailSend("b")))
	s, err := e.Dispatch(ctx, "a")
	refusedAs(t, err, "a", "b")
	if s.State != NotApplied {
		t.Fatalf("a denied while b waits: %+v", s)
	}
	p.revoke("b", true)
	must(e.Authorize(ctx, "b"))
	if s, err := e.Dispatch(ctx, "a"); err != nil || s.State != Succeeded {
		t.Fatalf("a after b was denied: %+v %v", s, err)
	}
	once(t, svc, 1, 0)
}

// An owner retry whose own attempt a check proves not done, while the
// parked attempt before it is still unknown, is not offered as not done
// (only as parked), and the engine does not resend it.
func TestOP2NotDoneRetryOfAParkedAttemptIsNotResent(t *testing.T) {
	svc := newService()
	svc.mode = func(key string) execMode {
		switch key {
		case AttemptKey("a", 1):
			return modeDropAck
		case AttemptKey("a", 2):
			return modeTimeout
		}
		return modeOK
	}
	svc.knows = func(key string) bool { return key == AttemptKey("a", 2) }
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	_, _ = sendNow(t, e, mailSend("a"))
	if !e.park("a", 1, true) {
		t.Fatal("a not parked")
	}
	if s, err := e.Retry(ctx, "a", 1); err != nil || s.State != OutcomeUnknown {
		t.Fatalf("retry: %+v %v", s, err)
	}
	if rep := e.Reconcile(ctx); len(rep.Redispatched) != 0 {
		t.Fatalf("report %+v", rep)
	}
	if s := must(e.Get("a")); s.State != OutcomeUnknown || s.Unclear() != 1 || len(s.Attempts) != 2 {
		t.Fatalf("a: %+v", s)
	}
	if ns := e.NotResent(); len(ns) != 0 {
		t.Fatalf("not resent %+v", ns)
	}
	if ps := e.Parked(); len(ps) != 1 || ps[0].Attempt != 2 {
		t.Fatalf("parked %+v", ps)
	}
	if _, err := e.Resend(ctx, "a", 2); !errors.Is(err, ErrState) {
		t.Fatalf("resend: %v", err)
	}
	if svc.effectCount("a") != 1 {
		t.Fatalf("effects %v", svc.effects)
	}
}

// The owner settles a parked attempt as done while their retry of it is
// still unclear; a check then proves the retry not done. The effect went,
// so it is not sent again.
func TestOP2RetryProvedNotDoneAfterTheParkedAttemptWentIsNotResent(t *testing.T) {
	svc := newService()
	svc.mode = func(key string) execMode {
		switch key {
		case AttemptKey("a", 1):
			return modeDropAck
		case AttemptKey("a", 2):
			return modeTimeout
		}
		return modeOK
	}
	svc.knows = func(key string) bool { return key == AttemptKey("a", 2) }
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	_, _ = sendNow(t, e, mailSend("a"))
	if !e.park("a", 1, true) {
		t.Fatal("a not parked")
	}
	if _, err := e.Retry(ctx, "a", 1); err != nil {
		t.Fatal(err)
	}
	must(e.Resolve("a", 1, Outcome{Result: ResultSucceeded, Evidence: "statement"}, "owner"))
	if rep := e.Reconcile(ctx); len(rep.Redispatched) != 0 {
		t.Fatalf("report %+v", rep)
	}
	if _, err := e.Resend(ctx, "a", 2); !errors.Is(err, ErrState) {
		t.Fatalf("resend: %v", err)
	}
	if svc.effectCount("a") != 1 {
		t.Fatalf("effects %v", svc.effects)
	}
}
