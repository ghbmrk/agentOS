package journal

import (
	"errors"
	"sync"
	"testing"
)

// REQ: OP-2

// The effect-level invariant (sameEffect): a not-done effect and its
// resubmission never both go, in either order and on every path to
// execution (Dispatch, Resend, Retry), and a not-done effect is never
// hidden by a resubmission that did not go.

// notDoneOriginal is a send a, killed between its dispatch and its
// outcome, that a check after the restart proved not done; its resend was
// refused (the approval lived in memory), so it is offered for RETRY. The
// policy allows a again.
func notDoneOriginal(t *testing.T) (*fakeService, *MemStore, *testPolicy, *Engine) {
	t.Helper()
	svc := notDoneService()
	st := killedBetween(t, svc, mailSend("a"))
	p := newPolicy()
	e := mustOpen(t, st, p, svc)
	p.revoke("a", true)
	refusedResend(t, e, e.Reconcile(ctx), svc, 1)
	p.revoke("a", false)
	return svc, st, p, e
}

// refusedAs checks that err is a SupersededError for id by by, matching
// ErrState.
func refusedAs(t *testing.T, err error, id, by string) {
	t.Helper()
	var se *SupersededError
	if !errors.As(err, &se) || se.ID != id || se.By != by || !errors.Is(err, ErrState) {
		t.Fatalf("%s: err %v, want superseded by %s", id, err, by)
	}
}

// once checks that the effect went exactly once in all, as a or b.
func once(t *testing.T, svc *fakeService, a, b int) {
	t.Helper()
	if svc.effectCount("a") != a || svc.effectCount("b") != b {
		t.Fatalf("effects a=%d b=%d, want a=%d b=%d", svc.effectCount("a"), svc.effectCount("b"), a, b)
	}
}

// B7, engine: the agent resubmits the not-done send as b, which waits
// for approval. While b is pending or authorized, a is not offered and
// the owner's RETRY of a is refused, also after a restart; b then goes,
// and the effect happens once.
func TestOP2NotDoneIsNotResentWhileAResubmissionWaits(t *testing.T) {
	svc, st, p, e := notDoneOriginal(t)
	must(e.Submit(mailSend("b")))
	superseded(t, e, svc, "b") // pending
	e = mustOpen(t, st, p, svc)
	superseded(t, e, svc, "b") // pending, replayed
	must(e.Authorize(ctx, "b"))
	superseded(t, e, svc, "b") // authorized
	if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != Succeeded {
		t.Fatalf("b: %+v %v", s, err)
	}
	superseded(t, e, svc, "b")
	once(t, svc, 0, 1)
}

// A resubmission that is denied holds nothing back: a is offered again
// and its RETRY sends it.
func TestOP2NotDoneIsOfferedAgainWhenTheResubmissionIsDenied(t *testing.T) {
	svc, _, p, e := notDoneOriginal(t)
	must(e.Submit(mailSend("b")))
	p.revoke("b", true)
	if s := must(e.Authorize(ctx, "b")); s.State != Denied {
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

// B7, the other order: the owner's RETRY of a goes first. A request made
// after that went is a new send (B8, P6): a succeeded rival holds back
// only requests made before it went, so it goes, also after a restart.
// One made before it went cannot go (the narrow window, below), and one
// made while a waited is refused instead of a (the first order, above).
func TestOP2RequestMadeAfterTheResendWentIsANewSend(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		svc, st, p, e := notDoneOriginal(t)
		if s, err := e.Resend(ctx, "a", 1); err != nil || s.State != Succeeded {
			t.Fatalf("resend of a: %+v %v", s, err)
		}
		must(e.Submit(mailSend("b")))
		must(e.Authorize(ctx, "b"))
		if reopen {
			e = mustOpen(t, st, p, svc)
		}
		if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != Succeeded {
			t.Fatalf("b: %+v %v", s, err)
		}
		once(t, svc, 1, 1)
	}
}

// The narrow window: a resubmission made while the owner's resend of a
// is unresolved is held behind it, and refused once a check finds that
// the resend went.
func TestOP2ResubmissionDuringTheResendIsRefusedWhenTheResendWent(t *testing.T) {
	svc, _, _, e := notDoneOriginal(t)
	svc.mu.Lock()
	svc.mode = func(key string) execMode {
		switch key {
		case AttemptKey("a", 1):
			return modeTimeout
		case AttemptKey("a", 2):
			return modeDropAck
		}
		return modeOK
	}
	svc.mu.Unlock()
	if s, err := e.Resend(ctx, "a", 1); err != nil || s.State != OutcomeUnknown {
		t.Fatalf("resend of a: %+v %v", s, err)
	}
	must(e.Submit(mailSend("b")))
	must(e.Authorize(ctx, "b"))
	var held *HeldError
	if _, err := e.Dispatch(ctx, "b"); !errors.As(err, &held) || held.BlockedBy != "a" {
		t.Fatalf("b while a's resend is unknown: %v", err)
	}
	e.Reconcile(ctx)
	if s := must(e.Get("a")); s.State != Succeeded {
		t.Fatalf("a: %+v", s)
	}
	_, err := e.Dispatch(ctx, "b")
	refusedAs(t, err, "b", "a")
	once(t, svc, 1, 0)
}

// R7: the guest repeats request a (Dispatch of a not-done intent) after
// its resubmission b went. Dispatch passes the same check as Resend: a is
// refused and denied, also after a restart.
func TestOP2RepeatedRequestIsRefusedAfterTheResubmissionWent(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		svc, st, p, e := notDoneOriginal(t)
		must(e.Submit(mailSend("b")))
		must(e.Authorize(ctx, "b"))
		if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != Succeeded {
			t.Fatalf("b: %+v %v", s, err)
		}
		if reopen {
			e = mustOpen(t, st, p, svc)
		}
		s, err := e.Dispatch(ctx, "a")
		refusedAs(t, err, "a", "b")
		if s.State != Denied || s.Permission.GuestReason != supersededGuest {
			t.Fatalf("a: %+v", s)
		}
		once(t, svc, 0, 1)
	}
}

// R8: a resubmission the service itself refuses (not_applied from the
// executor) does not hide a: it is offered again and its RETRY sends it,
// after which the resubmission cannot go.
func TestOP2NotDoneIsOfferedAgainWhenTheServiceRefusesTheResubmission(t *testing.T) {
	svc, _, _, e := notDoneOriginal(t)
	svc.mu.Lock()
	svc.mode = func(key string) execMode {
		switch key {
		case AttemptKey("a", 1):
			return modeTimeout
		case AttemptKey("b", 1):
			return modeRefuse
		}
		return modeOK
	}
	svc.mu.Unlock()
	must(e.Submit(mailSend("b")))
	must(e.Authorize(ctx, "b"))
	if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != NotApplied {
		t.Fatalf("b: %+v %v", s, err)
	}
	if ns := e.NotResent(); len(ns) != 1 || ns[0].Intent.ID != "a" {
		t.Fatalf("a hidden by a resubmission that did not go: %+v", ns)
	}
	if s, err := e.Resend(ctx, "a", 1); err != nil || s.State != Succeeded {
		t.Fatalf("resend of a: %+v %v", s, err)
	}
	_, err := e.Dispatch(ctx, "b")
	refusedAs(t, err, "b", "a")
	once(t, svc, 1, 0)
}

// R10: a resubmission that went and was then erased (CAP-3) still
// supersedes a, also after the restart that rewrites the journal.
func TestOP2ErasedResubmissionStillSupersedes(t *testing.T) {
	svc, st, p, e := notDoneOriginal(t)
	must(e.Submit(mailSend("b")))
	must(e.Authorize(ctx, "b"))
	if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != Succeeded {
		t.Fatalf("b: %+v %v", s, err)
	}
	if er, _, err := e.Erase([]string{"b"}); err != nil || len(er) != 1 {
		t.Fatalf("erase: %v %v", er, err)
	}
	superseded(t, e, svc, "b")
	e = mustOpen(t, st, p, svc)
	superseded(t, e, svc, "b")
	_, err := e.Dispatch(ctx, "a")
	refusedAs(t, err, "a", "b")
	once(t, svc, 0, 1)
}

// A resubmission whose outcome was unknown and that a check then found
// went supersedes a, after a restart too.
func TestOP2UnknownResubmissionThatWentSupersedes(t *testing.T) {
	svc, st, p, e := notDoneOriginal(t)
	svc.mu.Lock()
	svc.mode = func(key string) execMode {
		switch key {
		case AttemptKey("a", 1):
			return modeTimeout
		case AttemptKey("b", 1):
			return modeDropAck
		}
		return modeOK
	}
	svc.mu.Unlock()
	must(e.Submit(mailSend("b")))
	must(e.Authorize(ctx, "b"))
	if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != OutcomeUnknown {
		t.Fatalf("b: %+v %v", s, err)
	}
	superseded(t, e, svc, "b")
	e.Reconcile(ctx)
	if s := must(e.Get("b")); s.State != Succeeded {
		t.Fatalf("b: %+v", s)
	}
	e = mustOpen(t, st, p, svc)
	superseded(t, e, svc, "b")
	once(t, svc, 0, 1)
}

// The same effect resubmitted while the original's outcome was still
// unknown, before any check: once a check proves the original not done,
// the waiting resubmission holds back its redispatch, and goes itself.
func TestOP2ResubmissionMadeWhileUnknownWinsOverTheRedispatch(t *testing.T) {
	svc := notDoneService()
	svc.knows = func(string) bool { return false }
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	must(e.Submit(mailSend("a")))
	must(e.Authorize(ctx, "a"))
	if s, _ := e.Dispatch(ctx, "a"); s.State != OutcomeUnknown {
		t.Fatalf("a: %+v", s)
	}
	must(e.Submit(mailSend("b")))
	must(e.Authorize(ctx, "b"))
	var held *HeldError
	if _, err := e.Dispatch(ctx, "b"); !errors.As(err, &held) || held.BlockedBy != "a" {
		t.Fatalf("b while a is unknown: %v", err)
	}
	svc.mu.Lock()
	svc.knows = func(string) bool { return true }
	svc.mu.Unlock()
	rep := e.Reconcile(ctx)
	if len(rep.Resolved) != 1 || len(rep.Redispatched) != 0 {
		t.Fatalf("report %+v", rep)
	}
	if ns := e.NotResent(); len(ns) != 0 {
		t.Fatalf("a offered while b waits: %+v", ns)
	}
	if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != Succeeded {
		t.Fatalf("b: %+v %v", s, err)
	}
	_, err := e.Resend(ctx, "a", 1)
	refusedAs(t, err, "a", "b")
	once(t, svc, 0, 1)
}

// Two resubmissions of a not-done effect, both waiting for approval: the
// one dispatched first goes, and the other is refused. Neither holds the
// other back while both wait.
func TestOP2OfTwoResubmissionsTheFirstDispatchedGoes(t *testing.T) {
	svc, _, _, e := notDoneOriginal(t)
	must(e.Submit(mailSend("b")))
	c := mailSend("c")
	must(e.Submit(c))
	must(e.Authorize(ctx, "c"))
	must(e.Authorize(ctx, "b"))
	if s, err := e.Dispatch(ctx, "c"); err != nil || s.State != Succeeded {
		t.Fatalf("c: %+v %v", s, err)
	}
	_, err := e.Dispatch(ctx, "b")
	refusedAs(t, err, "b", "c")
	_, err = e.Resend(ctx, "a", 1)
	refusedAs(t, err, "a", "c")
	if n := svc.effectCount("a") + svc.effectCount("b") + svc.effectCount("c"); n != 1 {
		t.Fatalf("effect applied %d times", n)
	}
}

// R11: the owner's RETRY of a parked resubmission b is not held back by
// another resubmission c that waits for approval: c is itself held behind
// b while b's outcome is unknown, so refusing the retry would leave both
// waiting for each other. The retry goes; c, made before b went, is then
// refused and denied, and the effect goes once.
func TestOP2RetryOfAParkedResubmissionGoesBeforeAWaitingOne(t *testing.T) {
	svc, _, _, e := notDoneOriginal(t)
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
	if s, _ := e.Dispatch(ctx, "b"); s.State != OutcomeUnknown {
		t.Fatalf("b: %+v", s)
	}
	for i := 0; i < parkAfter; i++ {
		e.Reconcile(ctx)
	}
	if ps := e.Parked(); len(ps) != 1 || ps[0].Intent.ID != "b" {
		t.Fatalf("parked %+v", ps)
	}
	must(e.Submit(mailSend("c")))
	must(e.Authorize(ctx, "c"))
	var held *HeldError
	if _, err := e.Dispatch(ctx, "c"); !errors.As(err, &held) || held.BlockedBy != "b" {
		t.Fatalf("c while b is parked: %v", err)
	}
	if s, err := e.Retry(ctx, "b", 1); err != nil || s.State != Succeeded {
		t.Fatalf("retry of b: %+v %v", s, err)
	}
	s, err := e.Dispatch(ctx, "c")
	refusedAs(t, err, "c", "b")
	if s.State != Denied {
		t.Fatalf("c: %+v", s)
	}
	if n := svc.effectCount("a") + svc.effectCount("b") + svc.effectCount("c"); n != 1 {
		t.Fatalf("effect applied %d times", n)
	}
}

// Concurrent paths: the owner's RETRY of a and the dispatch of its
// resubmission b race; the effect goes at most once, and the loser is
// refused rather than held to go later.
func TestOP2ConcurrentResendAndResubmissionGoOnce(t *testing.T) {
	for i := 0; i < 100; i++ {
		svc, _, _, e := notDoneOriginal(t)
		must(e.Submit(mailSend("b")))
		must(e.Authorize(ctx, "b"))
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = e.Resend(ctx, "a", 1) }()
		go func() { defer wg.Done(); _, _ = e.Dispatch(ctx, "b") }()
		wg.Wait()
		_, _ = e.Dispatch(ctx, "b")
		_, _ = e.Resend(ctx, "a", 1)
		if n := svc.effectCount("a") + svc.effectCount("b"); n != 1 {
			t.Fatalf("iteration %d: effect applied %d times", i, n)
		}
	}
}

// Two intents with the same effect both proved not done: concurrent
// RETRYs of both send it once.
func TestOP2ConcurrentResendsOfTwoNotDoneGoOnce(t *testing.T) {
	for i := 0; i < 100; i++ {
		svc, _, p, e := notDoneOriginal(t)
		svc.mu.Lock()
		svc.mode = func(key string) execMode {
			if key == AttemptKey("a", 1) || key == AttemptKey("b", 1) {
				return modeTimeout
			}
			return modeOK
		}
		svc.mu.Unlock()
		must(e.Submit(mailSend("b")))
		must(e.Authorize(ctx, "b"))
		if s, _ := e.Dispatch(ctx, "b"); s.State != OutcomeUnknown {
			t.Fatalf("b: %+v", s)
		}
		p.revoke("b", true)
		e.Reconcile(ctx)
		p.revoke("b", false)
		if ns := e.NotResent(); len(ns) != 2 {
			t.Fatalf("not resent %+v", ns)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = e.Resend(ctx, "a", 1) }()
		go func() { defer wg.Done(); _, _ = e.Resend(ctx, "b", 1) }()
		wg.Wait()
		if n := svc.effectCount("a") + svc.effectCount("b"); n != 1 {
			t.Fatalf("iteration %d: effect applied %d times", i, n)
		}
	}
}

// Two identical requests both made before either was dispatched are two
// sends, as before: the first being proved not done does not make the
// other a resubmission of it, and both go.
func TestOP2RequestsMadeBeforeTheFirstWasTriedStaySeparate(t *testing.T) {
	svc := notDoneService()
	cs := &crashStore{MemStore: &MemStore{}, budget: 5}
	e := mustOpen(t, cs, newPolicy(), svc)
	must(e.Submit(mailSend("a")))
	must(e.Submit(mailSend("x")))
	must(e.Authorize(ctx, "a"))
	must(e.Authorize(ctx, "x"))
	_, _ = e.Dispatch(ctx, "a")
	if !cs.crashed {
		t.Fatal("not killed between a's intent and outcome")
	}
	p := newPolicy()
	e = mustOpen(t, cs.MemStore, p, svc)
	p.revoke("a", true)
	refusedResend(t, e, e.Reconcile(ctx), svc, 1)
	p.revoke("a", false)
	if s, err := e.Dispatch(ctx, "x"); err != nil || s.State != Succeeded {
		t.Fatalf("x: %+v %v", s, err)
	}
	if s, err := e.Resend(ctx, "a", 1); err != nil || s.State != Succeeded {
		t.Fatalf("resend of a: %+v %v", s, err)
	}
	if svc.effectCount("a") != 1 || svc.effectCount("x") != 1 {
		t.Fatalf("effects a=%d x=%d", svc.effectCount("a"), svc.effectCount("x"))
	}
}

// A request the service itself refused (not_applied from the executor)
// is proof too: the agent resubmits it as b, which goes, and a repeat of
// the refused request is then refused rather than sent again.
func TestOP2RepeatOfARefusedRequestIsRefusedAfterItsResubmissionWent(t *testing.T) {
	svc := newService()
	svc.mode = func(key string) execMode {
		if key == AttemptKey("a", 1) {
			return modeRefuse
		}
		return modeOK
	}
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	must(e.Submit(mailSend("a")))
	must(e.Authorize(ctx, "a"))
	if s, _ := e.Dispatch(ctx, "a"); s.State != NotApplied {
		t.Fatalf("a: %+v", s)
	}
	must(e.Submit(mailSend("b")))
	must(e.Authorize(ctx, "b"))
	if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != Succeeded {
		t.Fatalf("b: %+v %v", s, err)
	}
	_, err := e.Dispatch(ctx, "a")
	refusedAs(t, err, "a", "b")
	once(t, svc, 0, 1)
}
