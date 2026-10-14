package journal

import (
	"context"
	"errors"
	"testing"
	"time"
)

// REQ: OP-2, OP-4

// keyExec is an executor whose service honours the attempt's idempotency
// key: executing the same key twice applies the effect once.
type keyExec struct{ plainExec }

func (keyExec) HonoursKey(Intent) bool { return true }

// mailSend and paymentStub are the two OP-2 acceptance effects.
func mailSend(id string) Intent { return intent(id, "mail") }

func paymentStub(id string) Intent {
	in := intent(id, "bank")
	in.Action = "pay"
	in.Params = map[string]any{"amount": 1200, "currency": "GBP", "payee": "synthetic-payee"}
	in.Recipients = nil
	return in
}

// killedBetween runs in through a broker that is killed between the
// intent's dispatch record and its outcome record. The executor has run;
// whether the effect happened is svc's choice (its mode).
func killedBetween(t *testing.T, svc *fakeService, in Intent) *MemStore {
	t.Helper()
	cs := &crashStore{MemStore: &MemStore{}, budget: 3}
	e := mustOpen(t, cs, newPolicy(), svc)
	must(e.Submit(in))
	must(e.Authorize(ctx, in.ID))
	_, _ = e.Dispatch(ctx, in.ID)
	if !cs.crashed || svc.executeCount() != 1 {
		t.Fatalf("not killed between intent and outcome: crashed %v, executes %d", cs.crashed, svc.executeCount())
	}
	return cs.MemStore
}

func settle(e *Engine) ReconcileReport {
	return e.SettleUnknown(ctx, time.Millisecond, time.Millisecond)
}

func recordsOf(t *testing.T, e *Engine, typ RecordType) []Record {
	t.Helper()
	recs, err := e.RecordsAfter(0)
	if err != nil {
		t.Fatal(err)
	}
	var out []Record
	for _, r := range recs {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

// OP-2 acceptance: the broker is killed between intent and outcome, once
// for a mail send and once for a payment stub. The service cannot say what
// happened and honours no key, so the effect is parked for the digest:
// never executed again, the account's fence lifted, a same-effect intent
// still held, and nothing asked of the owner.
func TestOP2KilledBetweenIntentAndOutcomeNeverSendsTwice(t *testing.T) {
	for name, mk := range map[string]func(string) Intent{"mail send": mailSend, "payment stub": paymentStub} {
		t.Run(name, func(t *testing.T) {
			svc := newService()
			svc.knows = func(string) bool { return false }
			in := mk("a")
			st := killedBetween(t, svc, in)
			e := mustOpen(t, st, newPolicy(), svc)
			if got := e.Fenced(in.Account); len(got) != 1 {
				t.Fatalf("fence after restart = %v", got)
			}
			rep := settle(e)
			if len(rep.Unresolved) != 0 || len(rep.Parked) != 1 || rep.Parked[0] != "a" {
				t.Fatalf("report %+v", rep)
			}
			if svc.executeCount() != 1 || svc.effectCount("a") != 1 {
				t.Fatalf("executes %d, effects %d: the effect ran again", svc.executeCount(), svc.effectCount("a"))
			}
			if s := must(e.Get("a")); s.State != OutcomeUnknown || !s.Attempts[0].Parked {
				t.Fatalf("a is %s, attempts %+v", s.State, s.Attempts)
			}
			if got := e.Fenced(in.Account); len(got) != 0 {
				t.Fatalf("still fenced after parking: %v", got)
			}
			p := e.Parked()
			if len(p) != 1 || p[0].Intent.ID != "a" || p[0].Attempt != 1 || p[0].Dispatched.IsZero() {
				t.Fatalf("parked = %+v", p)
			}

			// The same effect under a new ID is held: no double send.
			dup := mk("a2")
			must(e.Submit(dup))
			must(e.Authorize(ctx, "a2"))
			var held *HeldError
			if _, err := e.Dispatch(ctx, "a2"); !errors.As(err, &held) || held.BlockedBy != "a" {
				t.Fatalf("same effect dispatched: %v", err)
			}
			// A different effect on the account runs.
			other := mk("b")
			other.Params = map[string]any{"subject": "other"}
			must(e.Submit(other))
			must(e.Authorize(ctx, "b"))
			if s, err := e.Dispatch(ctx, "b"); err != nil || s.State != Succeeded {
				t.Fatalf("other effect: %+v, %v", s, err)
			}

			// Parking survives a restart: no fence, no execute.
			e2 := mustOpen(t, st, newPolicy(), svc)
			if got := e2.Fenced(in.Account); len(got) != 0 {
				t.Fatalf("fenced again after restart: %v", got)
			}
			if p := e2.Parked(); len(p) != 1 || p[0].Intent.ID != "a" {
				t.Fatalf("parked after restart = %+v", p)
			}
			settle(e2)
			if svc.effectCount("a") != 1 || svc.wasApplied("a", 2) {
				t.Fatal("the effect ran again after a restart")
			}
		})
	}
}

// When the check through the same tool proves the effect was not done,
// the intent becomes not_applied and the engine dispatches one new attempt
// under the dispatch recheck (OP-2 step 2): one effect.
func TestOP2CheckProvesNotDoneThenOneEffect(t *testing.T) {
	for name, mk := range map[string]func(string) Intent{"mail send": mailSend, "payment stub": paymentStub} {
		t.Run(name, func(t *testing.T) {
			svc := newService()
			svc.mode = func(key string) execMode {
				if key == AttemptKey("a", 1) {
					return modeTimeout
				}
				return modeOK
			}
			st := killedBetween(t, svc, mk("a"))
			e := mustOpen(t, st, newPolicy(), svc)
			if rep := settle(e); len(rep.Resolved) != 1 || len(rep.Parked) != 0 || len(rep.Redispatched) != 1 {
				t.Fatalf("report %+v", rep)
			}
			if s := must(e.Get("a")); s.State != Succeeded || len(s.Attempts) != 2 || s.Attempts[1].Source != "executor" {
				t.Fatalf("a is %s, attempts %+v", s.State, s.Attempts)
			}
			if svc.executeCount() != 2 || !svc.wasApplied("a", 2) {
				t.Fatalf("executes %d", svc.executeCount())
			}
			if svc.effectCount("a") != 1 {
				t.Fatalf("effects %d", svc.effectCount("a"))
			}
		})
	}
}

// When the service honours the idempotency key, an unclear attempt is
// retried with the same key, so the service applies it at most once.
func TestOP2KeyRetryReusesTheKey(t *testing.T) {
	for name, effectDone := range map[string]bool{"effect done": true, "effect not done": false} {
		t.Run(name, func(t *testing.T) {
			svc := newService()
			svc.knows = func(string) bool { return false }
			first := true
			svc.mode = func(string) execMode {
				if first {
					first = false
					if !effectDone {
						return modeTimeout
					}
				}
				return modeOK
			}
			st := killedBetween(t, svc, paymentStub("a"))
			e := mustOpen(t, st, newPolicy(), keyExec{plainExec{svc}})
			rep := settle(e)
			if len(rep.Resolved) != 1 || len(rep.Parked) != 0 {
				t.Fatalf("report %+v", rep)
			}
			s := must(e.Get("a"))
			if s.State != Succeeded || len(s.Attempts) != 1 {
				t.Fatalf("a is %s with %d attempts", s.State, len(s.Attempts))
			}
			if svc.effectCount("a") != 1 || svc.executeCount() != 2 || svc.executes[1] != AttemptKey("a", 1) {
				t.Fatalf("effects %d, executes %v", svc.effectCount("a"), svc.executes)
			}
			d := recordsOf(t, e, RecDispatched)
			if len(d) != 2 || d[1].Source != DispatchKey || d[1].Attempt != 1 {
				t.Fatalf("dispatch records %+v", d)
			}
			if got := e.Fenced("bank"); len(got) != 0 {
				t.Fatalf("fence = %v", got)
			}
			// Replay reaches the same state.
			e2 := mustOpen(t, st, newPolicy(), keyExec{plainExec{svc}})
			if s := must(e2.Get("a")); s.State != Succeeded {
				t.Fatalf("after replay a is %s", s.State)
			}
		})
	}
}

// A key retry is a dispatch: it passes the recheck (OP-3) and STOP, and
// when either refuses it, the effect is parked, not retried.
func TestOP2KeyRetryNeedsTheRecheckAndNoStop(t *testing.T) {
	for _, name := range []string{"revoked", "stopped"} {
		t.Run(name, func(t *testing.T) {
			svc := newService()
			svc.knows = func(string) bool { return false }
			st := killedBetween(t, svc, mailSend("a"))
			p := newPolicy()
			e := mustOpen(t, st, p, keyExec{plainExec{svc}})
			if name == "revoked" {
				p.revoke("a", true)
			} else if _, err := e.Stop(ctx); err != nil {
				t.Fatal(err)
			}
			rep := settle(e)
			if len(rep.Parked) != 1 || svc.executeCount() != 1 {
				t.Fatalf("report %+v, executes %d", rep, svc.executeCount())
			}
			if d := recordsOf(t, e, RecDispatched); len(d) != 1 {
				t.Fatalf("dispatch records %+v", d)
			}
		})
	}
}

// parkedMail returns an engine with mail send "a" parked.
func parkedMail(t *testing.T) (*Engine, *MemStore, *testPolicy, *fakeService) {
	t.Helper()
	svc := newService()
	svc.knows = func(string) bool { return false }
	st := killedBetween(t, svc, mailSend("a"))
	p := newPolicy()
	e := mustOpen(t, st, p, svc)
	if rep := settle(e); len(rep.Parked) != 1 {
		t.Fatalf("report %+v", rep)
	}
	return e, st, p, svc
}

// The owner may retry a parked effect (OP-2c): a new attempt with a new
// key, which the owner accepted may duplicate.
func TestOP2OwnerRetryOfAParkedEffect(t *testing.T) {
	e, st, _, svc := parkedMail(t)
	s, err := e.Retry(ctx, "a", 1)
	if err != nil || s.State != Succeeded || len(s.Attempts) != 2 {
		t.Fatalf("retry: %+v, %v", s, err)
	}
	if !svc.wasApplied("a", 2) || svc.executeCount() != 2 {
		t.Fatalf("executes %v", svc.executes)
	}
	d := recordsOf(t, e, RecDispatched)
	if len(d) != 2 || d[1].Source != DispatchOwner || d[1].Attempt != 2 {
		t.Fatalf("dispatch records %+v", d)
	}
	if len(e.Parked()) != 0 {
		t.Fatalf("still parked: %+v", e.Parked())
	}
	if _, err := e.Retry(ctx, "a", 1); !errors.Is(err, ErrState) {
		t.Fatalf("second retry: %v", err)
	}
	e2 := mustOpen(t, st, newPolicy(), svc)
	if s := must(e2.Get("a")); s.State != Succeeded || len(s.Attempts) != 2 {
		t.Fatalf("after replay: %+v", s)
	}
}

// An owner retry is refused for an effect not parked, and when the
// recheck or STOP refuses it; a refusal journals nothing.
func TestOP2OwnerRetryRefusals(t *testing.T) {
	t.Run("not parked", func(t *testing.T) {
		svc := newService()
		svc.knows = func(string) bool { return false }
		e := mustOpen(t, killedBetween(t, svc, mailSend("a")), newPolicy(), svc)
		if _, err := e.Retry(ctx, "a", 1); !errors.Is(err, ErrState) {
			t.Fatalf("retry before parking: %v", err)
		}
		if _, err := e.Retry(ctx, "nope", 1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("retry of an unknown ID: %v", err)
		}
		if svc.executeCount() != 1 {
			t.Fatalf("executes %d", svc.executeCount())
		}
	})
	t.Run("stale attempt", func(t *testing.T) {
		e, _, _, svc := parkedMail(t)
		if _, err := e.Retry(ctx, "a", 2); !errors.Is(err, ErrState) {
			t.Fatalf("retry of an attempt not parked: %v", err)
		}
		if svc.executeCount() != 1 || len(e.Parked()) != 1 {
			t.Fatalf("executes %d", svc.executeCount())
		}
	})
	t.Run("revoked", func(t *testing.T) {
		e, _, p, svc := parkedMail(t)
		p.revoke("a", true)
		before := len(recordsOf(t, e, RecParked)) + len(recordsOf(t, e, RecDispatched)) + len(recordsOf(t, e, RecRecheckFailed))
		if _, err := e.Retry(ctx, "a", 1); !errors.Is(err, ErrRecheck) {
			t.Fatalf("retry when revoked: %v", err)
		}
		after := len(recordsOf(t, e, RecParked)) + len(recordsOf(t, e, RecDispatched)) + len(recordsOf(t, e, RecRecheckFailed))
		if before != after || svc.executeCount() != 1 || len(e.Parked()) != 1 {
			t.Fatalf("records %d then %d, executes %d", before, after, svc.executeCount())
		}
	})
	t.Run("stopped", func(t *testing.T) {
		e, _, _, svc := parkedMail(t)
		if _, err := e.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Retry(ctx, "a", 1); !errors.Is(err, ErrStopped) {
			t.Fatalf("retry while stopped: %v", err)
		}
		if svc.executeCount() != 1 {
			t.Fatalf("executes %d", svc.executeCount())
		}
	})
}

// A parked effect is still checked through the same tool; a check that
// later settles it closes it, and nothing runs again.
func TestOP2ParkedEffectSettlesWhenTheCheckCan(t *testing.T) {
	e, _, _, svc := parkedMail(t)
	svc.mu.Lock()
	svc.knows = func(string) bool { return true }
	svc.mu.Unlock()
	rep := settle(e)
	if len(rep.Resolved) != 1 || rep.Resolved[0] != "a" {
		t.Fatalf("report %+v", rep)
	}
	if s := must(e.Get("a")); s.State != Succeeded {
		t.Fatalf("a is %s", s.State)
	}
	if len(e.Parked()) != 0 || svc.executeCount() != 1 {
		t.Fatalf("parked %+v, executes %d", e.Parked(), svc.executeCount())
	}
}

// An effect left unknown during a run (not by a restart) is parked the
// same way, and never retried by the engine.
func TestOP2RuntimeUnknownIsParked(t *testing.T) {
	svc := newService()
	svc.knows = func(string) bool { return false }
	svc.mode = func(string) execMode { return modeDropAck }
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	must(e.Submit(mailSend("a")))
	must(e.Authorize(ctx, "a"))
	if s, _ := e.Dispatch(ctx, "a"); s.State != OutcomeUnknown {
		t.Fatalf("a is %s", s.State)
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if rep := e.SettleUnknown(c, time.Millisecond, time.Millisecond); len(rep.Parked) != 1 {
		t.Fatalf("report %+v", rep)
	}
	if svc.executeCount() != 1 {
		t.Fatalf("executes %d", svc.executeCount())
	}
}
