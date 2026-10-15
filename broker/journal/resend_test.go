package journal

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// REQ: OP-2, OP-3, OP-4

// notDoneService is a service on which attempt 1 of a never takes effect
// and every check can tell; every later attempt of a goes through.
func notDoneService() *fakeService {
	svc := newService()
	svc.mode = func(key string) execMode {
		if key == AttemptKey("a", 1) {
			return modeTimeout
		}
		return modeOK
	}
	return svc
}

// refusedResend checks that the redispatch of a was refused: the check
// settled attempt 1 as not done, nothing ran again, and a is listed as
// not resent, across a restart too, so the owner hears of it (OP-2).
func refusedResend(t *testing.T, e *Engine, rep ReconcileReport, svc *fakeService, executes int) {
	t.Helper()
	if len(rep.Redispatched) != 0 {
		t.Fatalf("redispatched %v; report %+v", rep.Redispatched, rep)
	}
	if s := must(e.Get("a")); s.State != NotApplied || len(s.Attempts) != 1 || s.Attempts[0].Source != SourceReconcile {
		t.Fatalf("a: %+v", s)
	}
	if svc.executeCount() != executes || svc.effectCount("a") != 0 {
		t.Fatalf("executes %v, effects %d", svc.executes, svc.effectCount("a"))
	}
	ns := e.NotResent()
	if len(ns) != 1 || ns[0].Intent.ID != "a" || ns[0].Attempt != 1 || !ns[0].NotDone || ns[0].Dispatched.IsZero() || ns[0].Seq == 0 {
		t.Fatalf("not resent %+v", ns)
	}
	for _, p := range e.Parked() {
		if p.Intent.ID == "a" {
			t.Fatalf("a is parked: %+v", p)
		}
	}
}

// A resend after a check proved the effect was not done is refused while
// STOP is on (validate also refuses it). It is listed as not resent, also
// after a restart; the owner's Resend runs it once STOP is lifted, and
// only once.
func TestOP2RedispatchIsRefusedUnderStop(t *testing.T) {
	svc := notDoneService()
	st := killedBetween(t, svc, mailSend("a"))
	e := mustOpen(t, st, newPolicy(), svc)
	if _, err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	rep := e.Reconcile(ctx)
	if len(rep.Resolved) != 1 {
		t.Fatalf("report %+v", rep)
	}
	refusedResend(t, e, rep, svc, 1)

	e = mustOpen(t, st, newPolicy(), svc)
	refusedResend(t, e, ReconcileReport{}, svc, 1)
	if _, err := e.Resend(ctx, "a", 1); !errors.Is(err, ErrStopped) || svc.executeCount() != 1 {
		t.Fatalf("resend under STOP: %v, executes %v", err, svc.executes)
	}
	if err := e.Resume(); err != nil {
		t.Fatal(err)
	}
	if s, err := e.Resend(ctx, "a", 1); err != nil || s.State != Succeeded || len(s.Attempts) != 2 {
		t.Fatalf("resend: %+v %v", s, err)
	}
	if svc.executeCount() != 2 || svc.effectCount("a") != 1 || len(e.NotResent()) != 0 {
		t.Fatalf("executes %v, effects %d, not resent %+v", svc.executes, svc.effectCount("a"), e.NotResent())
	}
	if _, err := e.Resend(ctx, "a", 1); !errors.Is(err, ErrState) || svc.executeCount() != 2 {
		t.Fatalf("second resend: %v, executes %v", err, svc.executes)
	}
}

// A resend is refused while another intent on the account is still
// unclear after the restart (OP-4), even though validate would let it
// through: the redispatch's own mayDispatch check holds it.
func TestOP2RedispatchWaitsBehindAnotherUnclearIntent(t *testing.T) {
	svc := notDoneService()
	b := mailSend("b")
	b.Params = map[string]any{"subject": "another mail"}
	svc.mode = func(key string) execMode {
		if key == AttemptKey("a", 1) || key == AttemptKey("b", 1) {
			return modeTimeout
		}
		return modeOK
	}
	svc.knows = func(key string) bool { return key != AttemptKey("b", 1) }
	cs := &crashStore{MemStore: &MemStore{}, budget: 1 << 20}
	e0 := mustOpen(t, cs, newPolicy(), svc)
	must(e0.Submit(b))
	must(e0.Authorize(ctx, "b"))
	if s, _ := e0.Dispatch(ctx, "b"); s.State != OutcomeUnknown {
		t.Fatalf("b is %s", s.State)
	}
	must(e0.Submit(mailSend("a")))
	must(e0.Authorize(ctx, "a"))
	cs.budget = 1
	_, _ = e0.Dispatch(ctx, "a")
	if !cs.crashed || svc.executeCount() != 2 {
		t.Fatalf("not killed during a: crashed %v, executes %v", cs.crashed, svc.executes)
	}

	e := mustOpen(t, cs.MemStore, newPolicy(), svc)
	if f := e.Fenced("mail"); len(f) != 2 {
		t.Fatalf("fenced %v", f)
	}
	rep := e.Reconcile(ctx)
	if len(rep.Resolved) != 1 || rep.Resolved[0] != "a" || len(rep.Unresolved) != 1 || rep.Unresolved[0] != "b" {
		t.Fatalf("report %+v", rep)
	}
	refusedResend(t, e, rep, svc, 2)
	if _, err := e.Resend(ctx, "a", 1); !errors.Is(err, ErrUnreconciled) || svc.executeCount() != 2 {
		t.Fatalf("resend behind b: %v, executes %v", err, svc.executes)
	}
}

// spliced is one journal holding the records of each store in turn,
// renumbered: a history the engine's own dispatch checks would not have
// let one broker write, used to test a guard on its own.
func spliced(t *testing.T, stores ...*MemStore) *MemStore {
	t.Helper()
	out := &MemStore{}
	var seq uint64
	for _, st := range stores {
		data, err := st.ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
			r, err := decodeLine(line)
			if err != nil {
				t.Fatal(err)
			}
			seq++
			r.Seq = seq
			enc, err := encodeRecord(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := out.Append(enc); err != nil {
				t.Fatal(err)
			}
		}
	}
	return out
}

// A resend is refused while a same-effect intent under another ID may
// have landed (here d, parked, which no longer fences the account): the
// redispatch's own mayDispatch check holds it, as Dispatch would.
func TestOP2RedispatchWaitsBehindASameEffectIntent(t *testing.T) {
	svc := newService()
	svc.mode = func(key string) execMode {
		if key == AttemptKey("d", 1) {
			return modeTimeout
		}
		return modeOK
	}
	svc.knows = func(key string) bool { return key != AttemptKey("d", 1) }
	first := &MemStore{}
	e0 := mustOpen(t, first, newPolicy(), svc)
	must(e0.Submit(mailSend("d")))
	must(e0.Authorize(ctx, "d"))
	if s, _ := e0.Dispatch(ctx, "d"); s.State != OutcomeUnknown {
		t.Fatalf("d is %s", s.State)
	}
	for i := 0; i < parkAfter; i++ {
		e0.Reconcile(ctx)
	}
	if p := e0.Parked(); len(p) != 1 || p[0].Intent.ID != "d" {
		t.Fatalf("parked %+v", p)
	}
	// a, the same effect, was killed between its dispatch and outcome on
	// a service where it never took effect.
	other := notDoneService()
	second := killedBetween(t, other, mailSend("a"))

	e := mustOpen(t, spliced(t, first, second), newPolicy(), svc)
	if f := e.Fenced("mail"); len(f) != 1 || f[0] != "a" {
		t.Fatalf("fenced %v", f)
	}
	rep := e.Reconcile(ctx)
	if len(rep.Resolved) != 1 || rep.Resolved[0] != "a" {
		t.Fatalf("report %+v", rep)
	}
	refusedResend(t, e, rep, svc, 1)
	var held *HeldError
	if _, err := e.Resend(ctx, "a", 1); !errors.As(err, &held) || held.BlockedBy != "d" || svc.executeCount() != 1 {
		t.Fatalf("resend behind d: %v, executes %v", err, svc.executes)
	}
}

// A resend is an ordinary dispatch, refused by the policy's recheck as
// any other; the effect is then listed, not dropped (OP-2, OP-3).
func TestOP2RefusedRedispatchIsListed(t *testing.T) {
	svc := notDoneService()
	st := killedBetween(t, svc, mailSend("a"))
	p := newPolicy()
	e := mustOpen(t, st, p, svc)
	p.revoke("a", true)
	rep := e.Reconcile(ctx)
	refusedResend(t, e, rep, svc, 1)
	if _, err := e.Resend(ctx, "a", 1); !errors.Is(err, ErrRecheck) || svc.executeCount() != 1 {
		t.Fatalf("resend refused by the recheck: %v, executes %v", err, svc.executes)
	}
	// Only an effect a check proved not done is resent or listed: not
	// one the executor itself reported not applied, which its caller
	// still holds, nor an unknown ID.
	x := mailSend("x")
	x.Params = map[string]any{"subject": "refused by the service"}
	svc.mode = func(key string) execMode {
		if key == AttemptKey("x", 1) {
			return modeRefuse
		}
		return modeOK
	}
	p.revoke("a", false)
	must(e.Submit(x))
	must(e.Authorize(ctx, "x"))
	if s, _ := e.Dispatch(ctx, "x"); s.State != NotApplied {
		t.Fatalf("x is %s", s.State)
	}
	if ns := e.NotResent(); len(ns) != 1 || ns[0].Intent.ID != "a" {
		t.Fatalf("not resent %+v", ns)
	}
	if _, err := e.Resend(ctx, "x", 1); !errors.Is(err, ErrState) || svc.executeCount() != 2 {
		t.Fatalf("resend of an executor refusal: %v, executes %v", err, svc.executes)
	}
	if _, err := e.Resend(ctx, "nope", 1); err == nil {
		t.Fatal("resent an unknown intent")
	}
}

// A same-key retry trusts the clock only when it is not behind the
// attempt's dispatch or the journal's newest record: a clock that went
// back (an RTC loss at the very restart) parks the effect at once, never
// retrying it under a key the service may have forgotten (OP-2).
func TestOP2KeyRetryNeedsATrustedClock(t *testing.T) {
	for _, tc := range []struct {
		name   string
		newest time.Duration // a record this far from the start, or 0
		now    time.Duration
		retry  bool
	}{
		{"2h behind the dispatch", 0, -2 * time.Hour, false},
		{"72h behind the dispatch", 0, -72 * time.Hour, false},
		{"behind the newest record", 2 * time.Hour, time.Hour, false},
		{"ahead of both", 2 * time.Hour, 3 * time.Hour, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newService()
			svc.knows = func(string) bool { return false }
			start := time.Now()
			st := killedBetween(t, svc, mailSend("a"))
			exec := keyExecOf{plainExec: plainExec{svc}, honours: true, life: 100 * time.Hour}
			if tc.newest != 0 {
				// A broker run at that time journals the unknown outcome.
				newest := start.Add(tc.newest)
				if _, err := Open(st, newPolicy(), map[string]Executor{"svc": exec}, testRedact,
					WithClock(func() time.Time { return newest })); err != nil {
					t.Fatal(err)
				}
			}
			now := start.Add(tc.now)
			e, err := Open(st, newPolicy(), map[string]Executor{"svc": exec}, testRedact, WithClock(func() time.Time { return now }))
			if err != nil {
				t.Fatal(err)
			}
			rep := e.Reconcile(ctx)
			if retried := svc.executeCount() == 2; retried != tc.retry {
				t.Fatalf("retried %v, want %v: report %+v, executes %v", retried, tc.retry, rep, svc.executes)
			}
			executesOnlyKey(t, svc, AttemptKey("a", 1))
			if !tc.retry && (len(rep.Parked) != 1 || len(e.Parked()) != 1) {
				t.Fatalf("not parked at once: report %+v", rep)
			}
		})
	}
}
