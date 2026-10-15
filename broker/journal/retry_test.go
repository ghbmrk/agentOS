package journal

import (
	"errors"
	"testing"
	"time"
)

// REQ: OP-2, OP-3, OP-4

// keyExecOf is a key executor whose answers the test sets: whether the
// service honours the key, and for how long it remembers it.
type keyExecOf struct {
	plainExec
	honours bool
	life    time.Duration
}

func (k keyExecOf) HonoursKey(Intent) bool           { return k.honours }
func (k keyExecOf) KeyLifetime(Intent) time.Duration { return k.life }

// executesOnlyKey fails unless every execute svc saw used key.
func executesOnlyKey(t *testing.T, svc *fakeService, key string) {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	for _, k := range svc.executes {
		if k != key {
			t.Fatalf("executes %v: %s is not %s", svc.executes, k, key)
		}
	}
}

// An executor that implements KeyHonouring but says its service does not
// honour the key gets no second call: the effect parks.
func TestOP2KeyRetryNeedsHonoursKey(t *testing.T) {
	svc := newService()
	svc.knows = func(string) bool { return false }
	st := killedBetween(t, svc, mailSend("a"))
	e := mustOpen(t, st, newPolicy(), keyExecOf{plainExec: plainExec{svc}, honours: false})
	if rep := settle(e); len(rep.Parked) != 1 {
		t.Fatalf("report %+v", rep)
	}
	if svc.executeCount() != 1 || len(recordsOf(t, e, RecDispatched)) != 1 {
		t.Fatalf("executes %v", svc.executes)
	}
}

// A parked attempt is never executed again under its key, even when the
// executor honours the key and the recheck passes again. Three guards
// stand in the way: Reconcile skips parked jobs, keyRetry refuses a parked
// attempt, and validate refuses a key dispatch of one. Each step below
// fails once the guards it reaches are removed: the Reconcile step when
// all three are, the keyRetry step when keyRetry's and validate's are,
// and the commit step when validate's is.
func TestOP2ParkedAttemptIsNeverKeyRetried(t *testing.T) {
	svc := newService()
	svc.knows = func(string) bool { return false }
	st := killedBetween(t, svc, mailSend("a"))
	p := newPolicy()
	exec := keyExecOf{plainExec: plainExec{svc}, honours: true}
	e := mustOpen(t, st, p, exec)
	p.revoke("a", true) // the key retry's recheck refuses, so it parks
	if rep := settle(e); len(rep.Parked) != 1 {
		t.Fatalf("report %+v", rep)
	}
	p.revoke("a", false)

	// Reconcile: checked again, never executed.
	settle(e)
	if svc.executeCount() != 1 || len(e.Parked()) != 1 {
		t.Fatalf("Reconcile key-retried a parked attempt: executes %v", svc.executes)
	}
	// keyRetry on its own.
	if out, _ := e.keyRetry(ctx, "a", 1, exec); out.Result != ResultUnknown || svc.executeCount() != 1 {
		t.Fatalf("keyRetry ran a parked attempt: %+v, executes %v", out, svc.executes)
	}
	// validate on its own.
	e.mu.Lock()
	err := e.commit(Record{Type: RecDispatched, ID: "a", Attempt: 1, Source: DispatchKey})
	e.mu.Unlock()
	if !errors.Is(err, ErrState) {
		t.Fatalf("key dispatch of a parked attempt committed: %v", err)
	}
	if d := recordsOf(t, e, RecDispatched); len(d) != 1 {
		t.Fatalf("dispatch records %+v", d)
	}
}

// A same-key retry is made only within the key's lifetime from the
// attempt's first dispatch: the executor's, or DefaultKeyLifetime.
func TestOP2KeyRetryWithinTheKeyLifetime(t *testing.T) {
	for _, tc := range []struct {
		name  string
		life  time.Duration
		after time.Duration
		retry bool
	}{
		{"default, within", 0, 23 * time.Hour, true},
		{"default, past", 0, 25 * time.Hour, false},
		{"executor's, within", time.Hour, 50 * time.Minute, true},
		{"executor's, past", time.Hour, 2 * time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newService()
			svc.knows = func(string) bool { return false }
			st := killedBetween(t, svc, mailSend("a"))
			later := time.Now().Add(tc.after)
			e, err := Open(st, newPolicy(), map[string]Executor{"svc": keyExecOf{plainExec: plainExec{svc}, honours: true, life: tc.life}},
				testRedact, WithClock(func() time.Time { return later }))
			if err != nil {
				t.Fatal(err)
			}
			rep := e.Reconcile(ctx)
			retried := svc.executeCount() == 2
			if retried != tc.retry {
				t.Fatalf("retried %v, want %v: report %+v, executes %v", retried, tc.retry, rep, svc.executes)
			}
			executesOnlyKey(t, svc, AttemptKey("a", 1))
			if !tc.retry && len(rep.Resolved) != 0 {
				t.Fatalf("report %+v", rep)
			}
		})
	}
}

// The broker is killed during an owner retry, between the retry's
// dispatch record and its outcome. On restart attempt 2 is unknown and
// fences the account; when no check settles it, attempt 2 is parked, and
// an approval of the old request (attempt 1) retries nothing.
func TestOP2KilledDuringOwnerRetry(t *testing.T) {
	_, st, _, svc := parkedMail(t)
	cs := &crashStore{MemStore: st, budget: 1}
	e1 := mustOpen(t, cs, newPolicy(), svc)
	if _, err := e1.Retry(ctx, "a", 1); err == nil || !cs.crashed {
		t.Fatalf("not killed during the retry: %v", err)
	}
	if svc.executeCount() != 2 || !svc.wasApplied("a", 2) {
		t.Fatalf("executes %v", svc.executes)
	}

	e2 := mustOpen(t, st, newPolicy(), svc)
	if s := must(e2.Get("a")); s.State != OutcomeUnknown || len(s.Attempts) != 2 || s.Attempts[1].Parked {
		t.Fatalf("after restart: %+v", s)
	}
	if f := e2.Fenced("mail"); len(f) != 1 || f[0] != "a" {
		t.Fatalf("fenced %v", f)
	}
	if rep := settle(e2); len(rep.Parked) != 1 {
		t.Fatalf("report %+v", rep)
	}
	if p := e2.Parked(); len(p) != 1 || p[0].Attempt != 2 {
		t.Fatalf("parked %+v", p)
	}
	if _, err := e2.Retry(ctx, "a", 1); !errors.Is(err, ErrState) {
		t.Fatalf("stale retry of attempt 1: %v", err)
	}
	if svc.executeCount() != 2 {
		t.Fatalf("executes %v", svc.executes)
	}
}

// The broker is killed during a key retry. On restart the same key is
// the only one executed again, and when nothing settles it the effect
// parks: no new attempt, no new key.
func TestOP2KilledDuringKeyRetry(t *testing.T) {
	svc := newService()
	svc.knows = func(string) bool { return false }
	svc.mode = func(string) execMode { return modeTimeout }
	exec := keyExecOf{plainExec: plainExec{svc}, honours: true}
	st := killedBetween(t, svc, mailSend("a"))

	// Opening journals attempt 1 as unknown; the key retry's dispatch
	// record is the second append, and its outcome is lost.
	cs := &crashStore{MemStore: st, budget: 2}
	e1 := mustOpen(t, cs, newPolicy(), exec)
	e1.Reconcile(ctx)
	if !cs.crashed || svc.executeCount() != 2 {
		t.Fatalf("not killed during the key retry: crashed %v, executes %v", cs.crashed, svc.executes)
	}

	e2 := mustOpen(t, st, newPolicy(), exec)
	if rep := settle(e2); len(rep.Parked) != 1 {
		t.Fatalf("report %+v", rep)
	}
	executesOnlyKey(t, svc, AttemptKey("a", 1))
	if s := must(e2.Get("a")); len(s.Attempts) != 1 || !s.Attempts[0].Parked {
		t.Fatalf("a: %+v", s)
	}
	if svc.effectCount("a") > 1 {
		t.Fatalf("effects %d", svc.effectCount("a"))
	}
}

// A check that proves the effect was not done dispatches it again, under
// the dispatch recheck: a refused recheck journals nothing and leaves the
// intent not_applied, not denied.
func TestOP2RedispatchNeedsTheRecheck(t *testing.T) {
	svc := newService()
	svc.mode = func(key string) execMode {
		if key == AttemptKey("a", 1) {
			return modeTimeout
		}
		return modeOK
	}
	st := killedBetween(t, svc, mailSend("a"))
	p := newPolicy()
	e := mustOpen(t, st, p, svc)
	p.revoke("a", true)
	rep := settle(e)
	if len(rep.Resolved) != 1 || len(rep.Redispatched) != 0 {
		t.Fatalf("report %+v", rep)
	}
	if s := must(e.Get("a")); s.State != NotApplied || len(s.Attempts) != 1 {
		t.Fatalf("a: %+v", s)
	}
	if svc.executeCount() != 1 || len(recordsOf(t, e, RecRecheckFailed)) != 0 {
		t.Fatalf("executes %v", svc.executes)
	}
}

// A redispatch after restart keeps the account's restart fence until it
// ends, so newer work on the account cannot run ahead of it.
func TestOP2RedispatchKeepsTheRestartFence(t *testing.T) {
	svc := newService()
	svc.mode = func(key string) execMode {
		if key == AttemptKey("a", 1) {
			return modeTimeout
		}
		return modeOK
	}
	st := killedBetween(t, svc, mailSend("a"))
	e := mustOpen(t, st, newPolicy(), svc)
	var during []string
	svc.onExecute = func(in Intent, attempt int) { during = e.Fenced("mail") }
	if rep := settle(e); len(rep.Redispatched) != 1 {
		t.Fatalf("report %+v", rep)
	}
	if len(during) != 1 || during[0] != "a" {
		t.Fatalf("fenced during the redispatch: %v", during)
	}
	if f := e.Fenced("mail"); len(f) != 0 {
		t.Fatalf("fenced after: %v", f)
	}
	if s := must(e.Get("a")); s.State != Succeeded || len(s.Attempts) != 2 {
		t.Fatalf("a: %+v", s)
	}
}
