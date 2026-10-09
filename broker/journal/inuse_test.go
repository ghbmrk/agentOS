package journal

import (
	"sync"
	"testing"
	"time"
)

// REQ: ADP-9, OP-2, OP-3, OP-4

// clock is a synthetic clock tests advance by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func openAt(t *testing.T, st Store, c *clock, svc *fakeService) *Engine {
	t.Helper()
	e, err := Open(st, newPolicy(), map[string]Executor{"svc": svc}, testRedact, WithClock(c.now))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return e
}

// uses maps each intent holding a place in the window ending now to
// whether it has started.
func uses(e *Engine, c *clock) map[string]bool {
	out := map[string]bool{}
	for _, u := range e.InUse("acct", "send", c.now().Add(-24*time.Hour)) {
		out[u.Intent.ID] = u.Started
	}
	return out
}

// TestInUseChargesDispatchNotAuthorization (SR3-2, F2): a queued intent
// holds its place until it starts, whatever its age, and a started one is
// charged to the window it started in. Authorization time alone never
// lets an old queued intent fall out of the bound.
func TestInUseChargesDispatchNotAuthorization(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	e := openAt(t, &MemStore{}, c, newService())
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	if _, err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	c.advance(48 * time.Hour)
	if got := uses(e, c); len(got) != 1 || got["a"] {
		t.Fatalf("a queued intent two days old: %v, want a reserved place", got)
	}
	// The pre-SR3-2 query lost it.
	if n := len(e.AuthorizedSince("acct", "send", c.now().Add(-24*time.Hour))); n != 0 {
		t.Fatalf("AuthorizedSince counted %d", n)
	}
	if err := e.Resume(); err != nil {
		t.Fatal(err)
	}
	must(e.Dispatch(ctx, "a"))
	if got := uses(e, c); len(got) != 1 || !got["a"] {
		t.Fatalf("after dispatch: %v, want a started", got)
	}
	// Window boundary: charged through exactly 24h after the start, not after.
	c.advance(24 * time.Hour)
	if got := uses(e, c); !got["a"] {
		t.Fatalf("at the boundary: %v", got)
	}
	c.advance(time.Nanosecond)
	if got := uses(e, c); len(got) != 0 {
		t.Fatalf("past the window: %v", got)
	}
}

// TestInUseReleasesOnlyOnEvidenceOfNoEffect (SR3-2): an attempt in
// flight or with an unknown outcome stays charged until evidence resolves
// it, however long that takes (OP-2). A confirmed not_applied releases
// the place; a retry is charged once, when it starts; a denial at the
// recheck (a cancelled queued intent) releases its reservation.
func TestInUseReleasesOnlyOnEvidenceOfNoEffect(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	svc := newService()
	mode := map[string]execMode{"u#1": modeTimeout, "r#1": modeRefuse, "s#1": modeDropAck}
	svc.mode = func(k string) execMode { return mode[k] }
	pol := newPolicy()
	e, err := Open(&MemStore{}, pol, map[string]Executor{"svc": svc}, testRedact, WithClock(c.now))
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"u", "r", "s", "d"} {
		in := intent(id, "acct")
		in.Params["n"] = i // distinct effects, so none is held behind another (OP-2)
		must(e.Submit(in))
		must(e.Authorize(ctx, id))
	}
	for _, id := range []string{"u", "r", "s"} {
		must(e.Dispatch(ctx, id))
	}
	got := uses(e, c)
	if !got["u"] || !got["s"] || got["d"] || len(got) != 3 {
		t.Fatalf("after dispatch: %v, want u and s started, d reserved, r released", got)
	}
	if _, ok := got["r"]; ok {
		t.Fatal("not_applied still holds a place")
	}

	// Cancelled before it started: refused at the recheck, released.
	pol.revoke("d", true)
	if _, err := e.Dispatch(ctx, "d"); err == nil {
		t.Fatal("d dispatched after revoke")
	}

	// Unknown outcomes outlive the window until resolved.
	c.advance(72 * time.Hour)
	got = uses(e, c)
	if len(got) != 2 || !got["u"] || !got["s"] {
		t.Fatalf("unresolved after three days: %v", got)
	}
	must(e.Resolve("u", 1, Outcome{Result: ResultNotApplied, Evidence: "no record"}, "owner"))
	must(e.Resolve("s", 1, Outcome{Result: ResultSucceeded, Evidence: "found"}, "owner"))
	// Resolved as an effect: charged to the window it started in, long gone.
	if got := uses(e, c); len(got) != 0 {
		t.Fatalf("after resolving: %v", got)
	}

	// A retry of the not-applied attempt is charged once, as it starts.
	mode["r#2"] = modeOK
	must(e.Dispatch(ctx, "r"))
	if got := uses(e, c); len(got) != 1 || !got["r"] {
		t.Fatalf("after retry: %v", got)
	}
	if n := len(e.InUse("acct", "send", time.Time{})); n != 2 {
		t.Fatalf("all time: %d uses, want r and s once each", n)
	}
}

// TestInUseSurvivesRestartBetweenReservationAndExecution (SR3-2, OP-4): a
// dispatch journaled before a crash, with the executor not yet returned,
// is replayed as started and stays charged until reconciled.
func TestInUseSurvivesRestartBetweenReservationAndExecution(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	st := &MemStore{}
	svc := newService()
	var snap []byte
	svc.onExecute = func(Intent, int) { snap, _ = st.ReadAll() }
	e := openAt(t, st, c, svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	must(e.Dispatch(ctx, "a"))

	crashed := &MemStore{}
	if err := crashed.Rewrite(snap); err != nil {
		t.Fatal(err)
	}
	c.advance(48 * time.Hour)
	e2 := openAt(t, crashed, c, newService())
	if got := uses(e2, c); len(got) != 1 || !got["a"] {
		t.Fatalf("after restart: %v, want a started", got)
	}
}
