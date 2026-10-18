package journal

import (
	"errors"
	"testing"
)

// REQ: CRED-5, OP-11, CRED-RS-1, CRED-RS-4, CRED-RS-5

// CRED-RS-1: a route stop is a journal record, so an engine reopened from the
// same store still holds it, and a reopen record clears it.
func TestRouteStopSurvivesReopen(t *testing.T) {
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	if err := e.StopRoute("codex", "login-refused"); err != nil {
		t.Fatal(err)
	}
	if err := e.StopRoute("claude", "unswappable"); err != nil {
		t.Fatal(err)
	}
	// A second stop for the same cause, or a reopening of an open route,
	// writes nothing.
	n := len(e.Trail())
	if err := e.StopRoute("codex", "login-refused"); err != nil {
		t.Fatal(err)
	}
	if err := e.ReopenRoute("nowhere", "login-refused"); err != nil {
		t.Fatal(err)
	}
	if len(e.Trail()) != n {
		t.Fatalf("an idempotent stop or reopen wrote a record")
	}

	e2 := mustOpen(t, st, newPolicy(), newService())
	if c, ok := e2.RouteStopped("codex"); !ok || c != "login-refused" {
		t.Fatalf("after a restart codex: %q %v", c, ok)
	}
	if c, ok := e2.RouteStopped("claude"); !ok || c != "unswappable" {
		t.Fatalf("after a restart claude: %q %v", c, ok)
	}
	if err := e2.ReopenRoute("codex", "login-refused"); err != nil {
		t.Fatal(err)
	}
	e3 := mustOpen(t, st, newPolicy(), newService())
	if _, ok := e3.RouteStopped("codex"); ok {
		t.Fatal("a reopened route is stopped after a restart")
	}
	if _, ok := e3.RouteStopped("claude"); !ok {
		t.Fatal("reopening one route reopened another")
	}
	// STOP holds dispatch, not this record: a stop is still written.
	if _, err := e3.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e3.StopRoute("codex", "login-refused"); err != nil {
		t.Fatalf("route stop under STOP: %v", err)
	}
}

// CRED-RS-1: the note carries codes only, never free text.
func TestRouteStopRefusesBadNotes(t *testing.T) {
	e := mustOpen(t, &MemStore{}, newPolicy(), newService())
	for _, c := range []struct{ route, cause string }{
		{"", "login-refused"},
		{"codex", ""},
		{"codex", "the provider said " + canary},
		{"code x", "login-refused"},
	} {
		if err := e.StopRoute(c.route, c.cause); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v, want ErrInvalid", c, err)
		}
	}
	for _, c := range []struct{ route, cause string }{
		{"code x", "login-refused"},
		{"codex", ""},
		{"codex", "the provider said " + canary},
	} {
		if err := e.ReopenRoute(c.route, c.cause); !errors.Is(err, ErrInvalid) {
			t.Fatalf("reopen %+v: %v, want ErrInvalid", c, err)
		}
	}
	if len(e.Trail()) != 0 {
		t.Fatal("a refused note was written")
	}
}

// CRED-RS-4: an unswappable stop outranks a refused login's, live and on
// replay; a refused login never lowers an unswappable stop, and a cause
// the journal does not know ranks as unswappable.
func TestUnswappableOutranksLoginRefused(t *testing.T) {
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	if err := e.StopRoute("codex", "login-refused"); err != nil {
		t.Fatal(err)
	}
	n := len(e.Trail())
	if err := e.StopRoute("codex", "unswappable"); err != nil {
		t.Fatal(err)
	}
	if len(e.Trail()) != n+1 {
		t.Fatal("raising the stop wrote no record")
	}
	if c, _ := e.RouteStopped("codex"); c != "unswappable" {
		t.Fatalf("raised stop: %q", c)
	}
	n = len(e.Trail())
	if err := e.StopRoute("codex", "login-refused"); err != nil {
		t.Fatal(err)
	}
	if err := e.StopRoute("codex", "unswappable"); err != nil {
		t.Fatal(err)
	}
	if len(e.Trail()) != n {
		t.Fatal("a stop that does not raise the cause wrote a record")
	}
	if err := e.StopRoute("claude", "login-refused"); err != nil {
		t.Fatal(err)
	}
	if err := e.StopRoute("claude", "revoked"); err != nil {
		t.Fatal(err)
	}

	e2 := mustOpen(t, st, newPolicy(), newService())
	if c, _ := e2.RouteStopped("codex"); c != "unswappable" {
		t.Fatalf("after a restart codex: %q", c)
	}
	if c, _ := e2.RouteStopped("claude"); c != "revoked" {
		t.Fatalf("after a restart claude: %q", c)
	}
}

// CRED-RS-5: a reopening lifts the stop only while it has the cause the
// caller read, and replay compares the reopen record's cause too.
func TestReopenComparesTheCause(t *testing.T) {
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	if err := e.StopRoute("codex", "login-refused"); err != nil {
		t.Fatal(err)
	}
	if err := e.StopRoute("codex", "unswappable"); err != nil {
		t.Fatal(err)
	}
	n := len(e.Trail())
	if err := e.ReopenRoute("codex", "login-refused"); !errors.Is(err, ErrRouteCause) {
		t.Fatalf("a sign-in's reopening of an unswappable stop: %v, want ErrRouteCause", err)
	}
	if len(e.Trail()) != n {
		t.Fatal("a refused reopening wrote a record")
	}
	if c, ok := e.RouteStopped("codex"); !ok || c != "unswappable" {
		t.Fatalf("after a refused reopening: %q %v", c, ok)
	}
	if err := e.ReopenRoute("codex", "unswappable"); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.RouteStopped("codex"); ok {
		t.Fatal("the release's reopening did not lift the stop")
	}
	if rec := e.Trail()[len(e.Trail())-1]; rec.RouteStop == nil || rec.RouteStop.Cause != "unswappable" {
		t.Fatalf("the reopen record does not carry the cause it lifted: %+v", rec.RouteStop)
	}
	if _, ok := mustOpen(t, st, newPolicy(), newService()).RouteStopped("codex"); ok {
		t.Fatal("the reopening did not survive a restart")
	}
}

// CRED-RS-5: replay compares a reopen record's cause, and a reopen record
// without one (written before CRED-RS-5) still lifts any stop.
func TestReopenRecordsReplayByCause(t *testing.T) {
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	for _, n := range []RouteStopNote{
		{Route: "codex", Event: RouteStoppedEvent, Cause: "unswappable"},
		{Route: "codex", Event: RouteReopenedEvent, Cause: "login-refused"},
		{Route: "claude", Event: RouteStoppedEvent, Cause: "unswappable"},
		{Route: "claude", Event: RouteReopenedEvent},
	} {
		n := n
		e.mu.Lock()
		err := e.commit(Record{Type: RecRouteStop, RouteStop: &n})
		e.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	e2 := mustOpen(t, st, newPolicy(), newService())
	if c, ok := e2.RouteStopped("codex"); !ok || c != "unswappable" {
		t.Fatalf("a reopen record of another cause lifted the stop: %q %v", c, ok)
	}
	if _, ok := e2.RouteStopped("claude"); ok {
		t.Fatal("a cause-less reopen record from before CRED-RS-5 did not lift the stop")
	}
}

// CRED-RS-4: raising a refused login's stop is its own event, which a
// binary from before #2016 does not know and so refuses the journal over
// (fails closed); recorded as a second "stopped", that binary would keep
// the first cause and the owner's sign-in would lift an unswappable stop.
// A raise to the sign-in cause is not a raise and is invalid.
func TestRaiseIsItsOwnEvent(t *testing.T) {
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	if err := e.StopRoute("codex", "login-refused"); err != nil {
		t.Fatal(err)
	}
	if err := e.StopRoute("codex", "unswappable"); err != nil {
		t.Fatal(err)
	}
	tr := e.Trail()
	last := tr[len(tr)-1].RouteStop
	if last == nil || last.Event != RouteRaisedEvent || last.Cause != "unswappable" {
		t.Fatalf("raise recorded as %+v", last)
	}
	for _, n := range []RouteStopNote{
		{Route: "codex", Event: RouteRaisedEvent, Cause: "login-refused"},
		{Route: "codex", Event: RouteRaisedEvent},
	} {
		if n.valid() {
			t.Fatalf("%+v is valid", n)
		}
	}
	// A raise replays by the precedence rule, also onto an open route.
	e.applyRouteStop(&RouteStopNote{Route: "claude", Event: RouteRaisedEvent, Cause: "unswappable"})
	if c, _ := e.RouteStopped("claude"); c != "unswappable" {
		t.Fatalf("raise onto an open route: %q", c)
	}
	e2 := mustOpen(t, st, newPolicy(), newService())
	if c, _ := e2.RouteStopped("codex"); c != "unswappable" {
		t.Fatalf("after a restart: %q", c)
	}
}
