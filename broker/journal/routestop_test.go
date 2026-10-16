package journal

import (
	"errors"
	"testing"
)

// REQ: CRED-5, CRED-5t, OP-11, RSP-1

// RSP-1: a route stop is a journal record, so an engine reopened from the
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
	// A second stop keeps the first cause and writes nothing.
	n := len(e.Trail())
	if err := e.StopRoute("codex", "unswappable"); err != nil {
		t.Fatal(err)
	}
	if err := e.ReopenRoute("nowhere"); err != nil {
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
	if err := e2.ReopenRoute("codex"); err != nil {
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

// RSP-1: the note carries codes only, never free text.
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
	if err := e.ReopenRoute("code x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reopen: %v, want ErrInvalid", err)
	}
	if len(e.Trail()) != 0 {
		t.Fatal("a refused note was written")
	}
}
