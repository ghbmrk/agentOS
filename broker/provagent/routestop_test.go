package provagent

import (
	"context"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CRED-5, OP-11, CRED-RS-2, CRED-RS-5, CRED-RS-6

// stopStore is a journal store that refuses every write once fail is set,
// as a full or failing disk does.
type stopStore struct {
	journal.MemStore
	fail bool
}

var errWrite = errors.New("journal refused the record")

func (s *stopStore) Append(line []byte) error {
	if s.fail {
		return errWrite
	}
	return s.MemStore.Append(line)
}

// journalStops opens a journal engine over st: the RouteStops agentosd
// wires, and a restart when opened again over the same store (CRED-RS-6).
func journalStops(t *testing.T, st journal.Store) *journal.Engine {
	t.Helper()
	e, err := journal.Open(st, nil, nil, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// raising is a RouteStops on which an unswappable exchange raises the stop
// right after the Runner reads it, as egress may between SignedIn's read
// and its reopening.
type raising struct{ *journal.Engine }

func (r raising) RouteStopped(route string) (string, bool) {
	c, ok := r.Engine.RouteStopped(route)
	r.Engine.StopRoute(route, StopUnswappable)
	return c, ok
}

// CRED-RS-2, CRED-RS-6: a refused login's stop is in the journal, so a new Runner over it
// (the broker restarted, and egress's in-memory refusal is gone) refuses
// the route, starts nothing and tells the owner once more. Only the owner's
// sign-in reopens it.
func TestStoppedRouteSurvivesARestart(t *testing.T) {
	store := &journal.MemStore{}
	g := newRig(nil)
	g.r.Stops = journalStops(t, store)
	g.h.cli = g.refuseLogin
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != LoginRefused {
		t.Fatalf("%v", err)
	}
	st := journalStops(t, store)
	if c, ok := st.RouteStopped("stub"); !ok || c != StopLoginRefused {
		t.Fatalf("store after a refusal: %q %v", c, ok)
	}

	g2 := newRig(ok("fine"))
	g2.r.Stops = st
	for i := 0; i < 2; i++ {
		_, err := g2.r.Run(context.Background(), req("b"))
		if reasonOf(err) != LoginRefused || !FallsBack(err) {
			t.Fatalf("run %d after a restart: %v", i, err)
		}
	}
	if len(g2.h.runs) != 0 || len(g2.h.created) != 0 || len(g2.sd.calls) != 0 {
		t.Fatalf("after a restart: %d CLI runs, %d workers, %d seeds", len(g2.h.runs), len(g2.h.created), len(g2.sd.calls))
	}
	if len(g2.signins) != 1 || g2.signins[0] != "stub" {
		t.Fatalf("sign-in line after a restart: %v", g2.signins)
	}

	g2.r.SignInStored = func(id string) bool { return id == "pw-ok" }
	if !g2.r.SignedIn("stub", "pw-ok") {
		t.Fatal("a stored sign-in did not reopen the route")
	}
	if _, ok := journalStops(t, store).RouteStopped("stub"); ok {
		t.Fatal("the reopening is not in the store")
	}
	if out, err := g2.r.Run(context.Background(), req("b")); err != nil || out != "fine" {
		t.Fatalf("after the sign-in: %q %v", out, err)
	}
}

// CRED-RS-2, CRED-RS-5, CRED-5t: on the journal egress shares, a route
// stopped by an unswappable exchange stays stopped through a sign-in (only
// a release requalifies it), falls back, and shows no sign-in line, since
// signing in would not help. A stop raised between SignedIn's read and its
// reopening stays too.
func TestSignedInLeavesAnUnswappableStop(t *testing.T) {
	st := journalStops(t, &journal.MemStore{})
	if err := st.StopRoute("stub", StopLoginRefused); err != nil {
		t.Fatal(err)
	}
	if err := st.StopRoute("stub", StopUnswappable); err != nil {
		t.Fatal(err)
	}
	g := newRig(ok("fine"))
	g.r.Stops = st
	g.r.SignInStored = func(string) bool { return true }
	if g.r.SignedIn("stub", "pw-ok") {
		t.Fatal("a sign-in reopened an unswappable route")
	}
	_, err := g.r.Run(context.Background(), req("b"))
	if err == nil || !FallsBack(err) || reasonOf(err) == LoginRefused {
		t.Fatalf("unswappable route: %v", err)
	}
	if len(g.h.runs) != 0 || len(g.signins) != 0 {
		t.Fatalf("%d CLI runs, sign-in line %v", len(g.h.runs), g.signins)
	}
	if c, _ := st.RouteStopped("stub"); c != StopUnswappable {
		t.Fatalf("store: %q", c)
	}

	st = journalStops(t, &journal.MemStore{})
	if err := st.StopRoute("stub", StopLoginRefused); err != nil {
		t.Fatal(err)
	}
	g = newRig(ok("fine"))
	g.r.Stops = raising{st}
	g.r.SignInStored = func(string) bool { return true }
	if g.r.SignedIn("stub", "pw-ok") {
		t.Fatal("a sign-in reopened a stop raised after it read the cause")
	}
	if c, ok := st.RouteStopped("stub"); !ok || c != StopUnswappable {
		t.Fatalf("store after the raced sign-in: %q %v", c, ok)
	}
}

// CRED-RS-2, CRED-RS-6: a stop the journal cannot record still stops the route in this
// process, and a reopening it cannot record leaves the route stopped.
func TestRouteStopWriteFailureFailsClosed(t *testing.T) {
	g := newRig(nil)
	g.r.Stops = journalStops(t, &stopStore{fail: true})
	g.h.cli = g.refuseLogin
	g.r.Run(context.Background(), req("b"))
	g.advance(1)
	g.h.cli = ok("fine")
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != LoginRefused || len(g.h.runs) != 1 {
		t.Fatalf("unrecorded stop: %v, %d runs", err, len(g.h.runs))
	}

	store := &stopStore{}
	st := journalStops(t, store)
	if err := st.StopRoute("stub", StopLoginRefused); err != nil {
		t.Fatal(err)
	}
	store.fail = true
	g = newRig(ok("fine"))
	g.r.Stops = st
	g.r.SignInStored = func(string) bool { return true }
	if g.r.SignedIn("stub", "pw-ok") {
		t.Fatal("SignedIn reported a reopening the store refused")
	}
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != LoginRefused || len(g.h.runs) != 0 {
		t.Fatalf("unrecorded reopening: %v, %d runs", err, len(g.h.runs))
	}
}
