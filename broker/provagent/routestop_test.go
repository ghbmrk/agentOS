package provagent

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// REQ: CRED-5, CRED-5t, OP-11, RSP-2

// stops is a RouteStops whose map outlives the Runner, as the journal does
// across a restart.
type stops struct {
	mu   sync.Mutex
	m    map[string]string
	fail bool // every write fails
}

var errWrite = errors.New("journal refused the record")

func (s *stops) StopRoute(route, cause string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errWrite
	}
	if _, ok := s.m[route]; !ok {
		s.m[route] = cause
	}
	return nil
}

func (s *stops) ReopenRoute(route string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errWrite
	}
	delete(s.m, route)
	return nil
}

func (s *stops) RouteStopped(route string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[route]
	return c, ok
}

// RSP-2: a refused login's stop is in the store, so a new Runner over it
// (the broker restarted, and egress's in-memory refusal is gone) refuses
// the route, starts nothing and tells the owner once more. Only the owner's
// sign-in reopens it.
func TestStoppedRouteSurvivesARestart(t *testing.T) {
	st := &stops{m: map[string]string{}}
	g := newRig(nil)
	g.r.Stops = st
	g.h.cli = g.refuseLogin
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != LoginRefused {
		t.Fatalf("%v", err)
	}
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
	if _, ok := st.RouteStopped("stub"); ok {
		t.Fatal("the reopening is not in the store")
	}
	if out, err := g2.r.Run(context.Background(), req("b")); err != nil || out != "fine" {
		t.Fatalf("after the sign-in: %q %v", out, err)
	}
}

// RSP-2, CRED-5t: on the store egress shares, a route stopped by an
// unswappable exchange stays stopped through a sign-in (only a release
// requalifies it), falls back, and shows no sign-in line, since signing in
// would not help.
func TestSignedInLeavesAnUnswappableStop(t *testing.T) {
	st := &stops{m: map[string]string{"stub": "unswappable"}}
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
	if c, _ := st.RouteStopped("stub"); c != "unswappable" {
		t.Fatalf("store: %q", c)
	}
}

// RSP-2: a stop the store cannot record still stops the route in this
// process, and a reopening it cannot record leaves the route stopped.
func TestRouteStopWriteFailureFailsClosed(t *testing.T) {
	st := &stops{m: map[string]string{}, fail: true}
	g := newRig(nil)
	g.r.Stops = st
	g.h.cli = g.refuseLogin
	g.r.Run(context.Background(), req("b"))
	g.advance(1)
	g.h.cli = ok("fine")
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != LoginRefused || len(g.h.runs) != 1 {
		t.Fatalf("unrecorded stop: %v, %d runs", err, len(g.h.runs))
	}

	st = &stops{m: map[string]string{"stub": StopLoginRefused}, fail: true}
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
