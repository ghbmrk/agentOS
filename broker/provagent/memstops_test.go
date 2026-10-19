package provagent

import (
	"context"
	"testing"
)

// REQ: CRED-RS-4, CRED-RS-5

// memRaising is the in-memory RouteStops on which an unswappable exchange
// raises the stop right after the Runner reads it, as egress may between
// SignedIn's read and its reopening.
type memRaising struct{ memStops }

func (m memRaising) RouteStopped(route string) (string, bool) {
	c, ok := m.memStops.RouteStopped(route)
	m.memStops.StopRoute(route, StopUnswappable)
	return c, ok
}

// CRED-RS-4: on the Runner's in-memory default, an unswappable stop raises
// the refused login's stop its run recorded, so the owner's sign-in no
// longer reopens the route.
func TestMemStopsRaiseALoginRefusedStop(t *testing.T) {
	g := newRig(nil)
	g.h.cli = g.refuseLogin
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != LoginRefused {
		t.Fatalf("refused login: %v", err)
	}
	g.r.mu.Lock()
	st := g.r.stops()
	g.r.mu.Unlock()
	if c, _ := st.RouteStopped("stub"); c != StopLoginRefused {
		t.Fatalf("stop after the refused login: %q", c)
	}
	if err := st.StopRoute("stub", StopUnswappable); err != nil {
		t.Fatal(err)
	}
	if c, _ := st.RouteStopped("stub"); c != StopUnswappable {
		t.Fatalf("stop after the unswappable exchange: %q, want it raised", c)
	}
	g.r.SignInStored = func(string) bool { return true }
	if g.r.SignedIn("stub", "pw-ok") {
		t.Fatal("a sign-in reopened a raised stop")
	}
}

// CRED-RS-5: on the in-memory default, the reopening names the cause, so
// a stop raised between SignedIn's read and its reopening stays.
func TestMemStopsReopenComparesTheCause(t *testing.T) {
	st := memRaising{memStops{}}
	if err := st.memStops.StopRoute("stub", StopLoginRefused); err != nil {
		t.Fatal(err)
	}
	g := newRig(ok("fine"))
	g.r.Stops = st
	g.r.SignInStored = func(string) bool { return true }
	if g.r.SignedIn("stub", "pw-ok") {
		t.Fatal("a sign-in reopened a stop raised after it read the cause")
	}
	if c, ok := st.memStops.RouteStopped("stub"); !ok || c != StopUnswappable {
		t.Fatalf("stop after the raced sign-in: %q %v", c, ok)
	}
}
