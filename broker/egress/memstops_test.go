package egress

import (
	"errors"
	"testing"
)

// REQ: CRED-RS-4

// noUnswappable is an in-memory RouteStops that records a refused login's
// stop but cannot record an unswappable one, as a store that fills between
// the two writes does.
type noUnswappable struct{ memStops }

func (s noUnswappable) StopRoute(route, cause string) error {
	if cause == StopUnswappable {
		return errStopWrite
	}
	return s.memStops.StopRoute(route, cause)
}

// CRED-RS-4: on the in-memory default agentos-egress runs with, an
// unswappable exchange on a route a refused login stopped raises the
// stored stop, so Resume (the owner's sign-in) no longer reopens it.
func TestMemStopsRaiseALoginRefusedStop(t *testing.T) {
	r := newPlanRig(t)
	r.proxy.stop("plan", ReasonLoginRefused)
	r.proxy.stop("plan", ReasonUnswappable)
	if c, ok := r.proxy.stops.RouteStopped("plan"); !ok || c != StopUnswappable {
		t.Fatalf("in-memory stop after the unswappable response: %q %v", c, ok)
	}
	if err := r.proxy.Resume("plan"); !errors.Is(err, ErrRequalify) {
		t.Fatalf("Resume of a raised stop = %v, want ErrRequalify", err)
	}
}

// CRED-RS-4: a held unswappable stop outranks a stored refused login's:
// the store kept the login stop and could not record the raise, so the
// proxy holds it, and Resume does not reopen the route.
func TestHeldUnswappableOutranksAStoredLoginStop(t *testing.T) {
	r := newPlanRig(t)
	r.rebuild(t, noUnswappable{memStops{}})
	r.proxy.stop("plan", ReasonLoginRefused)
	r.proxy.stop("plan", ReasonUnswappable)
	if c, _ := r.proxy.stops.RouteStopped("plan"); c != StopLoginRefused {
		t.Fatalf("store: %q, want the login stop it could record", c)
	}
	if reason, ok := r.proxy.stopped("plan"); !ok || reason != ReasonUnswappable {
		t.Fatalf("stopped = %q %v, want the held unswappable stop", reason, ok)
	}
	if err := r.proxy.Resume("plan"); !errors.Is(err, ErrRequalify) {
		t.Fatalf("Resume over a held unswappable stop = %v, want ErrRequalify", err)
	}
	if _, ok := r.proxy.stopped("plan"); !ok {
		t.Fatal("the route reopened")
	}
}
