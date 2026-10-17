package journal

import (
	"errors"
	"fmt"
)

// RecRouteStop journals a provider route stopping or reopening (CRED-5,
// CRED-5t). OP-11 keeps no durable state beside the journal, so the stop
// is a record and replay rebuilds which routes are stopped.
const RecRouteStop RecordType = "route_stop"

// The events a RouteStopNote records.
const (
	RouteStoppedEvent  = "stopped"
	RouteReopenedEvent = "reopened"
	// RouteRaisedEvent replaces a stopped route's cause with one that
	// outranks it (CRED-RS-4). It is its own event, not a second "stopped",
	// so a binary from before it refuses the journal (fails closed) rather
	// than keep the first cause and let a sign-in lift the stop.
	RouteRaisedEvent = "raised"
)

// routeCauseSignIn is the one cause the owner's sign-in lifts (CRED-5).
// Every other cause ("unswappable", or one this journal does not know)
// outranks it: only a release lifts it (CRED-5t).
const routeCauseSignIn = "login-refused"

// ErrRouteCause is ReopenRoute's answer for a route stopped for another
// cause than the one the caller would lift: it stays stopped.
var ErrRouteCause = errors.New("journal: the route is stopped for another cause")

// outranks reports whether a stop for cause replaces one for cur.
func outranks(cause, cur string) bool {
	return cur == routeCauseSignIn && cause != routeCauseSignIn
}

// RouteStopNote is one stop or reopening of a provider route. Route and
// Cause are identifier-like codes (an adapter ID; "login-refused" or
// "unswappable"), never free text, so they are kept as written. A
// reopening's Cause is the cause it lifted; one written before CRED-RS-5
// has none and lifts any.
type RouteStopNote struct {
	Route string `json:"route"`
	Event string `json:"event"`
	Cause string `json:"cause,omitempty"`
}

func (n RouteStopNote) valid() bool {
	if n.Route == "" || token(n.Route) != n.Route || token(n.Cause) != n.Cause {
		return false
	}
	switch n.Event {
	case RouteStoppedEvent:
		return n.Cause != ""
	case RouteRaisedEvent:
		return n.Cause != "" && n.Cause != routeCauseSignIn
	case RouteReopenedEvent:
		return true
	}
	return false
}

// StopRoute journals that route is stopped for cause. A route already
// stopped keeps its cause and nothing is written, unless cause outranks it
// (an unswappable stop over a refused login's, CRED-RS-4): that is written
// as a raise. STOP does not
// hold it: it records an observation, not an effect.
func (e *Engine) StopRoute(route, cause string) error {
	n := RouteStopNote{Route: route, Event: RouteStoppedEvent, Cause: cause}
	if !n.valid() {
		return fmt.Errorf("%w: a route stop needs a code-like route and cause", ErrInvalid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken != nil {
		return e.broken
	}
	if cur, ok := e.routeStops[route]; ok {
		if !outranks(cause, cur) {
			return nil
		}
		n.Event = RouteRaisedEvent
	}
	return e.commit(Record{Type: RecRouteStop, RouteStop: &n})
}

// ReopenRoute journals that route is open again, if it is stopped for
// cause (CRED-RS-5): one stopped for another cause stays stopped
// (ErrRouteCause), so a sign-in cannot lift a stop raised after it read
// the cause. An open route writes nothing.
func (e *Engine) ReopenRoute(route, cause string) error {
	n := RouteStopNote{Route: route, Event: RouteReopenedEvent, Cause: cause}
	if cause == "" || !n.valid() {
		return fmt.Errorf("%w: a route reopening needs a code-like route and cause", ErrInvalid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken != nil {
		return e.broken
	}
	cur, ok := e.routeStops[route]
	if !ok {
		return nil
	}
	if cur != cause {
		return fmt.Errorf("%w: %s is stopped for %s, not %s", ErrRouteCause, route, cur, cause)
	}
	return e.commit(Record{Type: RecRouteStop, RouteStop: &n})
}

// RouteStopped reports whether route is stopped, and why.
func (e *Engine) RouteStopped(route string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.routeStops[route]
	return c, ok
}

func (e *Engine) applyRouteStop(n *RouteStopNote) {
	cur, ok := e.routeStops[n.Route]
	if n.Event == RouteReopenedEvent {
		if n.Cause == "" || n.Cause == cur {
			delete(e.routeStops, n.Route)
		}
		return
	}
	if e.routeStops == nil {
		e.routeStops = map[string]string{}
	}
	if !ok || outranks(n.Cause, cur) {
		e.routeStops[n.Route] = n.Cause
	}
}
