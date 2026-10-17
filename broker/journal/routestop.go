package journal

import "fmt"

// RecRouteStop journals a provider route stopping or reopening (CRED-5,
// CRED-5t). OP-11 keeps no durable state beside the journal, so the stop
// is a record and replay rebuilds which routes are stopped.
const RecRouteStop RecordType = "route_stop"

// The events a RouteStopNote records.
const (
	RouteStoppedEvent  = "stopped"
	RouteReopenedEvent = "reopened"
)

// RouteStopNote is one stop or reopening of a provider route. Route and
// Cause are identifier-like codes (an adapter ID; "login-refused" or
// "unswappable"), never free text, so they are kept as written.
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
	case RouteReopenedEvent:
		return n.Cause == ""
	}
	return false
}

// StopRoute journals that route is stopped for cause. A route already
// stopped keeps its first cause and nothing is written. STOP does not hold
// it: it records an observation, not an effect.
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
	if _, ok := e.routeStops[route]; ok {
		return nil
	}
	return e.commit(Record{Type: RecRouteStop, RouteStop: &n})
}

// ReopenRoute journals that route is open again. An open route writes
// nothing.
func (e *Engine) ReopenRoute(route string) error {
	n := RouteStopNote{Route: route, Event: RouteReopenedEvent}
	if !n.valid() {
		return fmt.Errorf("%w: a route reopening needs a code-like route", ErrInvalid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken != nil {
		return e.broken
	}
	if _, ok := e.routeStops[route]; !ok {
		return nil
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
	if n.Event == RouteReopenedEvent {
		delete(e.routeStops, n.Route)
		return
	}
	if e.routeStops == nil {
		e.routeStops = map[string]string{}
	}
	if _, ok := e.routeStops[n.Route]; !ok {
		e.routeStops[n.Route] = n.Cause
	}
}
