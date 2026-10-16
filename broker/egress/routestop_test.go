package egress

import (
	"errors"
	"net/http"
	"sync"
	"testing"
)

// REQ: CRED-5, OP-11, CRED-RS-3

// routeStops is a RouteStops whose map outlives the Proxy, as the journal
// does across a restart.
type routeStops struct {
	mu   sync.Mutex
	m    map[string]string
	fail bool // every write fails
}

var errStopWrite = errors.New("journal refused the record")

func (s *routeStops) StopRoute(route, cause string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errStopWrite
	}
	if _, ok := s.m[route]; !ok {
		s.m[route] = cause
	}
	return nil
}

func (s *routeStops) ReopenRoute(route string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errStopWrite
	}
	delete(s.m, route)
	return nil
}

func (s *routeStops) RouteStopped(route string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[route]
	return c, ok
}

// rebuild builds the rig's proxy again over st, as a broker restart does.
func (r *planRig) rebuild(t *testing.T, st RouteStops) {
	t.Helper()
	p, err := New(Config{
		Adapters: []Adapter{planAdapter()}, Grants: map[string][]string{"w1": {"plan"}},
		Vault: r.vault, Transport: r.transport, Audit: r.audit, RouteFailed: r.fails.told,
		Swapper: r.swap, Stops: st,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.proxy = p
}

// CRED-RS-3: a stop is in the store, so a proxy built again over it (a
// restart) still refuses the route without reaching the provider. A
// refused login's stop is lifted by Resume; an unswappable one is not,
// only by Requalify (the release).
func TestProxyStopSurvivesARestart(t *testing.T) {
	st := &routeStops{m: map[string]string{}}
	r := newPlanRig(t)
	r.rebuild(t, st)
	canary := synthetic(t, "canary-")
	r.answer(http.StatusForbidden, "application/json", `{"error":"account restricted","detail":"`+canary+`"}`)
	if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("refusal got %d", w.Code)
	}
	if c, ok := st.RouteStopped("plan"); !ok || c != StopLoginRefused {
		t.Fatalf("store after a refused login: %q %v", c, ok)
	}
	r.rebuild(t, st)
	r.answer(200, "application/json", `{"content":[]}`)
	if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != http.StatusServiceUnavailable || leaked(w, canary) {
		t.Fatalf("after a restart got %d %q", w.Code, w.Body)
	}
	if r.provider.count() != 1 {
		t.Fatalf("provider reached %d times", r.provider.count())
	}
	if err := r.proxy.Resume("plan"); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.RouteStopped("plan"); ok {
		t.Fatal("Resume's reopening is not in the store")
	}
	if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != 200 {
		t.Fatalf("after Resume got %d", w.Code)
	}

	r.answer(200, "application/json", `{"access_token":"`+canary+`","refresh_token":"`+canary+`r","id_token":"`+canary+`i","expires_in":1,"token_type":"Bearer"}`)
	if w := r.do(t, "w1", refresh()); w.Code != http.StatusBadGateway {
		t.Fatalf("unswappable got %d", w.Code)
	}
	if c, _ := st.RouteStopped("plan"); c != StopUnswappable {
		t.Fatalf("store after an unswappable response: %q", c)
	}
	r.rebuild(t, st)
	if err := r.proxy.Resume("plan"); !errors.Is(err, ErrRequalify) {
		t.Fatalf("Resume after a restart = %v, want ErrRequalify", err)
	}
	r.answer(200, "application/json", `{"content":[]}`)
	if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unswappable after a restart got %d", w.Code)
	}
	if err := r.proxy.Requalify("plan"); err != nil {
		t.Fatal(err)
	}
	if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != 200 {
		t.Fatalf("after Requalify got %d", w.Code)
	}
}

// CRED-RS-3: a stop the store cannot record still stops the route in this
// proxy and tells the owner once; a reopening it cannot record is refused
// and leaves the route stopped.
func TestProxyStopWriteFailureFailsClosed(t *testing.T) {
	st := &routeStops{m: map[string]string{}, fail: true}
	r := newPlanRig(t)
	r.rebuild(t, st)
	r.answer(http.StatusForbidden, "application/json", `{"error":"account restricted"}`)
	for i := 0; i < 3; i++ {
		if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("request %d got %d", i, w.Code)
		}
	}
	if r.provider.count() != 1 || len(r.fails.list()) != 1 {
		t.Fatalf("provider reached %d times, owner told %v", r.provider.count(), r.fails.list())
	}

	st = &routeStops{m: map[string]string{"plan": StopLoginRefused}, fail: true}
	r = newPlanRig(t)
	r.rebuild(t, st)
	if err := r.proxy.Resume("plan"); err == nil {
		t.Fatal("Resume reported a reopening the store refused")
	}
	r.answer(200, "application/json", `{"content":[]}`)
	if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != http.StatusServiceUnavailable || r.provider.count() != 0 {
		t.Fatalf("unrecorded reopening: got %d, provider reached %d times", w.Code, r.provider.count())
	}
}
