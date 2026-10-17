package egress

import (
	"errors"
	"net/http"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CRED-5, OP-11, CRED-RS-3, CRED-RS-4, CRED-RS-5, CRED-RS-6

// stopStore is a journal store that refuses every write once fail is set,
// as a full or failing disk does.
type stopStore struct {
	journal.MemStore
	fail bool
}

var errStopWrite = errors.New("journal refused the record")

func (s *stopStore) Append(line []byte) error {
	if s.fail {
		return errStopWrite
	}
	return s.MemStore.Append(line)
}

// journalStops opens a journal engine over st: the RouteStops agentosd
// shares with provagent, and a restart when opened again over the same
// store (CRED-RS-6).
func journalStops(t *testing.T, st journal.Store) *journal.Engine {
	t.Helper()
	e, err := journal.Open(st, nil, nil, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	return e
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

// CRED-RS-3, CRED-RS-5, CRED-RS-6: a stop is in the journal, so a proxy
// built again over it (a restart) still refuses the route without reaching
// the provider. A refused login's stop is lifted by Resume; an unswappable
// one is not, only by Requalify (the release).
func TestProxyStopSurvivesARestart(t *testing.T) {
	store := &journal.MemStore{}
	st := journalStops(t, store)
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
	st = journalStops(t, store)
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
	if _, ok := journalStops(t, store).RouteStopped("plan"); ok {
		t.Fatal("Requalify's reopening is not in the journal")
	}
}

// CRED-RS-3, CRED-RS-6: a stop the journal cannot record still stops the
// route in this proxy and tells the owner once; a reopening it cannot
// record is refused and leaves the route stopped.
func TestProxyStopWriteFailureFailsClosed(t *testing.T) {
	r := newPlanRig(t)
	r.rebuild(t, journalStops(t, &stopStore{fail: true}))
	r.answer(http.StatusForbidden, "application/json", `{"error":"account restricted"}`)
	for i := 0; i < 3; i++ {
		if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("request %d got %d", i, w.Code)
		}
	}
	if r.provider.count() != 1 || len(r.fails.list()) != 1 {
		t.Fatalf("provider reached %d times, owner told %v", r.provider.count(), r.fails.list())
	}

	store := &stopStore{}
	st := journalStops(t, store)
	if err := st.StopRoute("plan", StopLoginRefused); err != nil {
		t.Fatal(err)
	}
	store.fail = true
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

// CRED-RS-4: an unswappable exchange on a route a refused login stopped (a
// request already past the stop check, or a stop provagent wrote) raises
// the stop, in the journal or, when the journal cannot record it, in the
// proxy; the owner is told again, and Resume no longer reopens it.
func TestProxyRaisesALoginRefusedStop(t *testing.T) {
	store := &journal.MemStore{}
	st := journalStops(t, store)
	if err := st.StopRoute("plan", StopLoginRefused); err != nil {
		t.Fatal(err)
	}
	r := newPlanRig(t)
	r.rebuild(t, st)
	r.proxy.stop("plan", ReasonUnswappable)
	if c, _ := journalStops(t, store).RouteStopped("plan"); c != StopUnswappable {
		t.Fatalf("journal after the unswappable response: %q", c)
	}
	if f := r.fails.list(); len(f) != 1 {
		t.Fatalf("owner told %v, want the raised stop once", f)
	}
	r.proxy.stop("plan", ReasonUnswappable)
	r.proxy.stop("plan", ReasonLoginRefused)
	if f := r.fails.list(); len(f) != 1 {
		t.Fatalf("a stop that raises nothing told the owner again: %v", f)
	}
	if err := r.proxy.Resume("plan"); !errors.Is(err, ErrRequalify) {
		t.Fatalf("Resume of a raised stop = %v, want ErrRequalify", err)
	}

	r = newPlanRig(t)
	failing := &stopStore{fail: true}
	r.rebuild(t, journalStops(t, failing))
	r.proxy.stop("plan", ReasonLoginRefused)
	r.proxy.stop("plan", ReasonUnswappable)
	if f := r.fails.list(); len(f) != 2 {
		t.Fatalf("owner told %v, want the stop and its raising", f)
	}
	if err := r.proxy.Resume("plan"); !errors.Is(err, ErrRequalify) {
		t.Fatalf("Resume of a raised stop held in the proxy = %v, want ErrRequalify", err)
	}
}
