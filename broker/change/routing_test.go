package change

// REQ: ADP-4, CHG-6

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/route"
	"github.com/ghbmrk/agentos/broker/routerule"
)

// newRouter builds a real router whose openai route always fails over
// (503) and whose anthropic route serves.
func newRouter(t *testing.T) *route.Router {
	t.Helper()
	ok, err := os.ReadFile("../route/testdata/anthropic_message.json")
	if err != nil {
		t.Fatal(err)
	}
	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if strings.HasPrefix(r.URL.Path, "/openai/") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(ok)
	})
	var ticks atomic.Int64
	r, err := route.New(route.Config{
		Providers: []route.Provider{route.OpenAI(), route.Anthropic()},
		Rule:      route.Rule{"chat": {{Provider: "openai", Model: "m1"}, {Provider: "anthropic", Model: "m2"}}},
		Granted:   func(string, string) bool { return true },
		Label:     func(string) string { return route.LabelPublic },
		Upstream:  func(string) http.Handler { return up },
		Audit:     func(route.Decision) {},
		// A deterministic nanosecond clock and matching fixture cooldown let
		// every attempt contribute evidence without sleeps or large latencies.
		Cooldown: time.Nanosecond,
		Now:      func() time.Time { return time.Unix(0, ticks.Add(1)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func callRouter(t *testing.T, r *route.Router, n int) {
	for i := 0; i < n; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"model":"chat","messages":[{"role":"user","content":"hi"}]}`))
		r.Handler("m").ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("call %d: %d %s", i, w.Code, w.Body)
		}
	}
}

var reordered = route.Rule{"chat": {{Provider: "anthropic", Model: "m2"}, {Provider: "openai", Model: "m1"}}}

func ruleCase(e *env, want route.Rule, n int) {
	for i := 0; i < n; i++ {
		e.taskCase(ClassRouting, RoutingPath, string(canonicalJSON(want)), Accepted)
	}
}

// ADP-4: the router's proposal changes routing only when the pipeline
// adopts it, as an authority-neutral change among granted routes, and it
// reverts by one reply.
func TestRouterCandidateAdoptsThroughPipeline(t *testing.T) {
	r := newRouter(t)
	e := newEnv(t, func(c *Config) {
		c.Targets = map[string]Target{"routing": RoutingTarget{Router: r}}
		c.RouteGranted = func(p string) bool { return p == "openai" || p == "anthropic" }
	})
	ruleCase(e, reordered, 12)
	if _, changed, _ := e.p.ProposeRouting(bg, r); changed {
		t.Fatal("no measurements, yet a candidate")
	}
	callRouter(t, r, 3)
	if _, changed, _ := e.p.ProposeRouting(bg, r); changed {
		t.Fatal("sparse transport evidence entered the pipeline")
	}
	callRouter(t, r, 7) // 10 observations per route in this class
	if got := r.Rule()["chat"][0].Provider; got != "openai" {
		t.Fatal("the router reordered itself:", got)
	}
	rep, changed, err := e.p.ProposeRouting(bg, r)
	if err != nil || !changed {
		t.Fatal(err, changed)
	}
	if rep.State != StateAdopted || rep.Basis != BasisStanding {
		t.Fatalf("routing candidate: %+v", rep)
	}
	if got := r.Rule()["chat"][0].Provider; got != "anthropic" {
		t.Fatal("adoption did not set the router's rule:", got)
	}
	d := e.p.Digest()
	if len(d) != 1 || !strings.HasPrefix(d[0], "Changed AI routing: chat tasks now go first to anthropic instead of openai. Tested on ") ||
		!strings.HasSuffix(d[0], "UNDO "+rep.Short+" / MORE "+rep.Short) {
		t.Fatalf("routing-primary digest: %q", d)
	}
	if err := e.p.Revert(bg, rep.ID, OriginOwner); err != nil {
		t.Fatal(err)
	}
	if got := r.Rule()["chat"][0].Provider; got != "openai" {
		t.Fatal("revert did not restore the rule:", got)
	}
}

// ADP-4, CAP-9: a routing candidate that adds a route asks the owner, and
// one naming an ungranted provider fails outright.
func TestRoutingNeverAddsRoutes(t *testing.T) {
	r := newRouter(t)
	e := newEnv(t, func(c *Config) {
		c.Targets = map[string]Target{"routing": RoutingTarget{Router: r}}
		c.RouteGranted = func(p string) bool { return p == "openai" || p == "anthropic" }
	})
	added := route.Rule{"chat": {{Provider: "anthropic", Model: "m3"}, {Provider: "openai", Model: "m1"}}}
	ruleCase(e, added, 12)
	rep := e.propose(Candidate{Source: Local, Files: Tree{RoutingPath: canonicalJSON(added)}})
	if rep.Neutral || rep.Basis != BasisOwner {
		t.Fatalf("added route: %+v", rep)
	}
	ungranted := e.propose(Candidate{Source: Local, Files: Tree{RoutingPath: []byte(`{"chat":[{"provider":"mistral","model":"x"}]}`)}})
	if ungranted.State != StateRejected || !strings.Contains(ungranted.Reason, "not granted") {
		t.Fatalf("ungranted provider: %+v", ungranted)
	}
	newClass := e.propose(Candidate{Source: Local, Files: Tree{RoutingPath: canonicalJSON(route.Rule{
		"chat": reordered["chat"], "code": {{Provider: "openai", Model: "m1"}}})}})
	if newClass.Neutral {
		t.Fatalf("new task class: %+v", newClass)
	}
	extra := e.propose(Candidate{Source: Local, Files: Tree{"routing/other.json": []byte("{}")}})
	if extra.State != StateRejected {
		t.Fatalf("second routing file: %+v", extra)
	}
	if got := r.Rule()["chat"][0].Model; got != "m1" {
		t.Fatal("rule changed without adoption:", got)
	}
}

// ADP-4: an adopted rule that regresses once new owner outcomes arrive is
// rolled back automatically, and the digest says so.
func TestRoutingRollsBackOnRegression(t *testing.T) {
	r := newRouter(t)
	e := newEnv(t, func(c *Config) {
		c.Targets = map[string]Target{"routing": RoutingTarget{Router: r}}
		c.RouteGranted = func(string) bool { return true }
	})
	ruleCase(e, reordered, 12)
	callRouter(t, r, 10)
	rep, _, _ := e.p.ProposeRouting(bg, r)
	if rep.State != StateAdopted {
		t.Fatal(rep)
	}
	if ids, _ := e.p.Recheck(bg); len(ids) != 0 {
		t.Fatal("rolled back without a regression:", ids)
	}
	// Owners now accept the original order on many new tasks.
	orig := route.Rule{"chat": {{Provider: "openai", Model: "m1"}, {Provider: "anthropic", Model: "m2"}}}
	ruleCase(e, orig, 40)
	ids, err := e.p.Recheck(bg)
	if err != nil || len(ids) != 1 || ids[0] != rep.ID {
		t.Fatal(ids, err)
	}
	if got := r.Rule()["chat"][0].Provider; got != "openai" {
		t.Fatal("rollback did not restore the rule:", got)
	}
	found := false
	for _, l := range e.p.Digest() {
		found = found || l == "Undid "+rep.Short+": it did worse on newer tasks."
	}
	if !found {
		t.Fatal("digest does not list the rollback")
	}
}

// Arbitrator R1: a reorder that drops the local fallback says so.
func TestDroppedLocalFallbackSaysSo(t *testing.T) {
	cur := route.Rule{"mail": {{Provider: "openai", Model: "m"}, {Provider: "local", Model: "l"}}}
	e := newEnv(t, func(c *Config) {
		c.Initial[RoutingPath] = canonicalJSON(cur)
		c.RouteGranted = func(string) bool { return true }
		c.LocalProvider = func(p string) bool { return p == "local" }
	})
	next := route.Rule{"mail": {{Provider: "openai", Model: "m"}}}
	ruleCase(e, next, 12)
	rep := e.propose(Candidate{Source: Local, Files: Tree{RoutingPath: canonicalJSON(next)}})
	if rep.State != StateAdopted {
		t.Fatal(rep)
	}
	if d := e.p.Digest(); len(d) != 1 || !strings.HasPrefix(d[0], "Changed AI routing: mail tasks no longer fall back to the local model.") {
		t.Fatalf("%q", d)
	}
}

// refusingRouting is agentosd's routing target until agentos-egress
// follows adoptions (cmd/agentosd heldRouting): empty, and refusing any
// non-empty tree.
type refusingRouting struct{ onRefuse func() }

func (refusingRouting) Current() (Tree, error) { return Tree{}, nil }
func (r refusingRouting) Apply(t Tree) error {
	if len(t) != 0 {
		if r.onRefuse != nil {
			r.onRefuse()
		}
		return errRefused
	}
	return nil
}

var errRefused = errorString("routing changes wait until agentos-egress follows them")

type errorString string

func (e errorString) Error() string { return string(e) }

// L3 S2 on #90: a routing candidate that qualifies is not adopted when the
// routing target refuses it, and the active tree is unchanged.
func TestRoutingAdoptionRefusedByTheTargetLeavesActiveUnchanged(t *testing.T) {
	r := newRouter(t)
	refusals := 0
	e := newEnv(t, func(c *Config) {
		c.Targets = map[string]Target{"routing": refusingRouting{onRefuse: func() { refusals++ }}}
		c.RouteGranted = func(p string) bool { return p == "openai" || p == "anthropic" }
	})
	e.owner.approve = true // the empty target makes this an owner-authorized addition
	ruleCase(e, reordered, 12)
	callRouter(t, r, 10)
	before := e.p.Files("routing")
	rep, changed, _ := e.p.ProposeRouting(bg, r)
	if !changed {
		t.Fatal("no routing candidate: the test proves nothing")
	}
	if refusals != 1 {
		t.Fatalf("target refused %d times; candidate stopped before target: %+v", refusals, rep)
	}
	if rep.State == StateAdopted {
		t.Fatalf("adopted through a refusing target: %+v", rep)
	}
	if after := e.p.Files("routing"); len(after) != len(before) || len(after) != 0 {
		t.Fatalf("active routing changed: %v -> %v", before, after)
	}
	if len(e.p.Adoptions()) != 0 {
		t.Fatalf("adoptions %+v", e.p.Adoptions())
	}
}

type emptyRouter struct{}

func (emptyRouter) Rule() routerule.Rule         { return nil }
func (emptyRouter) SetRule(routerule.Rule) error { return nil }
func (emptyRouter) Candidate() routerule.Rule    { return nil }

// ADP-4: a router with no proposal (the vault process unreachable, or no
// rule yet) proposes nothing, even while the active routing tree is empty.
func TestAnEmptyRoutingProposalIsNoCandidate(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Targets = map[string]Target{"routing": refusingRouting{}} })
	if _, changed, err := e.p.ProposeRouting(bg, emptyRouter{}); changed || err != nil {
		t.Fatalf("an empty proposal: %v %v", changed, err)
	}
}
