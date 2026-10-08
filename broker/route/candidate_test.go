package route

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// REQ: CAP-9, ADP-4
// These are transport observations, not judgments of completed-task acceptance.
const candidateSamples = 10

var candidateRoutes = []Route{{Provider: "anthropic", Model: "claude-fixture"}, {Provider: "openai", Model: "gpt-fixture"}}

type candidateRig struct {
	router *Router
	ticks  *atomic.Int64
}

// Each machine is granted only its named provider, letting the fixture collect
// evidence for both routes without adopting any candidate or bypassing a grant.
func newCandidateRig(t *testing.T, rule Rule, response func(provider, class string, w http.ResponseWriter)) candidateRig {
	t.Helper()
	var ticks atomic.Int64
	r, err := New(Config{
		Providers: []Provider{Anthropic(), OpenAI()},
		Rule:      rule,
		Granted:   func(machine, provider string) bool { return machine == provider },
		Label:     func(string) string { return LabelPublic },
		Audit:     func(Decision) {},
		Cooldown:  time.Nanosecond,
		Now:       func() time.Time { return time.Unix(0, ticks.Add(1)) },
		Upstream: func(machine string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var body struct {
					Messages []struct{ Content json.RawMessage }
				}
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil || len(body.Messages) != 1 {
					t.Errorf("bad fixture request: %v", err)
					w.WriteHeader(400)
					return
				}
				var class string
				if err := json.Unmarshal(body.Messages[0].Content, &class); err != nil {
					var blocks []struct{ Text string }
					if err := json.Unmarshal(body.Messages[0].Content, &blocks); err != nil || len(blocks) != 1 {
						t.Errorf("bad fixture content: %s", body.Messages[0].Content)
						w.WriteHeader(400)
						return
					}
					class = blocks[0].Text
				}
				response(machine, class, w)
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return candidateRig{router: r, ticks: &ticks}
}

func (r candidateRig) call(class, provider string) int {
	b, _ := json.Marshal(map[string]any{"model": class, "messages": []map[string]string{{"role": "user", "content": class}}})
	w := httptest.NewRecorder()
	r.router.Handler(provider).ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(string(b))))
	return w.Code
}

func candidateReply(t *testing.T) func(string, http.ResponseWriter) {
	t.Helper()
	a, o := fixture(t, "anthropic_message.json"), fixture(t, "openai_completion.json")
	return func(provider string, w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		if provider == "anthropic" {
			w.Write(a)
		} else {
			w.Write(o)
		}
	}
}

func requireCandidate(t *testing.T, r *Router, class string, want []Route) {
	t.Helper()
	if got := r.Candidate()[class]; !reflect.DeepEqual(got, want) {
		t.Fatalf("%s candidate = %v, want %v", class, got, want)
	}
}

func TestCandidateUsesClassEvidence(t *testing.T) {
	reply := candidateReply(t)
	rule := Rule{"edit": candidateRoutes, "research": candidateRoutes, "unseen": candidateRoutes}
	r := newCandidateRig(t, rule, func(provider, class string, w http.ResponseWriter) {
		if (class == "edit" && provider == "anthropic") || (class == "research" && provider == "openai") {
			w.WriteHeader(503)
			return
		}
		reply(provider, w)
	})
	for i := 0; i < candidateSamples; i++ {
		for _, class := range []string{"edit", "research"} {
			for _, provider := range []string{"anthropic", "openai"} {
				r.call(class, provider)
			}
		}
	}
	requireCandidate(t, r.router, "edit", []Route{candidateRoutes[1], candidateRoutes[0]})
	requireCandidate(t, r.router, "research", candidateRoutes)
	requireCandidate(t, r.router, "unseen", candidateRoutes)
	if !reflect.DeepEqual(r.router.Rule(), rule) {
		t.Fatal("proposal adopted itself")
	}
	if got := r.router.Stats(); got[candidateRoutes[0].String()].Calls != 2*candidateSamples || got[candidateRoutes[1].String()].Calls != 2*candidateSamples {
		t.Fatalf("aggregate diagnostics changed: %v", got)
	}
}

func TestCandidateLeavesSparseClassUnchanged(t *testing.T) {
	reply := candidateReply(t)
	r := newCandidateRig(t, Rule{"edit": candidateRoutes, "research": candidateRoutes}, func(provider, _ string, w http.ResponseWriter) {
		if provider == "anthropic" {
			w.WriteHeader(503)
			return
		}
		reply(provider, w)
	})
	for i := 0; i < candidateSamples; i++ {
		r.call("edit", "anthropic")
		r.call("edit", "openai")
	}
	for i := 0; i < candidateSamples-1; i++ {
		r.call("research", "anthropic")
		r.call("research", "openai")
	}
	requireCandidate(t, r.router, "edit", []Route{candidateRoutes[1], candidateRoutes[0]})
	requireCandidate(t, r.router, "research", candidateRoutes)
	// One measured route cannot displace an absent or insufficiently measured one.
	r.call("research", "openai")
	requireCandidate(t, r.router, "research", candidateRoutes)
	r.call("research", "anthropic")
	requireCandidate(t, r.router, "research", []Route{candidateRoutes[1], candidateRoutes[0]})
}

func TestCandidateDoesNotLearnFromRefusals(t *testing.T) {
	for _, kind := range []string{"guest-error", "proxy-denial", "no-grant", "unknown-class"} {
		t.Run(kind, func(t *testing.T) {
			reply := candidateReply(t)
			r := newCandidateRig(t, Rule{"edit": candidateRoutes}, func(provider, _ string, w http.ResponseWriter) {
				if provider == "anthropic" {
					if kind == "proxy-denial" {
						w.Header().Set(deniedHeader, "true")
						w.WriteHeader(503)
					} else {
						w.WriteHeader(400)
					}
					return
				}
				reply(provider, w)
			})
			for i := 0; i < candidateSamples; i++ {
				provider, class := "anthropic", "edit"
				if kind == "no-grant" {
					provider = "ungranted"
				}
				if kind == "unknown-class" {
					class = "unconfigured"
				}
				r.call(class, provider)
				r.call("edit", "openai")
			}
			requireCandidate(t, r.router, "edit", candidateRoutes)
			if got := r.router.Stats()[candidateRoutes[0].String()].Calls; got != 0 {
				t.Fatalf("refusals counted: %d", got)
			}
		})
	}
}

func TestCandidateModelReplacementAndReorder(t *testing.T) {
	reply := candidateReply(t)
	r := newCandidateRig(t, Rule{"edit": candidateRoutes}, func(provider, _ string, w http.ResponseWriter) {
		if provider == "anthropic" {
			w.WriteHeader(503)
			return
		}
		reply(provider, w)
	})
	for i := 0; i < candidateSamples; i++ {
		r.call("edit", "anthropic")
		r.call("edit", "openai")
	}
	reversed := []Route{candidateRoutes[1], candidateRoutes[0]}
	requireCandidate(t, r.router, "edit", reversed)
	if err := r.router.SetRule(Rule{"edit": reversed}); err != nil {
		t.Fatal(err)
	}
	if err := r.router.SetRule(Rule{"edit": candidateRoutes}); err != nil {
		t.Fatal(err)
	}
	requireCandidate(t, r.router, "edit", reversed) // reordering retains the evidence
	changed := append([]Route(nil), candidateRoutes...)
	changed[1].Model = "gpt-new-version"
	if err := r.router.SetRule(Rule{"edit": changed}); err != nil {
		t.Fatal(err)
	}
	requireCandidate(t, r.router, "edit", changed)
	if err := r.router.SetRule(Rule{"edit": candidateRoutes}); err != nil {
		t.Fatal(err)
	}
	requireCandidate(t, r.router, "edit", candidateRoutes) // old identity does not resurrect scores
}

func TestCandidateDiscardsRemovedModelInflightEvidence(t *testing.T) {
	reply := candidateReply(t)
	started, finish := make(chan struct{}), make(chan struct{})
	var block atomic.Bool
	r := newCandidateRig(t, Rule{"edit": candidateRoutes}, func(provider, _ string, w http.ResponseWriter) {
		if provider == "anthropic" {
			w.WriteHeader(503)
			return
		}
		if block.Load() {
			close(started)
			<-finish
		}
		reply(provider, w)
	})
	for i := 0; i < candidateSamples; i++ {
		r.call("edit", "anthropic")
		if i < candidateSamples-1 {
			r.call("edit", "openai")
		}
	}
	block.Store(true)
	done := make(chan struct{})
	go func() { defer close(done); r.call("edit", "openai") }()
	<-started
	if err := r.router.SetRule(Rule{"edit": {candidateRoutes[0]}}); err != nil {
		t.Fatal(err)
	}
	if err := r.router.SetRule(Rule{"edit": candidateRoutes}); err != nil {
		t.Fatal(err)
	}
	close(finish)
	<-done
	requireCandidate(t, r.router, "edit", candidateRoutes)
}

func TestCandidateConcurrentEvidenceAndRuleChanges(t *testing.T) {
	reply := candidateReply(t)
	rule := Rule{"edit": candidateRoutes, "research": candidateRoutes}
	r := newCandidateRig(t, rule, func(provider, _ string, w http.ResponseWriter) { reply(provider, w) })
	var wg sync.WaitGroup
	for _, class := range []string{"edit", "research"} {
		for _, provider := range []string{"anthropic", "openai"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 30; i++ {
					if code := r.call(class, provider); code != 200 {
						t.Errorf("call returned %d", code)
					}
				}
			}()
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if err := r.router.SetRule(rule); err != nil {
				t.Error(err)
			}
			cand := r.router.Candidate()
			if len(cand) != 2 {
				t.Errorf("incoherent rule: %v", cand)
			}
			for _, routes := range cand {
				if len(routes) != 2 || routes[0] == routes[1] {
					t.Errorf("not a permutation: %v", routes)
				}
			}
			r.router.Stats()
		}
	}()
	wg.Wait()
	for _, rt := range candidateRoutes {
		if got := r.router.Stats()[rt.String()].Calls; got != 60 {
			t.Fatalf("lost observations: %s: %d", rt, got)
		}
	}
}

// The tie-breaker is explicitly header latency; identical evidence must not
// create churn, including after a separately adopted reorder.
func TestCandidateHeaderLatencyAndStableTies(t *testing.T) {
	reply := candidateReply(t)
	var r candidateRig
	r = newCandidateRig(t, Rule{"latency": candidateRoutes, "tied": candidateRoutes}, func(provider, class string, w http.ResponseWriter) {
		delay := int64(10)
		if class == "latency" && provider == "anthropic" {
			delay = 20
		}
		r.ticks.Add(delay)
		reply(provider, w)
	})
	for i := 0; i < candidateSamples; i++ {
		for _, class := range []string{"latency", "tied"} {
			for _, provider := range []string{"anthropic", "openai"} {
				r.call(class, provider)
			}
		}
	}
	reversed := []Route{candidateRoutes[1], candidateRoutes[0]}
	requireCandidate(t, r.router, "latency", reversed)
	requireCandidate(t, r.router, "tied", candidateRoutes)
	if err := r.router.SetRule(Rule{"tied": reversed}); err != nil {
		t.Fatal(err)
	}
	requireCandidate(t, r.router, "tied", reversed)
	// Candidate and Rule return owned slices, never mutable router state.
	cand := r.router.Candidate()
	cand["tied"][0].Model = "guest-replacement"
	requireCandidate(t, r.router, "tied", reversed)
	if got := r.router.Rule()["tied"]; !reflect.DeepEqual(got, reversed) {
		t.Fatalf("candidate aliased active rule: %v", got)
	}
}

type renamedProvider struct {
	Provider
	name string
}

func (p renamedProvider) Name() string { return p.name }

func TestCandidateUsesStructuredRouteIdentity(t *testing.T) {
	// Display strings intentionally collide; provider and model are still
	// distinct configured identities and cannot share candidate evidence.
	routes := []Route{{Provider: "a", Model: "b/c"}, {Provider: "a/b", Model: "c"}}
	body := fixture(t, "openai_completion.json")
	router, err := New(Config{
		Providers: []Provider{renamedProvider{OpenAI(), "a"}, renamedProvider{OpenAI(), "a/b"}},
		Rule:      Rule{"edit": routes},
		Granted:   func(machine, provider string) bool { return machine == provider },
		Label:     func(string) string { return LabelPublic },
		Audit:     func(Decision) {},
		Cooldown:  time.Nanosecond,
		Upstream: func(machine string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if machine == "a" {
					w.WriteHeader(503)
					return
				}
				w.Write(body)
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := candidateRig{router: router}
	for i := 0; i < candidateSamples; i++ {
		r.call("edit", "a")
		r.call("edit", "a/b")
	}
	requireCandidate(t, router, "edit", []Route{routes[1], routes[0]})
}

func TestCandidateClassRemovalDropsEvidence(t *testing.T) {
	reply := candidateReply(t)
	r := newCandidateRig(t, Rule{"edit": candidateRoutes, "keeper": candidateRoutes}, func(provider, _ string, w http.ResponseWriter) {
		if provider == "anthropic" {
			w.WriteHeader(503)
			return
		}
		reply(provider, w)
	})
	for i := 0; i < candidateSamples; i++ {
		r.call("edit", "anthropic")
		r.call("edit", "openai")
	}
	requireCandidate(t, r.router, "edit", []Route{candidateRoutes[1], candidateRoutes[0]})
	if err := r.router.SetRule(Rule{"keeper": candidateRoutes}); err != nil {
		t.Fatal(err)
	}
	if len(r.router.evidence) != 2 {
		t.Fatalf("inactive evidence retained: %v", r.router.evidence)
	}
	if err := r.router.SetRule(Rule{"keeper": candidateRoutes, "edit": candidateRoutes}); err != nil {
		t.Fatal(err)
	}
	requireCandidate(t, r.router, "edit", candidateRoutes)
}
