package loops

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/route"
)

// REQ: LOOP-5, LOOP-2, OP-8, ADP-4, CAP-9
//
// Replay's model access (replay ASSUMPTIONS R2): the order among routes
// comes from the tree under test; grants, data labels, and the private-data
// allowance come from the broker (K1); calls are charged to the spare
// budget, never a work budget (K2); and builders see no record of them (K3).

type providers struct {
	mu   sync.Mutex
	hits map[string]int
}

func (p *providers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	p.mu.Lock()
	p.hits[name]++
	p.mu.Unlock()
	file := map[string]string{"openai": "openai_completion.json", "anthropic": "anthropic_message.json"}[name]
	b, err := os.ReadFile("../route/testdata/" + file)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (p *providers) count(name string) int { p.mu.Lock(); defer p.mu.Unlock(); return p.hits[name] }

func rule(routes ...string) []byte {
	var rs []route.Route
	for _, s := range routes {
		p, m, _ := strings.Cut(s, "/")
		rs = append(rs, route.Route{Provider: p, Model: m})
	}
	b, _ := json.Marshal(route.Rule{"chat": rs})
	return b
}

func evalModel(up http.Handler, granted []string, privateOK []string, calls *CallCount) EvalModel {
	g := map[string]bool{}
	for _, p := range granted {
		g[p] = true
	}
	ok := map[string]bool{}
	for _, p := range privateOK {
		ok[p] = true
	}
	return EvalModel{
		Providers: []route.Provider{route.OpenAI(), route.Anthropic()},
		Granted:   func(p string) bool { return g[p] },
		PrivateOK: ok,
		Upstream:  up,
		Active:    func() route.Rule { return route.Rule{"chat": {{Provider: "openai", Model: "gpt"}}} },
		Calls:     calls,
	}
}

func chat(t *testing.T, h http.Handler) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"chat","messages":[{"role":"user","content":"draft the reply"}],"max_completion_tokens":100}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

func TestReplayRoutesByTheTreeAmongGrantedRoutes(t *testing.T) {
	up := &providers{hits: map[string]int{}}
	m := evalModel(up, []string{"openai", "anthropic"}, []string{"openai", "anthropic"}, &CallCount{})
	// The candidate's order is what is measured.
	tree := change.Tree{change.RoutingPath: rule("anthropic/claude-x", "openai/gpt")}
	if code := chat(t, m.Handler(tree)); code != 200 || up.count("anthropic") != 1 || up.count("openai") != 0 {
		t.Fatalf("code %d, hits %v: the tree's first route should serve", code, up.hits)
	}
	// A tree without a rule replays under the active one.
	if code := chat(t, m.Handler(change.Tree{})); code != 200 || up.count("openai") != 1 {
		t.Fatalf("code %d, hits %v: the active rule should serve", code, up.hits)
	}
}

func TestReplayNeverUsesARouteTheBrokerDidNotAllow(t *testing.T) {
	up := &providers{hits: map[string]int{}}
	calls := &CallCount{}
	// Only openai is granted; the candidate puts anthropic first.
	m := evalModel(up, []string{"openai"}, []string{"openai", "anthropic"}, calls)
	if code := chat(t, m.Handler(change.Tree{change.RoutingPath: rule("anthropic/claude-x", "openai/gpt")})); code != 200 || up.count("anthropic") != 0 {
		t.Fatalf("ungranted provider reached (code %d, hits %v)", code, up.hits)
	}
	if code := chat(t, m.Handler(change.Tree{change.RoutingPath: rule("anthropic/claude-x")})); code == 200 || up.count("anthropic") != 0 {
		t.Fatalf("a rule of only ungranted routes was served (code %d, hits %v)", code, up.hits)
	}
	// Replays are private: a provider not allowed private data is never
	// sent a case, whatever the tree says.
	m = evalModel(up, []string{"openai", "anthropic"}, []string{"anthropic"}, calls)
	before := up.count("openai")
	if code := chat(t, m.Handler(change.Tree{change.RoutingPath: rule("openai/gpt")})); code == 200 || up.count("openai") != before {
		t.Fatalf("private case sent to a provider not allowed private data (code %d)", code)
	}
	// A rule naming an undeclared provider fails the candidate; it never
	// falls back to another rule.
	if code := chat(t, m.Handler(change.Tree{change.RoutingPath: rule("local/llama")})); code != http.StatusBadRequest {
		t.Fatalf("undeclared provider: code %d", code)
	}
	if served, denied := calls.Counts(); served != 1 || denied != 2 {
		t.Fatalf("counts served %d denied %d", served, denied)
	}
}

func TestReplayModelCallsSpendOnlyTheSpareBudget(t *testing.T) {
	r := newRig(t)
	up := &providers{hits: map[string]int{}}
	m := evalModel(up, []string{"openai"}, []string{"openai"}, &CallCount{})
	// The replay plane wraps each run's handler with the spare meter
	// (replay.Config.Meter); run IDs are fresh, so the overall cap is what
	// bounds evaluation.
	req, _ := ParseText("spare budget 3")
	must(t, r.s.Set(context.Background(), req))
	for i := 0; i < 3; i++ {
		h := r.spare.Wrap("eval-run"+string(rune('a'+i)), m.Handler(change.Tree{}))
		if code := chat(t, h); code != 200 {
			t.Fatalf("call %d: %d", i, code)
		}
	}
	h := r.spare.Wrap("eval-rund", m.Handler(change.Tree{}))
	if code := chat(t, h); code != http.StatusTooManyRequests || up.count("openai") != 3 {
		t.Fatalf("call past the spare budget: code %d, provider calls %d", code, up.count("openai"))
	}
	if used, _ := r.spare.Overall(); used.Calls != 3 {
		t.Fatalf("spare use %+v", used)
	}
}

func TestBuildersSeeOnlyTheHypothesisAndTheDevSplit(t *testing.T) {
	// K3 and C14 (d): nothing about evaluations reaches a builder. If a
	// field is added here, it must be one a builder may see.
	var names []string
	for _, f := range reflect.VisibleFields(reflect.TypeOf(Brief{})) {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "Dev,Hypothesis" {
		t.Fatalf("Brief fields %v", names)
	}
	var hf []string
	for _, f := range reflect.VisibleFields(reflect.TypeOf(Hypothesis{})) {
		hf = append(hf, f.Name)
	}
	sort.Strings(hf)
	if strings.Join(hf, ",") != "Class,Evidence,Key,Signal,Tasks" {
		t.Fatalf("Hypothesis fields %v", hf)
	}
}
