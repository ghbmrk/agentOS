package route

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CAP-9, ADP-3, ADP-4, ADP-7, CRED-5, REV-5
//
// The router in front of the real egress proxy, with both providers played
// by one fake TLS server that answers per Host from the fixtures.
// ADP-7 is partly covered: a route that breaks (rejected key, server
// errors) is rerouted to the next healthy granted route; the Loop 3 repair
// candidate is not here.

type upstream struct {
	mu      sync.Mutex
	reply   map[string]http.HandlerFunc // host -> reply
	seen    map[string]int
	headers map[string][]http.Header
	bodies  map[string][][]byte
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.seen[r.Host]++
	u.headers[r.Host] = append(u.headers[r.Host], r.Header.Clone())
	u.bodies[r.Host] = append(u.bodies[r.Host], b)
	h := u.reply[r.Host]
	u.mu.Unlock()
	if h == nil {
		http.Error(w, "no reply set", 500)
		return
	}
	h(w, r)
}

func (u *upstream) set(host string, h http.HandlerFunc) {
	u.mu.Lock()
	u.reply[host] = h
	u.mu.Unlock()
}

func (u *upstream) count(host string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.seen[host]
}

func (u *upstream) lastBody(host string) []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	bs := u.bodies[host]
	return bs[len(bs)-1]
}

const (
	hostOpenAI    = "api.openai.com"
	hostAnthropic = "api.anthropic.com"
)

func serveFixture(status int, ctype string, body []byte, hdr ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ctype)
		for i := 0; i+1 < len(hdr); i += 2 {
			w.Header().Set(hdr[i], hdr[i+1])
		}
		w.WriteHeader(status)
		w.Write(body)
	}
}

type rig struct {
	up        *upstream
	router    *Router
	keys      map[string]string
	mu        sync.Mutex
	decisions []Decision
	egress    []egress.Event
	now       time.Time
	grants    map[string][]string
	labels    map[string]string
	px        *egress.Proxy
}

func (r *rig) Egress(e egress.Event) {
	r.mu.Lock()
	r.egress = append(r.egress, e)
	r.mu.Unlock()
}

func (r *rig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now
}

func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func synthetic(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + hex.EncodeToString(b)
}

type rigOpts struct {
	rule      Rule
	grants    map[string][]string
	labels    map[string]string
	privateOK map[string]bool
	cap       egress.Cap
	maxOut    int
}

func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	up := &upstream{reply: map[string]http.HandlerFunc{}, seen: map[string]int{}, headers: map[string][]http.Header{}, bodies: map[string][][]byte{}}
	srv := httptest.NewTLSServer(up)
	t.Cleanup(srv.Close)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	kb := make([]byte, vault.KeySize)
	rand.Read(kb)
	v, err := vault.Create(filepath.Join(t.TempDir(), "vault"), kb)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	keys := map[string]string{"openai": synthetic(t, "sk-canary-oa-"), "anthropic": synthetic(t, "sk-ant-canary-")}
	for name, k := range keys {
		if err := v.Put(name+"-key", vault.KindAPIKey, []byte(k)); err != nil {
			t.Fatal(err)
		}
	}
	if o.grants == nil {
		o.grants = map[string][]string{"m1": {"openai", "anthropic"}}
	}
	if o.rule == nil {
		o.rule = Rule{"default": {{"anthropic", "claude-fixture"}, {"openai", "gpt-fixture"}}}
	}
	if o.labels == nil {
		o.labels = map[string]string{"m1": LabelPublic}
	}
	r := &rig{up: up, keys: keys, now: time.Unix(1_790_000_000, 0), grants: o.grants, labels: o.labels}
	label := func(m string) string { return r.labels[m] }
	px, err := egress.New(egress.Config{
		Adapters:  []egress.Adapter{egress.OpenAI("openai-key"), egress.Anthropic("anthropic-key")},
		Grants:    o.grants,
		Vault:     v,
		Transport: tr,
		Audit:     r,
		Label:     label,
		Cap:       o.cap,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.px = px
	r.router, err = New(Config{
		Providers: []Provider{OpenAI(), Anthropic()},
		Rule:      o.rule,
		Granted: func(m, p string) bool {
			for _, g := range r.grants[m] {
				if g == p {
					return true
				}
			}
			return false
		},
		PrivateOK:       o.privateOK,
		MaxOutputTokens: o.maxOut,
		Label:           label,
		Upstream:        px.Handler,
		Audit: func(d Decision) {
			r.mu.Lock()
			r.decisions = append(r.decisions, d)
			r.mu.Unlock()
		},
		Now: r.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const simpleChat = `{"model":"default","messages":[{"role":"user","content":"hello"}]}`

func (r *rig) do(t *testing.T, machine, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer placeholder-guest-key")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.router.Handler(machine).ServeHTTP(w, req)
	return w
}

func completionText(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var c struct {
		Choices []struct{ Message struct{ Content string } }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || len(c.Choices) == 0 {
		t.Fatalf("not a completion (%d): %s", w.Code, w.Body)
	}
	return c.Choices[0].Message.Content
}

// The first route serves; its body is the translated request with the
// route's model; the key on the wire is the vault's, injected by egress.
func TestServesFromFirstRouteThroughEgress(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))
	w := r.do(t, "m1", simpleChat)
	if w.Code != 200 || completionText(t, w) != "Checking the weather." {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if r.up.count(hostOpenAI) != 0 {
		t.Fatal("second route contacted although the first served")
	}
	h := r.up.headers[hostAnthropic][0]
	if h.Get("X-Api-Key") != r.keys["anthropic"] || h.Get("Authorization") != "" {
		t.Fatalf("credential on the wire: x-api-key=%q authorization=%q", h.Get("X-Api-Key"), h.Get("Authorization"))
	}
	if h.Get("Anthropic-Version") != AnthropicVersion {
		t.Fatalf("anthropic-version %q", h.Get("Anthropic-Version"))
	}
	var sent aRequest
	json.Unmarshal(r.up.lastBody(hostAnthropic), &sent)
	if sent.Model != "claude-fixture" || sent.Messages[0].Content[0].Text != "hello" {
		t.Fatalf("sent %s", r.up.lastBody(hostAnthropic))
	}
	d := r.decisions[len(r.decisions)-1]
	if d.Outcome != Served || d.Route != "anthropic/claude-fixture" || d.Class != "default" || d.Machine != "m1" {
		t.Fatalf("decision %+v", d)
	}
}

// CAP-9 and A15: an exhausted route fails over to the next granted route,
// and stays skipped until its Retry-After passes.
func TestFailsOverOnExhaustionAndHonorsRetryAfter(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.up.set(hostAnthropic, serveFixture(429, "application/json", fixture(t, "anthropic_rate_limit.json"), "Retry-After", "30"))
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))

	w := r.do(t, "m1", simpleChat)
	if w.Code != 200 || completionText(t, w) != "Hello from the fixture." {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if r.up.count(hostAnthropic) != 1 || r.up.count(hostOpenAI) != 1 {
		t.Fatalf("calls anthropic=%d openai=%d", r.up.count(hostAnthropic), r.up.count(hostOpenAI))
	}
	var sent map[string]any
	json.Unmarshal(r.up.lastBody(hostOpenAI), &sent)
	if sent["model"] != "gpt-fixture" || sent["store"] != false {
		t.Fatalf("openai body %v", sent)
	}

	r.advance(10 * time.Second)
	if w := r.do(t, "m1", simpleChat); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	if r.up.count(hostAnthropic) != 1 {
		t.Fatal("exhausted route retried before its Retry-After")
	}
	r.advance(25 * time.Second)
	r.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))
	if w := r.do(t, "m1", simpleChat); w.Code != 200 || completionText(t, w) != "Checking the weather." {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	st := r.router.Stats()
	if a := st["anthropic/claude-fixture"]; a.Calls != 2 || a.OK != 1 || a.Failovers != 1 {
		t.Fatalf("anthropic stats %+v", a)
	}
	if o := st["openai/gpt-fixture"]; o.Calls != 2 || o.OK != 2 || o.Bytes == 0 {
		t.Fatalf("openai stats %+v", o)
	}
}

// Overload, server errors, and a rejected key fail over; a request the
// provider calls invalid does not (it would be invalid everywhere).
func TestFailoverStatuses(t *testing.T) {
	cases := []struct {
		status int
		body   []byte
		over   bool
	}{
		{529, fixture(t, "anthropic_overloaded.json"), true},
		{500, []byte(`{"type":"error","error":{"type":"api_error","message":"x"}}`), true},
		{401, []byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`), true},
		{400, fixture(t, "anthropic_invalid.json"), false},
	}
	for _, c := range cases {
		r := newRig(t, rigOpts{})
		r.up.set(hostAnthropic, serveFixture(c.status, "application/json", c.body))
		r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
		w := r.do(t, "m1", simpleChat)
		if c.over {
			if w.Code != 200 || r.up.count(hostOpenAI) != 1 {
				t.Fatalf("%d: want failover, got %d %s", c.status, w.Code, w.Body)
			}
			continue
		}
		if w.Code != c.status || r.up.count(hostOpenAI) != 0 {
			t.Fatalf("%d: want the provider's answer, got %d, openai=%d", c.status, w.Code, r.up.count(hostOpenAI))
		}
		var e struct {
			Error struct{ Type, Message string }
		}
		json.Unmarshal(w.Body.Bytes(), &e)
		if e.Error.Type != "invalid_request_error" || !strings.Contains(e.Error.Message, "alternate") {
			t.Fatalf("guest error %s", w.Body)
		}
	}
}

// CAP-9: routing never adds a provider. A rule that lists a provider the
// machine was not granted never reaches it, even when every granted route
// is exhausted.
func TestNeverRoutesToUngrantedProvider(t *testing.T) {
	r := newRig(t, rigOpts{
		rule:   Rule{"default": {{"openai", "gpt-fixture"}, {"anthropic", "claude-fixture"}}},
		grants: map[string][]string{"m1": {"anthropic"}},
	})
	r.up.set(hostAnthropic, serveFixture(429, "application/json", fixture(t, "anthropic_rate_limit.json")))
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	w := r.do(t, "m1", simpleChat)
	if w.Code != 429 || r.up.count(hostOpenAI) != 0 {
		t.Fatalf("got %d, openai contacted %d times", w.Code, r.up.count(hostOpenAI))
	}
	var e struct{ Error struct{ Type string } }
	json.Unmarshal(w.Body.Bytes(), &e)
	if e.Error.Type != "rate_limit_error" {
		t.Fatalf("guest error %s", w.Body)
	}
	// While the only granted route cools down, the guest is told to wait;
	// still nothing reaches the ungranted provider.
	w = r.do(t, "m1", simpleChat)
	if w.Code != 429 || r.up.count(hostOpenAI) != 0 || r.up.count(hostAnthropic) != 1 {
		t.Fatalf("got %d, openai=%d anthropic=%d", w.Code, r.up.count(hostOpenAI), r.up.count(hostAnthropic))
	}
	// A machine granted nothing gets nothing.
	w = r.do(t, "m2", simpleChat)
	if w.Code != 403 {
		t.Fatalf("ungranted machine got %d", w.Code)
	}
}

// CAP-9 and REV-5: private-class calls go only to providers the owner
// allowed for private data; unknown labels count as private; no rule
// overrides it.
func TestPrivateCallsOnlyToPrivateAllowedProviders(t *testing.T) {
	r := newRig(t, rigOpts{
		rule:      Rule{"default": {{"openai", "gpt-fixture"}, {"anthropic", "claude-fixture"}}},
		grants:    map[string][]string{"pub": {"openai", "anthropic"}, "priv": {"openai", "anthropic"}, "unlabelled": {"openai", "anthropic"}},
		labels:    map[string]string{"pub": LabelPublic, "priv": "private"},
		privateOK: map[string]bool{"anthropic": true},
	})
	r.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))

	if w := r.do(t, "pub", simpleChat); w.Code != 200 || r.up.count(hostOpenAI) != 1 {
		t.Fatalf("public machine: %d, openai=%d", w.Code, r.up.count(hostOpenAI))
	}
	for _, m := range []string{"priv", "unlabelled"} {
		if w := r.do(t, m, simpleChat); w.Code != 200 || completionText(t, w) != "Checking the weather." {
			t.Fatalf("%s: %d %s", m, w.Code, w.Body)
		}
	}
	if r.up.count(hostOpenAI) != 1 {
		t.Fatal("a private machine's call reached a provider not allowed for private data")
	}
	// An adopted rule that puts openai alone cannot change that.
	if err := r.router.SetRule(Rule{"default": {{"openai", "gpt-fixture"}}}); err != nil {
		t.Fatal(err)
	}
	if w := r.do(t, "priv", simpleChat); w.Code != 403 || r.up.count(hostOpenAI) != 1 {
		t.Fatalf("private machine under openai-only rule: %d, openai=%d", w.Code, r.up.count(hostOpenAI))
	}
}

// With no provider marked private-allowed (the default), a private machine
// has no model route at all.
func TestDefaultNoProviderForPrivateData(t *testing.T) {
	r := newRig(t, rigOpts{labels: map[string]string{"m1": "private"}})
	if w := r.do(t, "m1", simpleChat); w.Code != 403 || r.up.count(hostOpenAI)+r.up.count(hostAnthropic) != 0 {
		t.Fatalf("%d", w.Code)
	}
}

// ADP-3: the router picks the first route that covers the call. A request
// the Messages API cannot express skips that route without sending it.
func TestSkipsRouteThatCannotExpressTheCall(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	w := r.do(t, "m1", `{"model":"default","n":2,"messages":[{"role":"user","content":"hi"}]}`)
	if w.Code != 200 || r.up.count(hostAnthropic) != 0 || r.up.count(hostOpenAI) != 1 {
		t.Fatalf("%d anthropic=%d openai=%d", w.Code, r.up.count(hostAnthropic), r.up.count(hostOpenAI))
	}
	// With only the route that cannot express it, the guest is told why.
	r2 := newRig(t, rigOpts{rule: Rule{"default": {{"anthropic", "claude-fixture"}}}})
	w = r2.do(t, "m1", `{"model":"default","n":2,"messages":[{"role":"user","content":"hi"}]}`)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "n other than 1") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// Egress policy still applies under the router: a private machine's
// remote image source is denied by the proxy and not retried elsewhere.
func TestEgressBodyRulesStillApply(t *testing.T) {
	r := newRig(t, rigOpts{labels: map[string]string{"m1": "private"}, privateOK: map[string]bool{"anthropic": true, "openai": true}})
	body := `{"model":"default","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://attacker.example/x.png"}}]}]}`
	w := r.do(t, "m1", body)
	if w.Code != 403 || r.up.count(hostAnthropic)+r.up.count(hostOpenAI) != 0 {
		t.Fatalf("%d anthropic=%d openai=%d", w.Code, r.up.count(hostAnthropic), r.up.count(hostOpenAI))
	}
}

func TestUnknownClassAndBadRequests(t *testing.T) {
	r := newRig(t, rigOpts{})
	for _, c := range []struct {
		method, path, body string
		code               int
	}{
		{"POST", "/v1/chat/completions", `{"model":"nope","messages":[{"role":"user","content":"x"}]}`, 404},
		{"POST", "/v1/chat/completions", `{"model":"default","messages":[{"role":"user","content":"x"}]} {}`, 400},
		{"POST", "/v1/chat/completions", `{"model":"default","messages":[{"role":"user","content":"x"}],"tools":[{"type":"web_search"}]}`, 400},
		{"POST", "/v1/responses", simpleChat, 404},
		{"GET", "/v1/chat/completions", "", 404},
		{"POST", "/v1/chat/completions?x=1", simpleChat, 404},
	} {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		w := httptest.NewRecorder()
		r.router.Handler("m1").ServeHTTP(w, req)
		if w.Code != c.code {
			t.Fatalf("%s %s %s: got %d want %d", c.method, c.path, c.body, w.Code, c.code)
		}
		var e struct{ Error struct{ Message string } }
		if json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Error.Message == "" {
			t.Fatalf("not an OpenAI error body: %s", w.Body)
		}
	}
	if r.up.count(hostAnthropic)+r.up.count(hostOpenAI) != 0 {
		t.Fatal("a refused request reached a provider")
	}
}

// Streaming through the proxy: Messages events arrive as chat chunks.
func TestStreamsTranslatedThroughEgress(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.up.set(hostAnthropic, serveFixture(200, "text/event-stream", fixture(t, "anthropic_stream.sse")))
	w := r.do(t, "m1", `{"model":"default","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`)
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	a := reassemble(t, w.Body.Bytes())
	if !a.done || a.text != "Hello, world" || a.names[0] != "get_weather" || a.usage["completion_tokens"] != float64(32) {
		t.Fatalf("%+v", a)
	}
	var sent aRequest
	json.Unmarshal(r.up.lastBody(hostAnthropic), &sent)
	if !sent.Stream {
		t.Fatal("stream not requested upstream")
	}

	// OpenAI streams pass through as sent.
	r2 := newRig(t, rigOpts{rule: Rule{"default": {{"openai", "gpt-fixture"}}}})
	r2.up.set(hostOpenAI, serveFixture(200, "text/event-stream", fixture(t, "openai_stream.sse")))
	w = r2.do(t, "m1", `{"model":"default","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if a := reassemble(t, w.Body.Bytes()); !a.done || a.text != "Hi" || a.finish != "stop" {
		t.Fatalf("%+v", a)
	}
}

// A failover before any byte reached the guest is invisible to it, also
// for streams.
func TestStreamFailsOverBeforeFirstByte(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.up.set(hostAnthropic, serveFixture(529, "application/json", fixture(t, "anthropic_overloaded.json")))
	r.up.set(hostOpenAI, serveFixture(200, "text/event-stream", fixture(t, "openai_stream.sse")))
	w := r.do(t, "m1", `{"model":"default","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if a := reassemble(t, w.Body.Bytes()); w.Code != 200 || !a.done || a.text != "Hi" {
		t.Fatalf("%d %+v", w.Code, a)
	}
}

// ADP-4: measurements propose a better order, but only SetRule (adoption
// through §11) changes routing, and a rule can name only declared
// providers.
func TestCandidateProposesButDoesNotAdopt(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.up.set(hostAnthropic, serveFixture(503, "application/json", []byte(`{}`)))
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	r.do(t, "m1", simpleChat)

	cand := r.router.Candidate()
	if cand["default"][0].Provider != "openai" || len(cand["default"]) != 2 {
		t.Fatalf("candidate %v", cand)
	}
	if r.router.Rule()["default"][0].Provider != "anthropic" {
		t.Fatal("a candidate changed the active rule without adoption")
	}
	if err := r.router.SetRule(cand); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * DefaultCooldown)
	r.do(t, "m1", simpleChat)
	if r.up.count(hostAnthropic) != 1 || r.up.count(hostOpenAI) != 2 {
		t.Fatalf("adopted rule not followed: anthropic=%d openai=%d", r.up.count(hostAnthropic), r.up.count(hostOpenAI))
	}

	for _, bad := range []Rule{
		{},
		{"default": {{"mistral", "m"}}},
		{"default": {}},
		{"default": {{"openai", ""}}},
		{"default": {{"openai", "x"}, {"openai", "x"}}},
	} {
		if err := r.router.SetRule(bad); err == nil {
			t.Fatalf("rule %v accepted", bad)
		}
	}
}

// Decisions and egress events carry no prompt, completion, or key.
func TestDecisionsCarryNoContentOrKey(t *testing.T) {
	r := newRig(t, rigOpts{})
	canary := synthetic(t, "canary-prompt-")
	r.up.set(hostAnthropic, serveFixture(429, "application/json", fixture(t, "anthropic_rate_limit.json")))
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	r.do(t, "m1", `{"model":"default","messages":[{"role":"user","content":"`+canary+`"}]}`)
	b, _ := json.Marshal(struct {
		D []Decision
		E []egress.Event
	}{r.decisions, r.egress})
	for _, s := range []string{canary, r.keys["openai"], r.keys["anthropic"], "fixture."} {
		if strings.Contains(string(b), s) {
			t.Fatalf("audit carries %q: %s", s, b)
		}
	}
	if len(r.decisions) != 2 || r.decisions[0].Outcome != Failover || r.decisions[1].Outcome != Served {
		t.Fatalf("decisions %+v", r.decisions)
	}
}

// CRED-5: the router holds no credential and opens no connection of its
// own. Its non-test code imports neither the vault nor any dialer, and
// constructs no HTTP client or transport.
func TestRouterHoldsNoCredentialAndDialsNothing(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if p == "github.com/ghbmrk/agentos/broker/vault" || p == "github.com/ghbmrk/agentos/broker/egress" ||
				p == "net" || p == "crypto/tls" || p == "os/exec" || p == "net/http/httputil" {
				t.Errorf("%s imports %s", f, p)
			}
		}
		src, _ := os.ReadFile(f)
		for _, s := range []string{"http.Client", "http.Transport", "http.DefaultClient", "http.Get(", "http.Post("} {
			if strings.Contains(string(src), s) {
				t.Errorf("%s uses %s", f, s)
			}
		}
	}
}

func TestNewRequiresWiring(t *testing.T) {
	if _, err := New(Config{Providers: []Provider{OpenAI()}, Rule: Rule{"d": {{"openai", "m"}}}}); err == nil {
		t.Fatal("router without Granted, Upstream, Audit accepted")
	}
	h := func(string) http.Handler { return http.NotFoundHandler() }
	_, err := New(Config{Providers: []Provider{OpenAI(), OpenAI()}, Rule: Rule{"d": {{"openai", "m"}}},
		Granted: func(string, string) bool { return true }, Upstream: h, Audit: func(Decision) {}})
	if err == nil {
		t.Fatal("duplicate provider accepted")
	}
}

func (r *rig) doPath(t *testing.T, machine, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	w := httptest.NewRecorder()
	r.router.Handler(machine).ServeHTTP(w, req)
	return w
}

func (r *rig) lastDecision() Decision {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.decisions[len(r.decisions)-1]
}

// The router's copy of the proxy's denial mark is the proxy's.
func TestDeniedHeaderMatchesEgress(t *testing.T) {
	if deniedHeader != egress.DeniedHeader {
		t.Fatalf("%q != %q", deniedHeader, egress.DeniedHeader)
	}
}

// CAP-9: one machine's own proxy limits never cool a route for another
// machine; the denial goes to that machine's guest as an OpenAI error.
func TestProxyLimitsStayPerMachine(t *testing.T) {
	r := newRig(t, rigOpts{
		grants: map[string][]string{"a": {"openai", "anthropic"}, "b": {"openai", "anthropic"}},
		labels: map[string]string{"a": LabelPublic, "b": LabelPublic},
		cap:    egress.Cap{Requests: 1},
	})
	r.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	if w := r.do(t, "a", simpleChat); w.Code != 200 {
		t.Fatalf("first call %d", w.Code)
	}
	w := r.do(t, "a", simpleChat)
	if w.Code != 429 || r.up.count(hostOpenAI) != 0 {
		t.Fatalf("capped machine: %d, openai=%d", w.Code, r.up.count(hostOpenAI))
	}
	var e struct {
		Error struct{ Type, Message string }
	}
	if json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Error.Type != "rate_limit_error" || !strings.Contains(e.Error.Message, "request cap") {
		t.Fatalf("guest error %s", w.Body)
	}
	if d := r.lastDecision(); d.Outcome != Denied || d.Reason != "egress denied" {
		t.Fatalf("decision %+v", d)
	}
	if w := r.do(t, "b", simpleChat); w.Code != 200 || completionText(t, w) != "Checking the weather." || r.up.count(hostAnthropic) != 2 {
		t.Fatalf("other machine: %d anthropic=%d", w.Code, r.up.count(hostAnthropic))
	}
	if st := r.router.Stats()["anthropic/claude-fixture"]; st.Failovers != 0 || st.Calls != 2 {
		t.Fatalf("proxy denial counted against the route: %+v", st)
	}
}

// OP-8 groundwork: served calls report the provider's usage, cache tokens
// included, whether or not the guest asked for it.
func TestDecisionsReportProviderUsage(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))
	r.do(t, "m1", simpleChat)
	if d := r.lastDecision(); d.Usage == nil || *d.Usage != (Usage{Input: 412, Output: 57, CacheRead: 3000, CacheWrite: 200, Reported: true, Complete: true, OutputChars: 51}) {
		t.Fatalf("decision %+v", d)
	}
	r.up.set(hostAnthropic, serveFixture(200, "text/event-stream", fixture(t, "anthropic_stream.sse")))
	w := r.do(t, "m1", `{"model":"default","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if a := reassemble(t, w.Body.Bytes()); a.usage != nil || !a.done {
		t.Fatalf("usage chunk sent unasked: %+v", a)
	}
	if d := r.lastDecision(); d.Usage == nil || *d.Usage != (Usage{Input: 25, Output: 32, CacheRead: 1800, Reported: true, Complete: true, OutputChars: 29}) {
		t.Fatalf("stream decision %+v", d)
	}

	// OpenAI: usage is always requested upstream, and its usage-only chunk
	// is dropped when the guest did not ask for it.
	r2 := newRig(t, rigOpts{rule: Rule{"default": {{"openai", "gpt-fixture"}}}})
	r2.up.set(hostOpenAI, serveFixture(200, "text/event-stream", fixture(t, "openai_stream.sse")))
	w = r2.do(t, "m1", `{"model":"default","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if a := reassemble(t, w.Body.Bytes()); a.usage != nil || !a.done || a.text != "Hi" {
		t.Fatalf("%+v", a)
	}
	var sent struct {
		StreamOptions *streamOptions `json:"stream_options"`
	}
	json.Unmarshal(r2.up.lastBody(hostOpenAI), &sent)
	if sent.StreamOptions == nil || !sent.StreamOptions.IncludeUsage {
		t.Fatalf("usage not requested upstream: %s", r2.up.lastBody(hostOpenAI))
	}
	if d := r2.lastDecision(); d.Usage == nil || *d.Usage != (Usage{Input: 9, Output: 2, CacheRead: 10, Reported: true, Complete: true, OutputChars: 2}) {
		t.Fatalf("openai stream decision %+v", d.Usage)
	}
	w = r2.do(t, "m1", `{"model":"default","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`)
	if a := reassemble(t, w.Body.Bytes()); a.usage == nil {
		t.Fatal("usage chunk dropped although the guest asked for it")
	}
}

// Every call goes upstream with an output limit at or below the owner's
// ceiling, so the meter can reserve it.
func TestOutputTokensClampedToCeiling(t *testing.T) {
	r := newRig(t, rigOpts{rule: Rule{"default": {{"openai", "gpt-fixture"}}}, maxOut: 1000})
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	for _, c := range []struct{ body, key string }{
		{simpleChat, "max_completion_tokens"},
		{`{"model":"default","max_tokens":999999,"messages":[{"role":"user","content":"x"}]}`, "max_tokens"},
		{`{"model":"default","max_completion_tokens":5000,"messages":[{"role":"user","content":"x"}]}`, "max_completion_tokens"},
	} {
		r.do(t, "m1", c.body)
		var sent map[string]any
		json.Unmarshal(r.up.lastBody(hostOpenAI), &sent)
		if sent[c.key] != float64(1000) {
			t.Fatalf("%s: sent %v", c.body, sent)
		}
	}
	r.do(t, "m1", `{"model":"default","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
	var sent map[string]any
	json.Unmarshal(r.up.lastBody(hostOpenAI), &sent)
	if sent["max_tokens"] != float64(10) {
		t.Fatalf("a lower limit must stay: %v", sent)
	}
	if r.router.MaxOutputTokens() != 1000 {
		t.Fatal("ceiling not exposed")
	}

	r2 := newRig(t, rigOpts{maxOut: 1000})
	r2.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))
	r2.do(t, "m1", `{"model":"default","max_tokens":999999,"messages":[{"role":"user","content":"x"}]}`)
	var a aRequest
	json.Unmarshal(r2.up.lastBody(hostAnthropic), &a)
	if a.MaxTokens != 1000 {
		t.Fatalf("anthropic max_tokens %d", a.MaxTokens)
	}
}

// The guest's existing base URL (the openai adapter's mount) is served too.
func TestServesOpenAIMountPath(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))
	if w := r.doPath(t, "m1", "/openai/v1/chat/completions", simpleChat); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := r.doPath(t, "m1", "/anthropic/v1/messages", simpleChat); w.Code != 404 {
		t.Fatalf("raw provider path served: %d", w.Code)
	}
}

// A stream that fails before its first byte fails over like any response.
func TestStreamErrorBeforeFirstByteFailsOver(t *testing.T) {
	r := newRig(t, rigOpts{})
	early := "event: error\ndata: " + strings.TrimSpace(string(fixture(t, "anthropic_overloaded.json"))) + "\n\n"
	r.up.set(hostAnthropic, serveFixture(200, "text/event-stream", []byte(early)))
	r.up.set(hostOpenAI, serveFixture(200, "text/event-stream", fixture(t, "openai_stream.sse")))
	w := r.do(t, "m1", `{"model":"default","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if a := reassemble(t, w.Body.Bytes()); w.Code != 200 || !a.done || a.text != "Hi" || strings.Contains(w.Body.String(), "Overloaded") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if st := r.router.Stats()["anthropic/claude-fixture"]; st.Failovers != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// Three routes with mixed outcomes: each exhausted one is passed over in
// order, and the first that answers serves.
func TestMixedOutcomesAcrossThreeRoutes(t *testing.T) {
	r := newRig(t, rigOpts{rule: Rule{"default": {
		{"anthropic", "claude-a"}, {"anthropic", "claude-b"}, {"openai", "gpt-fixture"},
	}}})
	r.up.set(hostAnthropic, func(w http.ResponseWriter, req *http.Request) {
		r.up.mu.Lock()
		b := r.up.bodies[hostAnthropic][len(r.up.bodies[hostAnthropic])-1]
		r.up.mu.Unlock()
		if strings.Contains(string(b), `"claude-a"`) {
			serveFixture(429, "application/json", fixture(t, "anthropic_rate_limit.json"))(w, req)
			return
		}
		serveFixture(500, "application/json", []byte(`{"type":"error","error":{"type":"api_error","message":"x"}}`))(w, req)
	})
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	if w := r.do(t, "m1", simpleChat); w.Code != 200 || completionText(t, w) != "Hello from the fixture." {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var outcomes []string
	for _, d := range r.decisions {
		outcomes = append(outcomes, d.Outcome+":"+d.Route)
	}
	want := "failover:anthropic/claude-a failover:anthropic/claude-b served:openai/gpt-fixture"
	if strings.Join(outcomes, " ") != want {
		t.Fatalf("%v", outcomes)
	}
}

// When every permitted route is cooling down, the guest is told when to
// retry; an HTTP-date Retry-After counts like seconds.
func TestRetryAfterReachesGuest(t *testing.T) {
	r := newRig(t, rigOpts{rule: Rule{"default": {{"anthropic", "claude-fixture"}}}})
	date := r.clock().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	r.up.set(hostAnthropic, serveFixture(429, "application/json", fixture(t, "anthropic_rate_limit.json"), "Retry-After", date))
	w := r.do(t, "m1", simpleChat)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("%d retry-after %q", w.Code, w.Header().Get("Retry-After"))
	}
	r.advance(60 * time.Second)
	w = r.do(t, "m1", simpleChat)
	if w.Code != 429 || r.up.count(hostAnthropic) != 1 {
		t.Fatalf("HTTP-date Retry-After not honored: %d, calls %d", w.Code, r.up.count(hostAnthropic))
	}
	if s, _ := strconv.Atoi(w.Header().Get("Retry-After")); s < 29 || s > 31 {
		t.Fatalf("retry-after %q", w.Header().Get("Retry-After"))
	}
}

// Requests the provider refuses as invalid do not count against the route.
func TestCandidateIgnoresGuestErrors(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.up.set(hostAnthropic, serveFixture(400, "application/json", fixture(t, "anthropic_invalid.json")))
	for i := 0; i < 3; i++ {
		r.do(t, "m1", simpleChat)
	}
	if st := r.router.Stats()["anthropic/claude-fixture"]; st.Calls != 0 {
		t.Fatalf("guest errors counted: %+v", st)
	}
	if r.router.Candidate()["default"][0].Provider != "anthropic" {
		t.Fatal("guest errors flipped the candidate")
	}
}

// With no usage in the response, the decision says so and carries the
// generated characters for the meter's fallback.
func TestUnreportedUsageFallsBackToCharacters(t *testing.T) {
	r := newRig(t, rigOpts{rule: Rule{"default": {{"openai", "gpt-fixture"}}}})
	r.up.set(hostOpenAI, serveFixture(200, "application/json", []byte(`{"choices":[{"message":{"content":"twelve chars","tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}]}}]}`)))
	r.do(t, "m1", simpleChat)
	if d := r.lastDecision(); d.Usage == nil || *d.Usage != (Usage{Complete: true, OutputChars: 14}) {
		t.Fatalf("usage %+v", d.Usage)
	}
}

// A rejected key fails over silently and tells the owner hook at most once
// per provider a day.
func TestCredentialRejectedToldOncePerDay(t *testing.T) {
	r := newRig(t, rigOpts{})
	var told []string
	r.router.cfg.CredentialRejected = func(p string) { told = append(told, p) }
	r.up.set(hostAnthropic, serveFixture(401, "application/json", []byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)))
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	for i := 0; i < 3; i++ {
		if w := r.do(t, "m1", simpleChat); w.Code != 200 {
			t.Fatalf("%d", w.Code)
		}
		r.advance(2 * DefaultCooldown)
	}
	if len(told) != 1 || told[0] != "anthropic" {
		t.Fatalf("told %v", told)
	}
	r.advance(24 * time.Hour)
	r.do(t, "m1", simpleChat)
	if len(told) != 2 {
		t.Fatalf("told %v after a day", told)
	}
}

// TestUsageReachesTheCallersContext: whoever serves the router (the guest
// plane, inside the OP-8 meter) receives each served call's provider and
// usage through the request context, also when the guest did not ask for
// usage and so its stream carries none.
func TestUsageReachesTheCallersContext(t *testing.T) {
	r := newRig(t, rigOpts{rule: Rule{"default": {{"openai", "gpt-fixture"}}}})
	r.up.set(hostOpenAI, serveFixture(200, "text/event-stream", fixture(t, "openai_stream.sse")))
	var got []string
	ctx := WithUsage(context.Background(), func(provider string, u Usage) { got = append(got, fmt.Sprint(provider, u)) })
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"default","stream":true,"messages":[{"role":"user","content":"hi"}]}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	r.router.Handler("m1").ServeHTTP(w, req)
	if a := reassemble(t, w.Body.Bytes()); a.usage != nil {
		t.Fatal("usage chunk sent unasked")
	}
	if want := fmt.Sprint("openai", Usage{Input: 9, Output: 2, CacheRead: 10, Reported: true, Complete: true, OutputChars: 2}); len(got) != 1 || got[0] != want {
		t.Fatalf("reported %q, want [%s]", got, want)
	}
	// An answer the router cannot translate is reported by its size.
	got = nil
	junk := strings.Repeat("x", 4000)
	r.up.set(hostOpenAI, serveFixture(200, "application/json", []byte(junk)))
	req = httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(simpleChat)).WithContext(ctx)
	r.router.Handler("m1").ServeHTTP(httptest.NewRecorder(), req)
	if want := fmt.Sprint("openai", Usage{OutputChars: 4000}); len(got) != 1 || got[0] != want {
		t.Fatalf("unusable answer reported %q, want [%s]", got, want)
	}
	// A denied call reports nothing.
	got = nil
	req = httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"nope","messages":[]}`)).WithContext(ctx)
	r.router.Handler("m1").ServeHTTP(httptest.NewRecorder(), req)
	if len(got) != 0 {
		t.Fatalf("a denied call reported %q", got)
	}
}
