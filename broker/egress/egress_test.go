package egress

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-1, CRED-5, CRED-7, ADP-10
//
// ADP-10 is partly covered: request shapes and body rules are enforced
// here; the verb-class and intent check before forwarding is not yet
// (ASSUMPTIONS.md E9).

// fakeProvider stands in for a provider's API. It records every request it
// receives and answers with whatever reply says.
type fakeProvider struct {
	mu    sync.Mutex
	seen  []*http.Request
	body  [][]byte
	reply http.HandlerFunc
}

func (f *fakeProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, r)
	f.body = append(f.body, b)
	f.mu.Unlock()
	if f.reply != nil {
		f.reply(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"choices":[{"message":{"content":"hi"}}]}`)
}

func (f *fakeProvider) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

type auditLog struct {
	mu  sync.Mutex
	evs []Event
}

func (a *auditLog) Egress(e Event) {
	a.mu.Lock()
	a.evs = append(a.evs, e)
	a.mu.Unlock()
}

func (a *auditLog) last(t *testing.T) Event {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.evs) == 0 {
		t.Fatal("nothing journaled")
	}
	return a.evs[len(a.evs)-1]
}

type rig struct {
	vault     *vault.Vault
	transport http.RoundTripper
	key       string
	provider  *fakeProvider
	audit     *auditLog
	proxy     *Proxy
}

func synthetic(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + hex.EncodeToString(b)
}

// newRig builds a vault holding a canary key, a fake provider behind TLS,
// and a proxy whose transport dials the fake for every declared host.
func newRig(t *testing.T, grants map[string][]string) *rig {
	t.Helper()
	fp := &fakeProvider{}
	srv := httptest.NewTLSServer(fp)
	t.Cleanup(srv.Close)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.DialTLSContext = nil

	kb := make([]byte, vault.KeySize)
	rand.Read(kb)
	v, err := vault.Create(filepath.Join(t.TempDir(), "vault"), kb)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	key := synthetic(t, "sk-canary-")
	if err := v.Put("openai-key", vault.KindAPIKey, []byte(key)); err != nil {
		t.Fatal(err)
	}
	if grants == nil {
		grants = map[string][]string{"m1": {"openai", "anthropic"}}
	}
	audit := &auditLog{}
	p, err := New(Config{
		Adapters:  []Adapter{OpenAI("openai-key"), Anthropic("openai-key")},
		Grants:    grants,
		Vault:     v,
		Transport: tr,
		Audit:     audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{key: key, provider: fp, audit: audit, proxy: p, vault: v, transport: tr}
}

func (r *rig) do(t *testing.T, machine string, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r.proxy.Handler(machine).ServeHTTP(w, req)
	return w
}

func chat(path string) *http.Request {
	req := httptest.NewRequest("POST", path, strings.NewReader(`{"model":"m","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer placeholder")
	return req
}

// CRED-5: the guest holds a placeholder; the broker injects the real key
// into a declared inference endpoint, and the guest sees the answer.
func TestInjectsKeyIntoDeclaredInferenceEndpoint(t *testing.T) {
	r := newRig(t, nil)
	w := r.do(t, "m1", chat("/openai/v1/chat/completions"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"hi"`) {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	if r.provider.count() != 1 {
		t.Fatalf("provider saw %d requests", r.provider.count())
	}
	got := r.provider.seen[0]
	if got.Header.Get("Authorization") != "Bearer "+r.key {
		t.Fatalf("provider saw Authorization %q", got.Header.Get("Authorization"))
	}
	if got.Host != "api.openai.com" || got.URL.Path != "/v1/chat/completions" || got.Method != "POST" {
		t.Fatalf("forwarded to %s %s%s", got.Method, got.Host, got.URL.Path)
	}
	var sent map[string]any
	if err := json.Unmarshal(r.provider.body[0], &sent); err != nil || sent["model"] != "m" || sent["store"] != false {
		t.Fatalf("forwarded body %s", r.provider.body[0])
	}
	if got.Header.Get("Accept-Encoding") != "identity" {
		t.Fatalf("Accept-Encoding %q", got.Header.Get("Accept-Encoding"))
	}
	if ev := r.audit.last(t); !ev.Allowed || ev.Machine != "m1" || ev.Operation != "chat.completions" {
		t.Fatalf("audit %+v", ev)
	}
}

// ADP-10: anything that is not a declared operation of a granted adapter
// is denied before it leaves the box, and reported to the Auditor. That includes the
// provider's key-management, file, and billing endpoints.
func TestUndeclaredRequestsAreDeniedAndReported(t *testing.T) {
	r := newRig(t, nil)
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"admin keys", "GET", "/openai/v1/organization/admin_api_keys"},
		{"responses API", "POST", "/openai/v1/responses"},
		{"models", "GET", "/openai/v1/models"},
		{"anthropic batches", "POST", "/anthropic/v1/messages/batches"},
		{"anthropic files", "POST", "/anthropic/v1/files"},
		{"project keys", "POST", "/openai/v1/organization/projects/p/api_keys"},
		{"files", "POST", "/openai/v1/files"},
		{"billing", "GET", "/openai/v1/dashboard/billing/usage"},
		{"wrong method", "GET", "/openai/v1/chat/completions"},
		{"prefix only", "POST", "/openai/v1/chat"},
		{"suffix", "POST", "/openai/v1/chat/completions/x"},
		{"dot-dot", "POST", "/openai/v1/chat/completions/../../organization/admin_api_keys"},
		{"encoded slash", "POST", "/openai/v1/chat%2Fcompletions"},
		{"double slash", "POST", "/openai//v1/chat/completions"},
		{"query", "POST", "/openai/v1/chat/completions?key=x"},
		{"unknown adapter", "POST", "/evil/v1/chat/completions"},
		{"no adapter", "POST", "/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, "http://broker"+c.path, strings.NewReader("{}"))
			w := r.do(t, "m1", req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("got %d", w.Code)
			}
			if ev := r.audit.last(t); ev.Allowed || ev.Reason == "" || ev.Machine != "m1" {
				t.Fatalf("audit %+v", ev)
			}
		})
	}
	if n := r.provider.count(); n != 0 {
		t.Fatalf("provider saw %d requests", n)
	}
}

// A machine with no grant for the adapter gets no key, whatever it asks.
func TestUngrantedMachineIsDenied(t *testing.T) {
	r := newRig(t, map[string][]string{"m1": {"openai"}})
	w := r.do(t, "m2", chat("/openai/v1/chat/completions"))
	if w.Code != http.StatusForbidden || r.provider.count() != 0 {
		t.Fatalf("got %d, provider saw %d", w.Code, r.provider.count())
	}
	if ev := r.audit.last(t); ev.Allowed || ev.Machine != "m2" {
		t.Fatalf("audit %+v", ev)
	}
}

// A14: a guest that brings its own ("attacker") key in any header has it
// stripped; only the vault key and allowlisted headers reach the provider.
func TestGuestCredentialsAreStripped(t *testing.T) {
	r := newRig(t, nil)
	attacker := synthetic(t, "sk-attacker-")
	req := chat("/openai/v1/chat/completions")
	req.Header.Set("Authorization", "Bearer "+attacker)
	req.Header.Set("Proxy-Authorization", "Basic "+attacker)
	req.Header.Set("X-Api-Key", attacker)
	req.Header.Set("Api-Key", attacker)
	req.Header.Set("Cookie", "session="+attacker)
	req.Header.Set("OpenAI-Organization", attacker)
	req.Header.Set("X-Forwarded-For", attacker)
	w := r.do(t, "m1", req)
	if w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
	got := r.provider.seen[0]
	for k, vs := range got.Header {
		for _, v := range vs {
			if strings.Contains(v, attacker) {
				t.Fatalf("provider saw attacker value in %s", k)
			}
		}
	}
	if got.Header.Get("Authorization") != "Bearer "+r.key {
		t.Fatal("vault key not injected")
	}
}

// CRED-1, CRED-7: whatever the provider sends back, the guest never sees
// the key, in the body or a header, streamed or not.
func TestResponsesNeverCarryTheKey(t *testing.T) {
	r := newRig(t, nil)
	r.provider.reply = func(w http.ResponseWriter, req *http.Request) {
		auth := req.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Echo", auth)
		w.Header().Set("Location", "https://evil.example/?k="+auth)
		fl := w.(http.Flusher)
		// Split the echoed key across flushes.
		for _, part := range []string{"data: {\"e\":\"" + auth[:20], auth[20:] + "\"}\n\n", "data: [DONE]\n\n"} {
			io.WriteString(w, part)
			fl.Flush()
		}
	}
	w := r.do(t, "m1", chat("/openai/v1/chat/completions"))
	if w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
	dump := w.Body.String()
	for k, vs := range w.Header() {
		dump += k + ": " + strings.Join(vs, ",") + "\n"
	}
	if strings.Contains(dump, r.key) || strings.Contains(dump, r.key[10:]) {
		t.Fatalf("key reached the guest:\n%s", dump)
	}
	if !strings.Contains(w.Body.String(), "data: [DONE]") || !strings.Contains(w.Body.String(), vault.Placeholder) {
		t.Fatalf("stream mangled: %q", w.Body.String())
	}
	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q", w.Header().Get("Content-Type"))
	}
}

// Redirects are returned, never followed, so the key is never re-sent to
// another host; the Location header does not reach the guest.
func TestRedirectsAreNotFollowed(t *testing.T) {
	r := newRig(t, nil)
	r.provider.reply = func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "https://evil.example/collect", http.StatusTemporaryRedirect)
	}
	w := r.do(t, "m1", chat("/openai/v1/chat/completions"))
	if r.provider.count() != 1 {
		t.Fatalf("provider saw %d requests", r.provider.count())
	}
	if w.Header().Get("Location") != "" {
		t.Fatalf("Location reached the guest: %q", w.Header().Get("Location"))
	}
}

// Errors and the audit trail carry no key.
func TestErrorsAndAuditCarryNoKey(t *testing.T) {
	r := newRig(t, nil)
	r.provider.reply = func(w http.ResponseWriter, req *http.Request) {
		hj, _ := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Close() // upstream dies mid-request
	}
	w := r.do(t, "m1", chat("/openai/v1/chat/completions"))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), r.key) {
		t.Fatal("error body carries the key")
	}
	r.do(t, "m1", chat("/openai/v1/files"))
	js, _ := json.Marshal(r.audit.evs)
	if bytes.Contains(js, []byte(r.key)) {
		t.Fatalf("audit carries the key: %s", js)
	}
}

// Oversized bodies are refused before anything is sent.
func TestOversizedBodyIsRefused(t *testing.T) {
	r := newRig(t, nil)
	r.proxy.maxBody = 1024
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", bytes.NewReader(make([]byte, 2048)))
	w := r.do(t, "m1", req)
	if w.Code != http.StatusRequestEntityTooLarge || r.provider.count() != 0 {
		t.Fatalf("got %d, provider saw %d", w.Code, r.provider.count())
	}
}

// Adapter declarations that would let a credential leak or an undeclared
// shape through are refused at construction.
func TestNewRejectsUnsafeDeclarations(t *testing.T) {
	ok := OpenAI("k")
	bad := []func(a *Adapter){
		func(a *Adapter) { a.Host = "" },
		func(a *Adapter) { a.Host = "api.openai.com/evil" },
		func(a *Adapter) { a.Host = "api.openai.com:80" },
		func(a *Adapter) { a.Name = "" },
		func(a *Adapter) { a.Name = "a/b" },
		func(a *Adapter) { a.Credential = "" },
		func(a *Adapter) { a.Inject.Header = "" },
		func(a *Adapter) { a.Operations = nil },
		func(a *Adapter) { a.Operations = []Operation{{Name: "x", Method: "POST", Path: "v1/x"}} },
		func(a *Adapter) { a.Operations = []Operation{{Name: "x", Method: "POST", Path: "/v1/../x"}} },
		func(a *Adapter) { a.Operations = []Operation{{Name: "x", Method: "", Path: "/v1/x"}} },
		func(a *Adapter) { a.RequestHeaders = []string{"Authorization"} },
		func(a *Adapter) { a.RequestHeaders = []string{"Cookie"} },
		func(a *Adapter) { a.ResponseHeaders = []string{"Location"} },
		func(a *Adapter) { a.RequestHeaders = []string{"X-Auth-Token"} },
		func(a *Adapter) { a.RequestHeaders = []string{"X-Session-Id"} },
		func(a *Adapter) { a.RequestHeaders = []string{"OpenAI-Project"} },
		func(a *Adapter) { a.RequestHeaders = []string{"OpenAI-Organization"} },
		func(a *Adapter) { a.RequestHeaders = []string{"Anthropic-Beta"} },
		func(a *Adapter) { a.RequestHeaders = []string{"Accept-Encoding"} },
		func(a *Adapter) { a.ResponseHeaders = []string{"Content-Encoding"} },
	}
	audit := &auditLog{}
	for i, mut := range bad {
		a := ok
		a.Operations = append([]Operation(nil), ok.Operations...)
		mut(&a)
		if _, err := New(Config{Adapters: []Adapter{a}, Vault: emptyVault{}, Audit: audit}); err == nil {
			t.Errorf("case %d: accepted %+v", i, a)
		}
	}
	if _, err := New(Config{Adapters: []Adapter{ok}, Vault: emptyVault{}, Audit: audit}); err != nil {
		t.Errorf("rejected the built-in adapter: %v", err)
	}
	if _, err := New(Config{Adapters: []Adapter{ok, ok}, Vault: emptyVault{}, Audit: audit}); err == nil {
		t.Error("accepted duplicate adapter names")
	}
	if _, err := New(Config{Adapters: []Adapter{ok}, Grants: map[string][]string{"m": {"nope"}}, Vault: emptyVault{}, Audit: audit}); err == nil {
		t.Error("accepted a grant to an undeclared adapter")
	}
}

// Denials must have somewhere to go: a proxy with no Auditor is refused.
func TestNewRequiresAuditor(t *testing.T) {
	if _, err := New(Config{Adapters: []Adapter{OpenAI("k")}, Vault: emptyVault{}}); err == nil {
		t.Fatal("built a proxy that would discard its decisions")
	}
}

type emptyVault struct{}

func (emptyVault) Secret(string) (vault.Secret, bool) { return vault.Secret{}, false }
func (emptyVault) Redactor() (*vault.Redactor, error) { return vault.NewRedactor(nil), nil }

// A granted adapter whose credential is missing from the vault fails
// closed: nothing is sent.
func TestMissingCredentialFailsClosed(t *testing.T) {
	r := newRig(t, nil)
	p, err := New(Config{
		Adapters: []Adapter{OpenAI("absent")},
		Grants:   map[string][]string{"m1": {"openai"}},
		Vault:    emptyVault{},
		Audit:    r.audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	p.Handler("m1").ServeHTTP(w, chat("/openai/v1/chat/completions"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", w.Code)
	}
}

// The built-in model relays declare inference endpoints only, each with a
// body rule that admits client tools only.
func TestBuiltInRelaysDeclareInferenceOnly(t *testing.T) {
	for _, a := range []Adapter{OpenAI("k"), Anthropic("k")} {
		for _, op := range a.Operations {
			if op.Method != "POST" || !(strings.HasSuffix(op.Path, "/chat/completions") || strings.HasSuffix(op.Path, "/messages")) {
				t.Errorf("%s declares non-inference op %+v", a.Name, op)
			}
			if op.Body == nil {
				t.Errorf("%s %s has no body rule", a.Name, op.Name)
			}
		}
	}
}

// A14 / REV-5: the provider must not become a way out. For a machine whose
// label is not public (here: no label source, so every machine is unknown),
// bodies that ask the provider to act on the network with the owner's key
// (server tools, remote MCP, web search) are denied; so, for every machine,
// are bodies the proxy cannot parse exactly as the provider would.
func TestRelayBodiesAdmitClientToolsOnly(t *testing.T) {
	r := newRig(t, nil)
	deny := []struct{ name, path, body string }{
		{"not json", "/openai/v1/chat/completions", `model=m`},
		{"json array", "/openai/v1/chat/completions", `[]`},
		{"trailing data", "/openai/v1/chat/completions", `{"model":"m"} {"tools":[{"type":"mcp"}]}`},
		{"openai web search tool", "/openai/v1/chat/completions", `{"model":"m","tools":[{"type":"web_search"}]}`},
		{"openai mcp tool", "/openai/v1/chat/completions", `{"model":"m","tools":[{"type":"mcp","server_url":"https://evil.example"}]}`},
		{"openai code interpreter", "/openai/v1/chat/completions", `{"model":"m","tools":[{"type":"function","function":{"name":"f"}},{"type":"code_interpreter"}]}`},
		{"openai web_search_options", "/openai/v1/chat/completions", `{"model":"m","web_search_options":{}}`},
		{"openai background", "/openai/v1/chat/completions", `{"model":"m","background":true}`},
		{"tools not a list", "/openai/v1/chat/completions", `{"model":"m","tools":{"type":"mcp"}}`},
		{"anthropic mcp_servers", "/anthropic/v1/messages", `{"model":"m","mcp_servers":[{"url":"https://evil.example"}]}`},
		{"anthropic web fetch", "/anthropic/v1/messages", `{"model":"m","tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}`},
		{"anthropic code execution", "/anthropic/v1/messages", `{"model":"m","tools":[{"type":"code_execution_20250522","name":"x"}]}`},
		{"anthropic container", "/anthropic/v1/messages", `{"model":"m","container":"c"}`},
		{"openai image by url", "/openai/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://attacker.example/x.png?d=secret"}}]}]}`},
		{"openai image_url string", "/openai/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":"https://attacker.example/x.png"}]}]}`},
		{"openai url with spaces and case", "/openai/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"  HTTPS://attacker.example/"}}]}]}`},
		{"anthropic image by url", "/anthropic/v1/messages", `{"model":"m","messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://attacker.example/x.png?d=secret"}}]}]}`},
		{"anthropic document by url", "/anthropic/v1/messages", `{"model":"m","messages":[{"role":"user","content":[{"type":"document","source":{"type":"url","url":"https://attacker.example/d.pdf"}}]}]}`},
		{"anthropic url inside tool_result", "/anthropic/v1/messages", `{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"image","source":{"type":"url","url":"https://attacker.example/i.png"}}]}]}]}`},
	}
	for _, c := range deny {
		t.Run(c.name, func(t *testing.T) {
			w := r.do(t, "m1", httptest.NewRequest("POST", c.path, strings.NewReader(c.body)))
			if w.Code != http.StatusForbidden {
				t.Fatalf("got %d", w.Code)
			}
			if ev := r.audit.last(t); ev.Allowed {
				t.Fatalf("audit %+v", ev)
			}
		})
	}
	if n := r.provider.count(); n != 0 {
		t.Fatalf("provider saw %d requests", n)
	}

	// Client tools pass; store is forced off; a duplicated key reaches the
	// provider once, as the proxy read it.
	allow := []struct{ path, body string }{
		{"/openai/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"see https://example.com"},{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}]}],"tools":[{"type":"function","function":{"name":"fetch","parameters":{"type":"object","properties":{"url":{"type":"string","default":"https://example.com"}}}}}]}`},
		{"/anthropic/v1/messages", `{"model":"m","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"fetch","input":{"url":"https://example.com"}}]},{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]}]}`},
		{"/openai/v1/chat/completions", `{"model":"m","store":true,"tools":[{"type":"function","function":{"name":"f"}}],"tools":[{"type":"custom","name":"g"}]}`},
		{"/anthropic/v1/messages", `{"model":"m","tools":[{"name":"f","input_schema":{}},{"type":"custom","name":"g","input_schema":{}}]}`},
	}
	for i, c := range allow {
		w := r.do(t, "m1", httptest.NewRequest("POST", c.path, strings.NewReader(c.body)))
		if w.Code != 200 {
			t.Fatalf("allow %d: got %d %s", i, w.Code, w.Body)
		}
	}
	first := string(r.provider.body[2])
	if strings.Count(first, `"tools"`) != 1 || !strings.Contains(first, `"store":false`) || !strings.Contains(first, `"custom"`) {
		t.Fatalf("forwarded %s", first)
	}
}

// A14 on the Anthropic route: the guest's own X-Api-Key is replaced by the
// vault key, and beta flags (which switch on server tools) are dropped.
func TestAnthropicGuestKeyAndBetasAreStripped(t *testing.T) {
	r := newRig(t, nil)
	attacker := synthetic(t, "sk-ant-attacker-")
	req := httptest.NewRequest("POST", "/anthropic/v1/messages", strings.NewReader(`{"model":"m","messages":[]}`))
	req.Header.Set("X-Api-Key", attacker)
	req.Header.Set("Authorization", "Bearer "+attacker)
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("Anthropic-Beta", "mcp-client-2025-04-04")
	if w := r.do(t, "m1", req); w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
	got := r.provider.seen[0]
	if got.Header.Get("X-Api-Key") != r.key || got.Header.Get("Anthropic-Version") != "2023-06-01" {
		t.Fatalf("headers %v", got.Header)
	}
	if got.Header.Get("Anthropic-Beta") != "" || got.Header.Get("Authorization") != "" {
		t.Fatalf("forwarded %v", got.Header)
	}
}

// CRED-7: a compressed response would pass the redactor unread and be
// inflated by the guest, so any encoded response is refused.
func TestEncodedResponsesAreRefused(t *testing.T) {
	r := newRig(t, nil)
	r.provider.reply = func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Encoding", "deflate")
		var b bytes.Buffer
		fw, _ := flate.NewWriter(&b, flate.BestSpeed)
		io.WriteString(fw, req.Header.Get("Authorization"))
		fw.Close()
		w.Write(b.Bytes())
	}
	w := r.do(t, "m1", chat("/openai/v1/chat/completions"))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("got %d", w.Code)
	}
	if w.Header().Get("Content-Encoding") != "" || !strings.HasPrefix(w.Body.String(), "egress: encoded response refused") {
		t.Fatalf("encoded body passed: %v %q", w.Header(), w.Body)
	}
}

// One machine cannot hold more than MaxConcurrent requests in flight, nor
// exceed its hard request cap.
func TestPerMachineLimits(t *testing.T) {
	r := newRig(t, nil)
	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	r.provider.reply = func(w http.ResponseWriter, req *http.Request) {
		entered <- struct{}{}
		<-block
		io.WriteString(w, "{}")
	}
	p, err := New(Config{
		Adapters: []Adapter{OpenAI("openai-key")}, Grants: map[string][]string{"m1": {"openai"}, "m2": {"openai"}},
		Vault: r.vault, Audit: r.audit, Transport: r.transport, MaxConcurrent: 1, Cap: Cap{Requests: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(m string) int {
		w := httptest.NewRecorder()
		p.Handler(m).ServeHTTP(w, chat("/openai/v1/chat/completions"))
		return w.Code
	}
	done := make(chan int)
	go func() { done <- do("m1") }()
	<-entered
	if c := do("m1"); c != http.StatusTooManyRequests {
		t.Fatalf("second concurrent request: %d", c)
	}
	close(block)
	if c := <-done; c != 200 {
		t.Fatalf("first request: %d", c)
	}
	go func() { <-entered }()
	if c := do("m1"); c != 200 {
		t.Fatalf("second request: %d", c)
	}
	if c := do("m1"); c != http.StatusTooManyRequests {
		t.Fatalf("over the cap: %d", c)
	}
	go func() { <-entered }()
	if c := do("m2"); c != 200 {
		t.Fatalf("other machine: %d", c)
	}
}

// REV-5: provider-side tools follow the calling machine's data label. A
// public machine may use them; a private machine, a machine with an
// unknown label, and every machine when no label source is wired, may not.
// background and store:false hold for every label.
func TestServerToolsFollowTheDataLabel(t *testing.T) {
	r := newRig(t, nil)
	labels := map[string]string{"pub": LabelPublic, "priv": "private", "odd": "PUBLIC "}
	p, err := New(Config{
		Adapters: []Adapter{OpenAI("openai-key"), Anthropic("openai-key")},
		Grants:   map[string][]string{"pub": {"openai", "anthropic"}, "priv": {"openai"}, "odd": {"openai"}, "none": {"openai"}},
		Vault:    r.vault, Audit: r.audit, Transport: r.transport,
		Label: func(m string) string { return labels[m] },
	})
	if err != nil {
		t.Fatal(err)
	}
	send := func(m, path, body string) int {
		w := httptest.NewRecorder()
		p.Handler(m).ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return w.Code
	}
	search := `{"model":"m","tools":[{"type":"web_search"}],"store":true}`
	for _, m := range []string{"priv", "odd", "none"} {
		if c := send(m, "/openai/v1/chat/completions", search); c != http.StatusForbidden {
			t.Errorf("%s: server tool got %d", m, c)
		}
		if c := send(m, "/openai/v1/chat/completions", `{"model":"m","web_search_options":{}}`); c != http.StatusForbidden {
			t.Errorf("%s: web_search_options got %d", m, c)
		}
	}
	if r.provider.count() != 0 {
		t.Fatalf("provider saw %d requests from non-public machines", r.provider.count())
	}
	if c := send("pub", "/openai/v1/chat/completions", search); c != 200 {
		t.Fatalf("public machine: server tool got %d", c)
	}
	if !strings.Contains(string(r.provider.body[0]), `"store":false`) {
		t.Fatalf("store not forced for a public machine: %s", r.provider.body[0])
	}
	if c := send("pub", "/anthropic/v1/messages", `{"model":"m","mcp_servers":[{"url":"https://x.example"}]}`); c != 200 {
		t.Fatalf("public machine: mcp_servers got %d", c)
	}
	urlImage := `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x.example/i.png"}}]}]}`
	if c := send("none", "/openai/v1/chat/completions", urlImage); c != http.StatusForbidden {
		t.Fatalf("unlabelled machine: url image got %d", c)
	}
	if c := send("pub", "/openai/v1/chat/completions", urlImage); c != 200 {
		t.Fatalf("public machine: url image got %d", c)
	}
	if c := send("pub", "/openai/v1/chat/completions", `{"model":"m","background":true}`); c != http.StatusForbidden {
		t.Fatalf("public machine: background got %d", c)
	}
}

// An adapter that declares a body rule without opting in gets the strict
// form for every machine, public included.
func TestBodyRuleIsStrictUnlessOptedIn(t *testing.T) {
	strict := &BodyRule{ServerToolKeys: []string{"mcp_servers"}}
	for _, body := range []string{
		`{"tools":[{"type":"web_search"}]}`,
		`{"mcp_servers":[]}`,
		`{"messages":[{"content":[{"type":"image","source":{"type":"url","url":"https://x.example"}}]}]}`,
	} {
		if _, err := strict.apply([]byte(body), true); err == nil {
			t.Errorf("public machine passed %s without opt-in", body)
		}
	}
}

// Content-Type is the proxy's, and every Content-Encoding value counts.
func TestContentHeadersAreTheProxys(t *testing.T) {
	r := newRig(t, nil)
	req := chat("/openai/v1/chat/completions")
	req.Header.Set("Content-Type", "text/plain; charset=evil")
	if w := r.do(t, "m1", req); w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
	if ct := r.provider.seen[0].Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q", ct)
	}
	for _, ce := range [][]string{{"identity", "gzip"}, {"identity, br"}, {" Deflate "}} {
		if !encoded(http.Header{"Content-Encoding": ce}) {
			t.Errorf("%q passed as unencoded", ce)
		}
	}
	if encoded(http.Header{"Content-Encoding": {"identity"}}) || encoded(http.Header{}) {
		t.Error("identity treated as encoded")
	}
}
