package egress

import (
	"bytes"
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
	key      string
	provider *fakeProvider
	audit    *auditLog
	proxy    *Proxy
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
		grants = map[string][]string{"m1": {"openai"}}
	}
	audit := &auditLog{}
	p, err := New(Config{
		Adapters:  []Adapter{OpenAI("openai-key")},
		Grants:    grants,
		Vault:     v,
		Transport: tr,
		Audit:     audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{key: key, provider: fp, audit: audit, proxy: p}
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
	if string(r.provider.body[0]) != `{"model":"m","messages":[]}` {
		t.Fatalf("body changed: %s", r.provider.body[0])
	}
	if ev := r.audit.last(t); !ev.Allowed || ev.Machine != "m1" || ev.Operation != "chat.completions" {
		t.Fatalf("audit %+v", ev)
	}
}

// ADP-10: anything that is not a declared operation of a granted adapter
// is denied before it leaves the box, and journaled. That includes the
// provider's key-management, file, and billing endpoints.
func TestUndeclaredRequestsAreDeniedAndJournaled(t *testing.T) {
	r := newRig(t, nil)
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"admin keys", "GET", "/openai/v1/organization/admin_api_keys"},
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
	}
	for i, mut := range bad {
		a := ok
		a.Operations = append([]Operation(nil), ok.Operations...)
		mut(&a)
		if _, err := New(Config{Adapters: []Adapter{a}, Vault: emptyVault{}}); err == nil {
			t.Errorf("case %d: accepted %+v", i, a)
		}
	}
	if _, err := New(Config{Adapters: []Adapter{ok, ok}, Vault: emptyVault{}}); err == nil {
		t.Error("accepted duplicate adapter names")
	}
	if _, err := New(Config{Adapters: []Adapter{ok}, Grants: map[string][]string{"m": {"nope"}}, Vault: emptyVault{}}); err == nil {
		t.Error("accepted a grant to an undeclared adapter")
	}
}

type emptyVault struct{}

func (emptyVault) Secret(string) (vault.Secret, bool) { return vault.Secret{}, false }
func (emptyVault) Redactor() *vault.Redactor          { return vault.NewRedactor(nil) }

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

// The built-in model relays declare inference endpoints only.
func TestBuiltInRelaysDeclareInferenceOnly(t *testing.T) {
	for _, a := range []Adapter{OpenAI("k"), Anthropic("k")} {
		for _, op := range a.Operations {
			if op.Method != "POST" || !(strings.HasSuffix(op.Path, "/chat/completions") || strings.HasSuffix(op.Path, "/messages") || strings.HasSuffix(op.Path, "/responses")) {
				t.Errorf("%s declares non-inference op %+v", a.Name, op)
			}
		}
	}
}
