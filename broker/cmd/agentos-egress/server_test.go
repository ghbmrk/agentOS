package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-8, CRED-1, CRED-5, CRED-7, ADP-10, REV-5, ARC-6

// REQ: CAP-9, OP-8

// testRouter routes class "default" to OpenAI and "claude" to Anthropic;
// the machine "agent" is granted OpenAI only, and OpenAI is allowed for
// private data.
func testRouter(t *testing.T) *route.Router {
	t.Helper()
	rt, err := newRouter(route.Rule{
		"default": {{Provider: "openai", Model: "gpt-test"}},
		"claude":  {{Provider: "anthropic", Model: "claude-test"}},
	}, map[string][]string{"agent": {"openai"}}, map[string]bool{"openai": true})
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// meterStub stands in for the OP-8 meter's writer in front of the
// forwarder.
type meterStub struct {
	http.ResponseWriter
	usage    string
	complete bool
}

func (m *meterStub) ReportUsage(u []byte, complete bool) { m.usage, m.complete = string(u), complete }

// TestUnknownHostUnlockThenModelRoute is the P2-4a chain on one host:
// `init` seals a vault under a generated passphrase, the vault process
// starts locked, the model route answers 503, the passphrase plus an
// approval code unlock it through the unlock socket, and the broker's
// forwarder (as agentosd wires it) then reaches a provider through the
// model router with the vault key injected, never shown to the guest. The
// provider's usage comes back to the broker's meter, and denials to its
// journal. Locking again returns the route to 503.
func TestUnknownHostUnlockThenModelRoute(t *testing.T) {
	dir := t.TempDir()
	vp, kp := filepath.Join(dir, "state", "vault"), filepath.Join(dir, "state", "vault.keys")
	var card bytes.Buffer
	if err := initCmd([]string{"-vault", vp, "-keys", kp}, &card); err != nil {
		t.Fatal(err)
	}
	pass, seed := readCard(t, card.String())

	// A hostile provider that reflects whatever key it receives.
	var mu sync.Mutex
	var got, models []string
	prov := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		var req struct{ Model string }
		json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		got, models = append(got, key), append(models, req.Model)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c1","object":"chat.completion","created":1,"model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"key is `+key+
			`"},"finish_reason":"stop"}],"usage":{"prompt_tokens":40,"completion_tokens":3,"total_tokens":43,"prompt_tokens_details":{"cached_tokens":30}}}`)
	}))
	defer prov.Close()
	tr := prov.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	addr := prov.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	clk := &clock{t: time.Now()}
	c, err := newCustody(&custody{
		statePath: filepath.Join(dir, "state", "unlock.json"),
		open:      func(p string) (*vault.Vault, error) { return vault.OpenSealed(vp, kp, vault.Passphrase(p)) },
		build: func(v *vault.Vault) (*egress.Proxy, error) {
			return newProxy(v, map[string][]string{"agent": {"openai"}}, tr)
		},
		ttl:    15 * time.Minute,
		now:    clk.now,
		notify: func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.lock()
	run := filepath.Join(dir, "run")
	srvs, err := serve(run, c, testRouter(t), os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	if fi, err := os.Stat(run); err != nil || fi.Mode().Perm() != 0o711 {
		t.Fatalf("run dir: %v %v", fi.Mode(), err)
	}

	var denied []modelroute.Denial
	fwd := modelroute.Forward(modelroute.Config{
		Socket: filepath.Join(run, ModelSocket),
		Label:  func(string) string { return "private" },
		Denied: func(_ string, d modelroute.Denial) { denied = append(denied, d) },
	})
	var meter *meterStub
	ask := func(class string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"`+class+`","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Authorization", "Bearer placeholder")
		meter = &meterStub{ResponseWriter: w}
		fwd("agent").ServeHTTP(meter, req)
		return w
	}

	if w := ask("default"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("locked vault: %d", w.Code)
	}

	ui := unixClient(filepath.Join(run, UnlockSocket))
	if _, code, _ := post(ui, "/unlock", map[string]string{"passphrase": "wrong " + pass}); code != http.StatusForbidden {
		t.Fatalf("wrong passphrase: %d", code)
	}
	if _, code, _ := post(ui, "/unlock", map[string]string{"passphrase": pass}); code != http.StatusTooManyRequests {
		t.Fatalf("attempt inside the gap: %d", code)
	}
	clk.add(MinAttemptGap)
	res, code, err := post(ui, "/unlock", map[string]string{"passphrase": strings.ToUpper(pass)})
	if err != nil || code != 200 || res["state"] != "pending" {
		t.Fatalf("unlock: %v %d %v", res, code, err)
	}
	ticket, _ := res["ticket"].(string)
	if w := ask("default"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("passphrase alone opened the route: %d", w.Code)
	}
	if res, code, _ := post(ui, "/confirm", map[string]string{"ticket": ticket, "code": "000000"}); code != http.StatusForbidden || res["error"] != "wrong code; 2 tries left" {
		t.Fatalf("wrong code: %v %d", res, code)
	}
	if res, code, _ := post(ui, "/confirm", map[string]string{"ticket": ticket, "code": totp(seed, clk.now())}); code != 200 || res["state"] != "open" {
		t.Fatalf("confirm: %v %d", res, code)
	}

	// No key yet: the proxy fails closed.
	if w := ask("default"); w.Code != http.StatusServiceUnavailable || len(denied) != 1 || denied[0].Reason != "credential not in vault" {
		t.Fatalf("missing key: %d %+v", w.Code, denied)
	}
	key := synthetic(t, "sk-canary-")
	if err := putCmd([]string{"-run", run, "-name", "openai"}, strings.NewReader(key+"\n")); err != nil {
		t.Fatal(err)
	}
	w := ask("default")
	if w.Code != 200 || strings.Contains(w.Body.String(), key) || !strings.Contains(w.Body.String(), "key is") {
		t.Fatalf("model call: %d %s", w.Code, w.Body)
	}
	mu.Lock()
	if len(got) != 1 || got[0] != key || models[0] != "gpt-test" {
		t.Fatalf("provider did not get the routed model with the vault key: %q", models)
	}
	mu.Unlock()
	// The provider's own usage object reaches the meter; nothing of ours
	// reaches the guest.
	var u struct {
		Prompt  int64 `json:"prompt_tokens"`
		Out     int64 `json:"completion_tokens"`
		Details struct {
			Cached int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	}
	if err := json.Unmarshal([]byte(meter.usage), &u); err != nil || u.Prompt != 40 || u.Details.Cached != 30 || u.Out != 3 || !meter.complete {
		t.Fatalf("usage to the meter: %q %v", meter.usage, meter.complete)
	}
	for k := range w.Result().Trailer {
		t.Fatalf("guest got trailer %s", k)
	}

	// A class whose provider is not granted: refused by the router before
	// any provider, and journaled by the broker.
	n := len(denied)
	if w := ask("claude"); w.Code != http.StatusForbidden || w.Header().Get(modelroute.HeaderDenial) != "" {
		t.Fatalf("ungranted provider: %d", w.Code)
	}
	if len(denied) != n+1 || denied[n].Adapter != "router" || denied[n].Machine != "agent" || denied[n].Status != 403 {
		t.Fatalf("denial: %+v", denied[n:])
	}
	if meter.usage != "" {
		t.Fatalf("usage reported for a refused call: %q", meter.usage)
	}

	if _, code, _ := post(ui, "/lock", nil); code != 200 {
		t.Fatalf("lock: %d", code)
	}
	if w := ask("default"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("after lock: %d", w.Code)
	}
}

func readCard(t *testing.T, card string) (string, []byte) {
	t.Helper()
	var pass, secret string
	for _, line := range strings.Split(card, "\n") {
		if p, ok := strings.CutPrefix(line, "Vault passphrase: "); ok {
			pass = p
		}
		if _, q, ok := strings.Cut(line, "secret="); ok {
			secret, _, _ = strings.Cut(q, "&")
		}
	}
	seed, err := b32().DecodeString(secret)
	if pass == "" || err != nil || len(seed) != 20 {
		t.Fatalf("card: %q", card)
	}
	if n := len(strings.ReplaceAll(pass, " ", "")); n != 20 {
		t.Fatalf("passphrase has %d characters, want 20 (100 bits)", n)
	}
	return pass, seed
}

// The sockets admit one uid each: anyone else is closed unread.
func TestSocketsAdmitOnlyTheirPeer(t *testing.T) {
	c := &custody{now: time.Now, notify: func(string) {}}
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, c, testRouter(t), os.Getuid()+1, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	for _, name := range []string{ModelSocket, UnlockSocket} {
		resp, err := unixClient(filepath.Join(run, name)).Get("http://x/status")
		if err == nil {
			resp.Body.Close()
			t.Fatalf("%s answered a stranger: %d", name, resp.StatusCode)
		}
	}
}

// The model socket takes a machine name only in the broker's shape.
func TestModelSocketNeedsAMachine(t *testing.T) {
	c := &custody{now: time.Now, notify: func(string) {}}
	for _, m := range []string{"", "../x", "Agent", strings.Repeat("a", 41)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/openai/v1/chat/completions", nil)
		r.Header.Set(modelroute.HeaderMachine, m)
		modelHandler(c, testRouter(t)).ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("machine %q: %d", m, w.Code)
		}
	}
}

func TestStatusShowsPhaseOnly(t *testing.T) {
	r := newFastRig(t, true)
	h := unlockHandler(r.c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["state"] != "locked" || len(out) != 1 {
		t.Fatalf("status %v", out)
	}
}

// Usage goes to the meter in the serving provider's own shape, so cached
// input is weighed at that provider's rates; unreported usage sends none.
func TestUsageTrailerInProviderShape(t *testing.T) {
	u := route.Usage{Input: 50, Output: 777, CacheRead: 200, CacheWrite: 10, Reported: true, Complete: true}
	for _, c := range []struct {
		route string
		u     route.Usage
		want  string
	}{
		{"anthropic/claude-test", u, `{"usage":{"cache_creation_input_tokens":10,"cache_read_input_tokens":200,"input_tokens":50,"output_tokens":777},"complete":true}`},
		{"openai/gpt-test", u, `{"usage":{"completion_tokens":777,"prompt_tokens":260,"prompt_tokens_details":{"cached_tokens":200}},"complete":true}`},
		{"openai/gpt-test", route.Usage{OutputChars: 40, Complete: true}, ``},
	} {
		var a callAudit
		a.decide(httptest.NewRecorder())(route.Decision{Outcome: route.Served, Route: c.route, Usage: &c.u})
		if got := a.usage(); got != c.want {
			t.Fatalf("%s: %s, want %s", c.route, got, c.want)
		}
	}
}
