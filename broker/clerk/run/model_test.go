package run

// REQ: LOG-7, CLK-1, CLK-7, CLK-3, CLK-4, PLN-3

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// fakeProvider answers every model call with 400 bytes, or err, and counts
// them.
type fakeProvider struct {
	calls int
	err   error
}

func (f *fakeProvider) Call(route, prompt string, maxOut int64) (string, model.Usage, error) {
	f.calls++
	return strings.Repeat("x", 400), model.Usage{}, f.err
}

// The model clerk runs apart from the kernel and meters through the meter
// socket: a call is admitted against the plan's cap, its use lands in the
// log on the kernel's clock whatever the clerk's says, and a call past the
// cap is refused with the cap's code, which holds the plan, without reaching
// the provider (LOG-7, #2572).
func TestModelClerkMetersThroughTheKernelSocket(t *testing.T) {
	b := newBoxFor(t, filepath.Join(shortDir(t), "web.sock"), "model", key.Read)
	root := key.Issue(key.Ed25519Signer(ownerPriv), key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "m"})
	ky, err := key.ClerkKey(root, key.Ed25519Signer(ownerPriv), holderPub, b.now, 1<<40, key.LimitSpendTask(100))
	if err != nil {
		t.Fatal(err)
	}
	cos := []key.Cosign{key.Approve(key.Ed25519Signer(ownerPriv), kernel.BatchHash(root, ky)), key.Approve(key.Ed25519Signer(sparePriv), kernel.BatchHash(root, ky))}
	p := kernel.SignPlan(kernel.Plan{ID: "t", Key: ky, Steps: []kernel.PlanStep{{Verb: key.Read, Clerk: "model", Args: map[string]string{"query": "q"}}}}, holderPriv)
	if err := b.h.With(func(k *kernel.Kernel) error {
		if err := k.Issue(b.now-kernel.GrantHold, cos, root, ky); err != nil {
			return err
		}
		return k.Submit(b.now, p)
	}); err != nil {
		t.Fatal(err)
	}

	pr := &fakeProvider{}
	c := &model.Clerk{Routes: map[string]model.Price{"api": {InPerM: 1_000_000, OutPerM: 1_000_000}}, Provider: pr,
		Ledger: proc.Meter{Conn: serveMeter(t, b)}}
	sock := filepath.Join(shortDir(t), "model.sock")
	ln, err := ListenModel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeModel(ln, ModelHost{Clerk: c, Clock: func() int64 { return 0 }}) // a clerk clock far behind
	m := Model{proc.Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}}

	start := time.Now().UnixMilli()
	if reply, err := m.Call("t", "api", "hi", 50); err != nil || len(reply) != 400 {
		t.Fatalf("a call within the cap: %d bytes, %v", len(reply), err)
	}
	var used kernel.Entry
	b.h.With(func(k *kernel.Kernel) error {
		for _, e := range k.Log().Entries() {
			if e.Type == kernel.TModelUsed {
				used = e
			}
		}
		return nil
	})
	if used.Type == "" || used.At < start || !strings.Contains(string(used.Body), `"api"`) {
		t.Fatalf("the metered use: %+v, want a model.used entry at the kernel's time (>= %d)", used, start)
	}

	_, err = m.Call("t", "api", "hi", 1000)
	var rf *key.Refusal
	if !errors.As(err, &rf) || rf.Code != key.RSpendTask {
		t.Fatalf("a call past the cap: %v, want refusal %s", err, key.RSpendTask)
	}
	if pr.calls != 1 {
		t.Fatalf("the provider saw %d calls, want 1", pr.calls)
	}
	b.h.With(func(k *kernel.Kernel) error {
		if _, ok := k.State().SpendHeld["t"]; !ok {
			t.Fatal("the plan past its cap is not held")
		}
		return nil
	})
}

// A meter socket that cannot be reached admits nothing: the clerk refuses
// the call as the broken log does, and the provider is never called.
func TestModelClerkWithoutTheKernelCallsNothing(t *testing.T) {
	pr := &fakeProvider{}
	c := &model.Clerk{Routes: map[string]model.Price{"api": {InPerM: 1, OutPerM: 1}}, Provider: pr,
		Ledger: proc.Meter{Conn: proc.Conn{Socket: filepath.Join(shortDir(t), "none.sock"), UID: os.Getuid()}}}
	_, err := c.Call(0, "t", "api", "hi", 10)
	var rf *key.Refusal
	if !errors.As(err, &rf) || rf.Code != kernel.CBroken || pr.calls != 0 {
		t.Fatalf("no kernel: %v with %d provider calls, want refusal %s and none", err, pr.calls, kernel.CBroken)
	}
}

// A provider's own error, which can carry its URL or a key, never leaves the
// model clerk's process: the planner sees ErrModelCall, while a refusal
// still crosses with its code (CLK-1, #2717 Security 1).
func TestAProviderErrorStaysInTheModelClerk(t *testing.T) {
	const canary = "CANARY-SECRET-2717"
	pr := &fakeProvider{err: errors.New("Post https://api.example.test/v1?key=" + canary + ": 401")}
	c := &model.Clerk{Routes: map[string]model.Price{"api": {InPerM: 1, OutPerM: 1}}, Provider: pr, Ledger: admitAll{}}
	sock := filepath.Join(shortDir(t), "model.sock")
	ln, err := ListenModel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeModel(ln, ModelHost{Clerk: c, Clock: func() int64 { return 0 }})
	m := Model{proc.Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}}
	_, err = m.Call("t", "api", "hi", 10)
	if !errors.Is(err, ErrModelCall) || strings.Contains(err.Error(), canary) || pr.calls != 1 {
		t.Fatalf("a failed provider call: %v (%d calls), want %v without the canary", err, pr.calls, ErrModelCall)
	}
}

// admitAll is a ledger that admits and records everything.
type admitAll struct{}

func (admitAll) AdmitSpend(_ int64, plan string, _ int64) (kernel.Admitted, *key.Refusal) {
	return kernel.Admitted{Plan: plan}, nil
}

func (admitAll) Meter(int64, kernel.Admitted, string, int64, string) error { return nil }

func (admitAll) Hold(int64, string, *key.Refusal) error { return nil }

func (admitAll) AdmitPool(int64, string) *key.Refusal { return nil }

func (admitAll) ReadPool(int64, string, []kernel.WindowReading) error { return nil }

// serveMeter serves b's kernel's meter side on a fresh socket that admits
// this uid, and returns a Conn to it.
func serveMeter(t *testing.T, b *box) proc.Conn {
	t.Helper()
	sock := filepath.Join(shortDir(t), "meter.sock")
	ln, err := proc.ListenKernel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go proc.ServeKernel(ln, b.h, proc.MeterSide, func() int64 { return time.Now().UnixMilli() })
	return proc.Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}
}

// apiFix is the model socket over one API-key route whose declared host is
// a local TLS server; the provider's answer is the handler's.
type apiFix struct {
	m    Model
	apis *model.APIs
	hits atomic.Int32
	seen chan *http.Request
	logs []string
	mu   sync.Mutex
	l    *meterLog
}

// meterLog is a ledger that admits everything and records what it meters.
type meterLog struct {
	admitAll
	mu     sync.Mutex
	amount []int64
	source []string
}

func (l *meterLog) Meter(_ int64, _ kernel.Admitted, _ string, amount int64, source string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.amount, l.source = append(l.amount, amount), append(l.source, source)
	return nil
}

type fixedResolver netip.Addr

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.Addr(r)}, nil
}

const apiKeyCanary = "sk-test-CANARY-3680-0123456789abcdef"

func newAPIFix(t *testing.T, handler http.HandlerFunc) *apiFix {
	t.Helper()
	f := &apiFix{seen: make(chan *http.Request, 16), l: &meterLog{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.seen <- r.Clone(context.Background())
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	guard := netguard.New(netguard.Config{Resolver: fixedResolver(netip.MustParseAddr("8.8.8.8")), Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}})
	d := model.Shipped[0]
	d.Host = "api.example.com"
	k := make([]byte, 32)
	rand.Read(k)
	s, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	f.apis, err = model.NewAPIs([]model.APIDeclaration{d}, model.NewKeys(s, nil), guard, roots)
	if err != nil {
		t.Fatal(err)
	}
	f.apis.Log = func(line string) { f.mu.Lock(); f.logs = append(f.logs, line); f.mu.Unlock() }
	c := &model.Clerk{Routes: f.apis.Prices(), Ledger: f.l}
	sock := filepath.Join(shortDir(t), "model.sock")
	ln, err := ListenModel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServeModel(ln, ModelHost{Clerk: c, APIs: f.apis, Clock: func() int64 { return 0 }})
	f.m = Model{proc.Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}}
	return f
}

// answer is a provider answer that reports usage.
func answer(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"type":"message","content":[{"type":"text","text":%q}],"usage":{"input_tokens":10,"output_tokens":5}}`, text)
}

func messages(model string, maxOut int) []byte {
	return []byte(fmt.Sprintf(`{"model":%q,"max_tokens":%d,"messages":[{"role":"user","content":"hi"}]}`, model, maxOut))
}

// A call on an API-key route is sent only to the declared host and path,
// with the sealed key in the declared header, and metered at the usage the
// answer reports. A route or operation not declared, a body out of its
// shape and a model other than the route's are refused before anything is
// sent, and each refusal is logged (CLK-3, CLK-7, LOG-7).
func TestModelCallWithAnAPIKeyReachesOnlyTheDeclaredEndpoint(t *testing.T) {
	f := newAPIFix(t, func(w http.ResponseWriter, r *http.Request) { answer(w, "hello") })
	if err := f.apis.SetKey("anthropic", apiKeyCanary, true); err != nil {
		t.Fatal(err)
	}
	reply, err := f.m.Send("t", "anthropic-sonnet-5-5", "messages", messages("claude-sonnet-5-5", 64))
	if err != nil || !strings.Contains(string(reply), "hello") {
		t.Fatalf("a declared call: %s, %v", reply, err)
	}
	r := <-f.seen
	if r.Method != "POST" || r.Host != "api.example.com" || r.URL.Path != "/v1/messages" ||
		r.Header.Get("X-Api-Key") != apiKeyCanary || r.Header.Get("Anthropic-Version") != "2023-06-01" || r.Header.Get("Authorization") != "" {
		t.Fatalf("sent %s %s%s with headers %v", r.Method, r.Host, r.URL.Path, r.Header)
	}
	// 10 in and 5 out at 200 and 1000 per million round up to 1.
	if len(f.l.amount) != 1 || f.l.amount[0] != 1 || f.l.source[0] != "provider" {
		t.Fatalf("metered %v %v, want 1 from the provider", f.l.amount, f.l.source)
	}

	for _, c := range []struct {
		name, route, op string
		body            []byte
		detail          string
	}{
		{"an undeclared operation", "anthropic-sonnet-5-5", "files", messages("claude-sonnet-5-5", 64), model.DUndeclared},
		{"an undeclared route", "other-route", "messages", messages("claude-sonnet-5-5", 64), model.DUndeclared},
		{"another route's model", "anthropic-sonnet-5-5", "messages", messages("claude-opus-5-5", 64), model.DBody},
		{"an undeclared key", "anthropic-sonnet-5-5", "messages", []byte(`{"model":"claude-sonnet-5-5","max_tokens":8,"messages":[],"stream":true}`), model.DBody},
		{"a hosted tool", "anthropic-sonnet-5-5", "messages", []byte(`{"model":"claude-sonnet-5-5","max_tokens":8,"messages":[],"tools":[{"type":"web_search_20260209","name":"web_search"}]}`), model.DBody},
		{"a content source by address", "anthropic-sonnet-5-5", "messages", []byte(`{"model":"claude-sonnet-5-5","max_tokens":8,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://x.test/a.png"}}]}]}`), model.DBody},
		{"an output cap past the model's", "anthropic-sonnet-5-5", "messages", messages("claude-sonnet-5-5", 128001), model.DBody},
		{"no output cap", "anthropic-sonnet-5-5", "messages", []byte(`{"model":"claude-sonnet-5-5","messages":[]}`), model.DBody},
	} {
		_, err := f.m.Send("t", c.route, c.op, c.body)
		if err == nil || !strings.HasPrefix(err.Error(), "model: "+c.detail) {
			t.Errorf("%s: %v, want %s", c.name, err, c.detail)
		}
	}
	if n := f.hits.Load(); n != 1 {
		t.Fatalf("%d requests reached the provider, want only the declared one", n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.logs) != 8 {
		t.Fatalf("logged %q, want each refusal", f.logs)
	}
	for _, l := range f.logs {
		if strings.Contains(l, apiKeyCanary) || strings.Contains(l, "x.test") {
			t.Fatalf("a log line carries a value: %q", l)
		}
	}
}

// The key and its encodings are stripped from what a call returns, and a
// failed call's answer, which can echo it, never crosses (CLK-1, CLK-4).
// The positive control: the provider did echo the key.
func TestModelReplyCarriesNoKey(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(apiKeyCanary))
	var fail, escaped atomic.Bool
	f := newAPIFix(t, func(w http.ResponseWriter, r *http.Request) {
		echo := r.Header.Get("X-Api-Key")
		if echo != apiKeyCanary {
			t.Errorf("the provider saw %q", echo)
		}
		if fail.Load() {
			http.Error(w, `{"error":{"message":"bad key `+echo+`"}}`, 401)
			return
		}
		if escaped.Load() {
			// The same echoes, JSON-escaped: decoded, they are the key.
			esc := `\u0073` + echo[1:]
			fmt.Fprintf(w, `{"content":[{"type":"text","text":"%s and %s"}],"usage":{"input_tokens":1,"output_tokens":1}}`,
				esc, strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(echo)), "/", `\/`))
			return
		}
		answer(w, "your key is "+echo+" or "+base64.StdEncoding.EncodeToString([]byte(echo)))
	})
	if err := f.apis.SetKey("anthropic", apiKeyCanary, true); err != nil {
		t.Fatal(err)
	}
	reply, err := f.m.Send("t", "anthropic-haiku-5-5", "messages", messages("claude-haiku-5-5", 64))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reply), "your key is [redacted] or [redacted]") || strings.Contains(string(reply), apiKeyCanary) || strings.Contains(string(reply), b64) {
		t.Fatalf("reply %s", reply)
	}
	escaped.Store(true)
	reply, err = f.m.Send("t", "anthropic-haiku-5-5", "messages", messages("claude-haiku-5-5", 64))
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if json.Unmarshal(reply, &decoded) != nil || strings.Contains(fmt.Sprint(decoded), apiKeyCanary) || strings.Contains(fmt.Sprint(decoded), b64) ||
		!strings.Contains(string(reply), "[redacted] and [redacted]") {
		t.Fatalf("an escaped echo: %s", reply)
	}
	escaped.Store(false)
	fail.Store(true)
	_, err = f.m.Send("t", "anthropic-haiku-5-5", "messages", messages("claude-haiku-5-5", 64))
	if err == nil || err.Error() != "model: "+model.DUpstream+" http 401" {
		t.Fatalf("a refused key: %v", err)
	}
	st, err := f.apis.State()
	if err != nil || len(st) != 1 || !st[0].Set || !st[0].Private || !st[0].Serves {
		t.Fatalf("state %+v, %v", st, err)
	}
	if b, _ := json.Marshal(st); strings.Contains(string(b), apiKeyCanary) {
		t.Fatalf("the key's state carries it: %s", b)
	}
	// 401 is declared unbilled: metered at 0 as the provider's figure.
	if len(f.l.amount) != 3 || f.l.amount[2] != 0 || f.l.source[2] != "provider" {
		t.Fatalf("metered %v %v", f.l.amount, f.l.source)
	}
}

// Every call is private: no label the clerk can check comes with a call, so
// a route whose key the owner did not allow private data refuses every
// call, with nothing sent or metered, and allowing it lets calls run
// (PLN-3, #3705 L3 1).
func TestPrivateCallRefusedOnARouteNotAllowedPrivate(t *testing.T) {
	f := newAPIFix(t, func(w http.ResponseWriter, r *http.Request) { answer(w, "ok") })
	if _, err := f.m.Send("t", "anthropic-opus-5-5", "messages", messages("claude-opus-5-5", 8)); err == nil || err.Error() != "model: "+model.DNoKey {
		t.Fatalf("no key: %v", err)
	}
	if err := f.apis.SetKey("anthropic", apiKeyCanary, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Send("t", "anthropic-opus-5-5", "messages", messages("claude-opus-5-5", 8)); err == nil || err.Error() != "model: "+model.DPrivate {
		t.Fatalf("a call on a route not allowed private data: %v", err)
	}
	// A frame that still claims its values are public is refused all the
	// same: the claim is not read.
	raw := proc.Conn{Socket: f.m.Socket, UID: os.Getuid(), Timeout: 10 * time.Second}
	err := raw.Call("send", map[string]any{"plan": "t", "route": "anthropic-opus-5-5", "op": "messages",
		"body": json.RawMessage(messages("claude-opus-5-5", 8)), "public": true}, nil)
	if err == nil || err.Error() != "model: "+model.DPrivate {
		t.Fatalf("a call claiming to be public: %v", err)
	}
	if f.hits.Load() != 0 || len(f.l.amount) != 0 {
		t.Fatalf("a refused call reached the provider (%d) or was metered (%v)", f.hits.Load(), f.l.amount)
	}
	// The owner's page is told such a key serves nothing (#3705 UX 9).
	if st, err := f.apis.State(); err != nil || !st[0].Set || st[0].Private || st[0].Serves {
		t.Fatalf("a key not allowed private data: %+v, %v", st, err)
	}
	if err := f.apis.SetPrivate("anthropic", true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Send("t", "anthropic-opus-5-5", "messages", messages("claude-opus-5-5", 8)); err != nil {
		t.Fatalf("a call once allowed: %v", err)
	}
	if f.hits.Load() != 1 {
		t.Fatalf("%d calls reached the provider, want 1", f.hits.Load())
	}
}
