package clerk_test

// REQ: CLK-1, CLK-2, CLK-3, CLK-4, KRN-8

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"math/rand/v2"
)

const canary = "canary-token-7731"

type exitFix struct {
	k    *kernel.Kernel
	x    *clerk.Exit
	srv  *httptest.Server
	root key.Key
	hits atomic.Int32
	got  struct{ auth, idem, body, path string }
}

func setupExit(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *exitFix {
	t.Helper()
	f := &exitFix{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		f.got.auth, f.got.idem, f.got.body, f.got.path = r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key"), string(b), r.URL.EscapedPath()
		if h != nil {
			h(w, r)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(f.srv.Close)
	sec := clerk.NewSecrets(sealer(t))
	if err := sec.Put("web", []byte(canary)); err != nil {
		t.Fatal(err)
	}
	opub, opriv := gen(1)
	hpub, _ := gen(2)
	kpub, kpriv := gen(3)
	ops := []clerk.Op{
		{Verb: key.Post, Method: "POST", URL: f.srv.URL + "/v1/msg/{to}", Slot: "web", Prefix: "Bearer ", Body: "msg", Content: "text", Labels: []string{"public"}},
		{Verb: key.Fetch, Method: "GET", URL: f.srv.URL + "/v1/doc/{url}", Content: "text", Labels: []string{"public"}},
	}
	x, err := clerk.NewExit("web", opub, ops, sec, f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	f.x = x
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: kpub,
		Sign: kpriv, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	f.k, err = kernel.Boot(l, opub, map[string]kernel.Clerk{"web": x}, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.root = key.Issue(opriv, key.Root{Holder: hpub, Clerk: "web", Verbs: []key.Verb{key.Post, key.Fetch}, Serial: "r1"})
	if err := f.k.Issue(0, f.root); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *exitFix) req(verb key.Verb, idem string, args map[string]string) kernel.Request {
	s := key.Step{Verb: verb, Clerk: "web", Task: "t", Args: map[string]key.Arg{}}
	for n, v := range args {
		s.Args[n] = key.Arg{Value: v, Source: key.SrcClerk}
	}
	for _, o := range []string{"to", "msg", "url"} {
		_ = o
	}
	content, labels, amount := f.x.Facts(s)
	s.Content, s.Labels, s.Amount = content, labels, amount
	s.Recipient = s.Args[key.ArgNames(verb)[0]].Value
	return kernel.Request{Plan: "p", Step: s, Key: f.root, Idem: idem, Now: 1}
}

func TestExitSendsDeclaredRequestWithSecretAndIdempotencyKey(t *testing.T) {
	f := setupExit(t, nil)
	r := f.x.Do(f.req(key.Post, "i1", map[string]string{"to": "bob/../x", "msg": "hello"}), f.k.State())
	if r.Outcome != "ok" {
		t.Fatalf("declared post failed: %+v", r)
	}
	if f.got.auth != "Bearer "+canary || f.got.idem != "i1" || f.got.body != "hello" {
		t.Fatalf("request not as declared: %+v", f.got)
	}
	if f.got.path != "/v1/msg/bob%2F..%2Fx" {
		t.Fatalf("argument escaped the path segment: %s", f.got.path)
	}
}

func TestExitIsIdempotentAndProbes(t *testing.T) {
	f := setupExit(t, nil)
	q := f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"})
	if f.x.Probe(q, f.k.State()) != "notdone" {
		t.Fatal("never attempted must probe notdone")
	}
	f.x.Do(q, f.k.State())
	f.x.Do(q, f.k.State())
	if f.hits.Load() != 1 {
		t.Fatalf("same idempotency key reached the remote %d times", f.hits.Load())
	}
	if f.x.Probe(q, f.k.State()) != "done" {
		t.Fatal("completed step must probe done")
	}
}

func TestExitUnknownOnServerErrorThenProbeUnknown(t *testing.T) {
	f := setupExit(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) })
	q := f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"})
	if r := f.x.Do(q, f.k.State()); r.Outcome != "unknown" {
		t.Fatalf("a 5xx may have acted: %+v", r)
	}
	if f.x.Probe(q, f.k.State()) != "unknown" {
		t.Fatal("an attempted step with no answer must probe unknown")
	}
}

func TestExitFailedOnClientErrorAndNeverLeaksSecret(t *testing.T) {
	f := setupExit(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, "bad token "+canary)
	})
	r := f.x.Do(f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"}), f.k.State())
	if r.Outcome != "failed" {
		t.Fatalf("4xx must fail: %+v", r)
	}
	if strings.Contains(r.Detail, canary) {
		t.Fatal("secret in the result detail")
	}
}

func TestExitRedactsSecretFromTransportErrors(t *testing.T) {
	f := setupExit(t, nil)
	f.srv.Close()
	r := f.x.Do(f.req(key.Post, "i1", map[string]string{"to": canary, "msg": "hi"}), f.k.State())
	if r.Outcome != "unknown" || strings.Contains(r.Detail, canary) {
		t.Fatalf("transport error must be unknown and redacted: %+v", r)
	}
}

func TestExitRefusesUndeclaredAndOverclaimed(t *testing.T) {
	f := setupExit(t, nil)
	// A verb with no declared shape.
	u := f.req(key.Fetch, "i1", map[string]string{"url": "a"})
	u.Step.Verb = key.Send
	if r := f.x.Do(u, f.k.State()); r.Outcome != "failed" || f.hits.Load() != 0 {
		t.Fatal("undeclared verb must be refused without a request")
	}
	// A claim the clerk's own facts contradict.
	c := f.req(key.Post, "i2", map[string]string{"to": "bob", "msg": "hi"})
	c.Step.Labels = []string{"private"}
	if r := f.x.Do(c, f.k.State()); r.Outcome != "failed" || f.hits.Load() != 0 {
		t.Fatal("contradicted claim must be refused")
	}
	// A request with an extra argument.
	e := f.req(key.Post, "i3", map[string]string{"to": "bob", "msg": "hi"})
	e.Step.Args["extra"] = key.Arg{Value: "x", Source: key.SrcClerk}
	if r := f.x.Do(e, f.k.State()); r.Outcome != "failed" || f.hits.Load() != 0 {
		t.Fatal("an undeclared argument must be refused")
	}
}

func TestExitDoesNotFollowRedirectsWithCredentials(t *testing.T) {
	var other atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other.Add(1) }))
	defer elsewhere.Close()
	f := setupExit(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	})
	r := f.x.Do(f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"}), f.k.State())
	if r.Outcome == "ok" || other.Load() != 0 {
		t.Fatalf("redirect was followed or treated as success: %+v", r)
	}
}

func TestExitRefusesWhatKeyForbids(t *testing.T) {
	f := setupExit(t, nil)
	q := f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"})
	v, _ := key.Verify(f.root, opubOf())
	if err := f.k.Revoke(2, v.ID()); err != nil {
		t.Fatal(err)
	}
	q.Now = 3
	if r := f.x.Do(q, f.k.State()); r.Outcome != "failed" || f.hits.Load() != 0 {
		t.Fatal("a revoked key must stop the exit before any request")
	}
}

func TestNewExitRejectsUnsafeDeclarations(t *testing.T) {
	opub, _ := gen(1)
	sec := clerk.NewSecrets(sealer(t))
	cl := http.DefaultClient
	bad := map[string]clerk.Op{
		"plain http":      {Verb: key.Fetch, Method: "GET", URL: "http://h.example/{url}"},
		"templated host":  {Verb: key.Fetch, Method: "GET", URL: "https://{url}.example/"},
		"unknown arg":     {Verb: key.Fetch, Method: "GET", URL: "https://h.example/{nope}"},
		"unknown verb":    {Verb: "teleport", Method: "GET", URL: "https://h.example/"},
		"missing slot":    {Verb: key.Fetch, Method: "GET", URL: "https://h.example/{url}", Slot: "ghost"},
		"bad method":      {Verb: key.Fetch, Method: "get all", URL: "https://h.example/{url}"},
		"body arg absent": {Verb: key.Fetch, Method: "POST", URL: "https://h.example/{url}", Body: "msg"},
	}
	for name, op := range bad {
		if _, err := clerk.NewExit("web", opub, []clerk.Op{op}, sec, cl); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
