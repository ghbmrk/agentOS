package clerk_test

// REQ: CLK-1, CLK-2, CLK-3, CLK-4, KRN-8

import (
	"crypto/ed25519"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const canary = "canary-token-7731"

type exitFix struct {
	k    *kernel.Kernel
	x    *clerk.Exit
	srv  *httptest.Server
	root key.Key
	hits atomic.Int32
	got  struct{ auth, idem, body, path string }

	store  *kernel.MemStore
	anchor *kernel.MemAnchor
	cfg    kernel.Config
	opub   ed25519.PublicKey
	ops    []clerk.Op
	sec    *clerk.Secrets
	inLog  int // log length the request handler saw
}

// reboot reopens the same log with the given clerk, as a restart does.
func (f *exitFix) reboot(t *testing.T, x kernel.Clerk, now int64) {
	t.Helper()
	l, err := kernel.Open(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if f.k, err = kernel.Boot(l, f.opub, map[string]kernel.Clerk{"web": x}, now); err != nil {
		t.Fatal(err)
	}
}

// cutLast drops the last n log entries: the effect reached the remote, the
// record of its result did not.
func (f *exitFix) cutLast(t *testing.T, n int) {
	t.Helper()
	var ends []int
	for off := 0; off < len(f.store.B); {
		off += 4 + int(binary.BigEndian.Uint32(f.store.B[off:]))
		ends = append(ends, off)
	}
	if err := f.store.Truncate(ends[len(ends)-1-n]); err != nil {
		t.Fatal(err)
	}
}

func setupExit(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *exitFix {
	t.Helper()
	f := &exitFix{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.inLog = f.k.Log().Len()
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
	f.ops, f.sec = ops, sec
	x, err := clerk.NewExit("web", opub, ops, sec, f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	f.x = x
	f.store, f.anchor, f.opub = &kernel.MemStore{}, &kernel.MemAnchor{}, opub
	f.cfg = kernel.Config{Store: f.store, Anchor: f.anchor, Pub: kpub, Sign: kpriv, Rand: rand.NewChaCha8([32]byte{1})}
	f.reboot(t, x, 0)
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
	content, labels, amount := f.x.Facts(s)
	s.Content, s.Labels, s.Amount = content, labels, amount
	s.Recipient = s.Args[key.RecipientArg(verb)].Value
	return kernel.Request{Plan: "p", Step: s, Key: f.root, Idem: idem, Now: 1}
}

func TestExitSendsDeclaredRequestWithSecretAndIdempotencyKey(t *testing.T) {
	f := setupExit(t, nil)
	r := f.x.Do(f.req(key.Post, "i1", map[string]string{"to": "bob&x=1", "msg": "hello"}), f.k.State())
	if r.Outcome != "ok" {
		t.Fatalf("declared post failed: %+v", r)
	}
	if f.got.auth != "Bearer "+canary || f.got.idem != "i1" || f.got.body != "hello" {
		t.Fatalf("request not as declared: %+v", f.got)
	}
	if f.got.path != "/v1/msg/bob&x=1" {
		t.Fatalf("argument escaped the path segment: %s", f.got.path)
	}
}

func TestExitIsIdempotentAndProbes(t *testing.T) {
	f := setupExit(t, nil)
	q := f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"})
	if f.x.Probe(q, f.k.State()) != "unknown" {
		t.Fatal("a clerk with no memory of a step must not claim it was never sent (KRN-8)")
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

func TestExitRestartThenProbeDoesNotResend(t *testing.T) {
	f := setupExit(t, nil)
	step := f.req(key.Post, "", map[string]string{"to": "bob", "msg": "hi"}).Step
	if err := f.k.Submit(0, kernel.Plan{ID: "p1", Key: f.root, Steps: []key.Step{step}}); err != nil {
		t.Fatal(err)
	}
	if err := f.k.Tick(0); err != nil {
		t.Fatal(err)
	}
	if f.hits.Load() != 1 {
		t.Fatalf("setup: %d hits", f.hits.Load())
	}
	f.cutLast(t, 1) // the result never reached disk; the request did
	x2, err := clerk.NewExit("web", f.opub, f.ops, f.sec, f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	f.reboot(t, x2, 1)
	if f.k.State().Plans["p1"].Steps[0].Phase != kernel.PUnknown {
		t.Fatal("an in-flight step must come back unknown")
	}
	for i := int64(1); i < 4; i++ {
		if err := f.k.Tick(i * kernel.ProbeEvery); err != nil {
			t.Fatal(err)
		}
	}
	if f.hits.Load() != 1 {
		t.Fatalf("a restart resent the step: %d requests", f.hits.Load())
	}
}

func TestExitDispatchIsLoggedBeforeTheRequestLeaves(t *testing.T) {
	f := setupExit(t, nil)
	step := f.req(key.Post, "", map[string]string{"to": "bob", "msg": "hi"}).Step
	if err := f.k.Submit(0, kernel.Plan{ID: "p1", Key: f.root, Steps: []key.Step{step}}); err != nil {
		t.Fatal(err)
	}
	before := f.k.Log().Len()
	if err := f.k.Tick(0); err != nil {
		t.Fatal(err)
	}
	if f.hits.Load() != 1 || f.inLog <= before {
		t.Fatalf("the request left before step.dispatch was in the log (log %d at send, %d before)", f.inLog, before)
	}
}

func TestExitRefusesSlotsOutsideThePath(t *testing.T) {
	sec := clerk.NewSecrets(sealer(t))
	opub, _ := gen(1)
	for name, u := range map[string]string{
		"host":       "https://{to}.example.invalid/v1",
		"port":       "https://example.invalid:{to}/v1",
		"userinfo":   "https://{to}@example.invalid/v1",
		"query":      "https://example.invalid/v1?q={to}",
		"fragment":   "https://example.invalid/v1#{to}",
		"upper":      "HTTPS://{to}.example.invalid/v1",
		"partial":    "https://example.invalid/v1/a{to}",
		"plain-http": "http://example.invalid/v1/{to}",
	} {
		_, err := clerk.NewExit("web", opub, []clerk.Op{{Verb: key.Post, Method: "POST", URL: u, Body: "msg", Content: "text"}}, sec, http.DefaultClient)
		if err == nil {
			t.Errorf("%s: declaration accepted", name)
		}
	}
}

func TestExitRefusesValuesThatWouldReshapeThePath(t *testing.T) {
	f := setupExit(t, nil)
	for _, to := range []string{"", ".", "..", "a/b", "a/../b"} {
		q := f.req(key.Post, "i-"+to, map[string]string{"to": to, "msg": "hi"})
		if r := f.x.Do(q, f.k.State()); r.Outcome != "failed" {
			t.Errorf("%q: %+v", to, r)
		}
	}
	if f.hits.Load() != 0 {
		t.Fatalf("%d requests left for refused values", f.hits.Load())
	}
}
