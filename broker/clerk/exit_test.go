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

	store *kernel.MemStore
	cfg   kernel.Config
	opub  ed25519.PublicKey
	ops   []clerk.Op
	sec   *clerk.Secrets
	inLog int // log length the request handler saw
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
	f.store, f.opub = &kernel.MemStore{}, opub
	f.cfg = kernel.Config{Store: f.store, Anchor: &kernel.MemAnchor{}, Pub: kpub, Sign: kpriv, Rand: rand.NewChaCha8([32]byte{1})}
	f.reboot(t, x, 0)
	f.root = key.Issue(opriv, key.Root{Holder: hpub, Clerk: "web", Verbs: []key.Verb{key.Post, key.Fetch}, Serial: "r1"})
	if err := f.k.Issue(0, f.root); err != nil {
		t.Fatal(err)
	}
	return f
}

// step is a plan step as an honest planner writes it: its claims are the
// clerk's own facts about it.
func (f *exitFix) step(verb key.Verb, args map[string]string) kernel.PlanStep {
	ps := kernel.PlanStep{Verb: verb, Clerk: "web", Args: args}
	ps.Content, ps.Labels, _ = f.x.Facts(kernel.Normalize("p", ps))
	return ps
}

// request is ps as the kernel hands it to the clerk: one step of a plan the
// root's holder signed.
func (f *exitFix) request(ps kernel.PlanStep, idem string) kernel.Request {
	p := kernel.SignPlan(kernel.Plan{ID: "p", Key: f.root, Steps: []kernel.PlanStep{ps}}, hpubPriv())
	return kernel.Request{Plan: p, Idem: idem, Now: 1}
}

func (f *exitFix) req(verb key.Verb, idem string, args map[string]string) kernel.Request {
	return f.request(f.step(verb, args), idem)
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
	u := f.step(key.Fetch, map[string]string{"url": "a"})
	u.Verb = key.Send
	if r := f.x.Do(f.request(u, "i1"), f.k.State()); r.Outcome != "failed" || f.hits.Load() != 0 {
		t.Fatal("undeclared verb must be refused without a request")
	}
	// A claim the clerk's own facts contradict.
	c := f.step(key.Post, map[string]string{"to": "bob", "msg": "hi"})
	c.Labels = []string{"private"}
	if r := f.x.Do(f.request(c, "i2"), f.k.State()); r.Outcome != "failed" || f.hits.Load() != 0 {
		t.Fatal("contradicted claim must be refused")
	}
	// A request with an extra argument.
	e := f.step(key.Post, map[string]string{"to": "bob", "msg": "hi", "extra": "x"})
	if r := f.x.Do(f.request(e, "i3"), f.k.State()); r.Outcome != "failed" || f.hits.Load() != 0 {
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
	if err := f.k.Revoke(2, f.root.Tip()); err != nil {
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
	step := f.step(key.Post, map[string]string{"to": "bob", "msg": "hi"})
	if err := f.k.Submit(0, kernel.SignPlan(kernel.Plan{ID: "p1", Key: f.root, Steps: []kernel.PlanStep{step}}, hpubPriv())); err != nil {
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
	step := f.step(key.Post, map[string]string{"to": "bob", "msg": "hi"})
	if err := f.k.Submit(0, kernel.SignPlan(kernel.Plan{ID: "p1", Key: f.root, Steps: []kernel.PlanStep{step}}, hpubPriv())); err != nil {
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
		"host":           "https://{to}.example.invalid/v1",
		"port":           "https://example.invalid:{to}/v1",
		"userinfo":       "https://{to}@example.invalid/v1",
		"query":          "https://example.invalid/v1?q={to}",
		"fragment":       "https://example.invalid/v1#{to}",
		"upper":          "HTTPS://{to}.example.invalid/v1",
		"partial":        "https://example.invalid/v1/a{to}",
		"plain-http":     "http://example.invalid/v1/{to}",
		"escape":         "https://example.invalid/v1/%2e%2e/{to}",
		"userinfo-fixed": "https://u:p@example.invalid/v1/{to}",
	} {
		_, err := clerk.NewExit("web", opub, []clerk.Op{{Verb: key.Post, Method: "POST", URL: u, Body: "msg", Content: "text"}}, sec, http.DefaultClient)
		if err == nil {
			t.Errorf("%s: declaration accepted", name)
		}
	}
}

func TestExitDeclarationRefusesDuplicateVerb(t *testing.T) {
	opub, _ := gen(1)
	op := clerk.Op{Verb: key.Post, Method: "POST", URL: "https://example.invalid/v1/{to}", Body: "msg", Content: "text"}
	if _, err := clerk.NewExit("web", opub, []clerk.Op{op, op}, clerk.NewSecrets(sealer(t)), http.DefaultClient); err == nil {
		t.Fatal("verb declared twice was accepted")
	}
}

func TestExitEscapesValuesAsOnePathSegment(t *testing.T) {
	f := setupExit(t, nil)
	if r := f.x.Do(f.req(key.Post, "i1", map[string]string{"to": "a?x=1#f", "msg": "hi"}), f.k.State()); r.Outcome != "ok" {
		t.Fatalf("%+v", r)
	}
	if f.got.path != "/v1/msg/a%3Fx=1%23f" {
		t.Fatalf("value not escaped as one segment: %s", f.got.path)
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
