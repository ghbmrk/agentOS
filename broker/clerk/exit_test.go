package clerk_test

// REQ: CLK-1, CLK-2, CLK-3, CLK-4, KRN-8

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
)

const canary = "canary-token-7731"

type exitFix struct {
	k    *kernel.Kernel
	x    *clerk.Exit
	srv  *httptest.Server
	root key.Key
	hits atomic.Int32
	got  struct {
		auth, idem, body, path, query, ctype string
		header                               http.Header
	}

	store *kernel.MemStore
	cfg   kernel.Config
	opub  ed25519.PublicKey
	ops   []clerk.Op
	sec   *clerk.Secrets
	roots *x509.CertPool
	inLog int // log length the request handler saw
}

// resolver answers every name with one address.
// pub is a policy that has learned no home network: it refuses only the IANA
// special ranges. Shape tests never dial.
var pub = netguard.New(netguard.Config{})

type resolver netip.Addr

func (r resolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.Addr(r)}, nil
}

// guard is the home-network policy with the test server standing in for a
// host the name resolves to: the policy checks address a, then its connect
// seam reaches the server.
func (f *exitFix) guard(a netip.Addr) *netguard.Policy {
	return netguard.New(netguard.Config{Resolver: resolver(a), Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, f.srv.Listener.Addr().String())
	}})
}

// base is the test server under a name its certificate holds.
func (f *exitFix) base() string {
	return "https://example.com:" + f.srv.URL[strings.LastIndex(f.srv.URL, ":")+1:]
}

func (f *exitFix) decl(ops []clerk.Op) clerk.Declaration {
	return clerk.Declaration{Name: "web", Ops: ops, Guard: f.guard(netip.MustParseAddr("8.8.8.8"))}
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
	return setupExitOps(t, h, nil)
}

// setupExitOps lets a test change the declared ops before the exit is built.
func setupExitOps(t *testing.T, h func(w http.ResponseWriter, r *http.Request), mod func(base string, ops []clerk.Op)) *exitFix {
	t.Helper()
	f := &exitFix{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.inLog = f.k.Log().Len()
		b, _ := io.ReadAll(r.Body)
		f.got.auth, f.got.idem, f.got.body, f.got.path = r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key"), string(b), r.URL.EscapedPath()
		f.got.query, f.got.ctype, f.got.header = r.URL.RawQuery, r.Header.Get("Content-Type"), r.Header.Clone()
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
		{Verb: key.Post, Method: "POST", URL: f.base() + "/v1/msg/{to}", Slot: "web", Prefix: "Bearer ", Type: clerk.TypeForm, Body: map[string]string{"msg": "msg"}, Content: "text", Labels: []string{"public"}},
		{Verb: key.Fetch, Method: "GET", URL: f.base() + "/v1/doc/{url}", Content: "text", Labels: []string{"public"}},
	}
	if mod != nil {
		mod(f.base(), ops)
	}
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.srv.Certificate())
	f.ops, f.sec = ops, sec
	x, err := clerk.NewExit(f.decl(ops), opub, sec, f.roots)
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
	if f.got.auth != "Bearer "+canary || f.got.idem != "i1" || f.got.body != "msg=hello" || f.got.ctype != clerk.TypeForm {
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

func TestExitTransportErrorsCarryNoValues(t *testing.T) {
	f := setupExit(t, nil)
	f.srv.Close()
	r := f.x.Do(f.req(key.Post, "i1", map[string]string{"to": canary, "msg": "hi"}), f.k.State())
	if r.Outcome != "unknown" || !strings.HasPrefix(r.Detail, clerk.DNoAnswer+" ") || strings.Contains(r.Detail, canary) {
		t.Fatalf("transport error must be unknown, typed and value-free: %+v", r)
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
	if r.Outcome != "unknown" || !strings.HasPrefix(r.Detail, clerk.DRedirect) || other.Load() != 0 {
		t.Fatalf("a redirect must be unknown and never followed: %+v", r)
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
	bad := map[string]clerk.Op{
		"plain http":      {Verb: key.Fetch, Method: "GET", URL: "http://h.example/{url}"},
		"templated host":  {Verb: key.Fetch, Method: "GET", URL: "https://{url}.example/"},
		"unknown arg":     {Verb: key.Fetch, Method: "GET", URL: "https://h.example/{nope}"},
		"unknown verb":    {Verb: "teleport", Method: "GET", URL: "https://h.example/"},
		"missing slot":    {Verb: key.Fetch, Method: "GET", URL: "https://h.example/{url}", Slot: "ghost"},
		"bad method":      {Verb: key.Fetch, Method: "get all", URL: "https://h.example/{url}"},
		"body arg absent": {Verb: key.Fetch, Method: "POST", URL: "https://h.example/{url}", Type: clerk.TypeJSON, Body: map[string]string{"m": "msg"}},
	}
	for name, op := range bad {
		if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{op}}, opub, sec, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExitRestartThenProbeDoesNotResend(t *testing.T) {
	f := setupExit(t, nil)
	step := f.req(key.Post, "", map[string]string{"to": "bob", "msg": "hi"}).Step
	if err := f.k.Submit(0, kernel.Plan{ID: "p1", Key: f.root, Steps: []kernel.PlanStep{planStep(step)}}); err != nil {
		t.Fatal(err)
	}
	if err := f.k.Tick(0); err != nil {
		t.Fatal(err)
	}
	if f.hits.Load() != 1 {
		t.Fatalf("setup: %d hits", f.hits.Load())
	}
	f.cutLast(t, 1) // the result never reached disk; the request did
	x2, err := clerk.NewExit(f.decl(f.ops), f.opub, f.sec, f.roots)
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
	if err := f.k.Submit(0, kernel.Plan{ID: "p1", Key: f.root, Steps: []kernel.PlanStep{planStep(step)}}); err != nil {
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
		_, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{{Verb: key.Post, Method: "POST", URL: u, Content: "text"}}}, opub, sec, nil)
		if err == nil {
			t.Errorf("%s: declaration accepted", name)
		}
	}
}

func TestExitDeclarationRefusesDuplicateVerb(t *testing.T) {
	opub, _ := gen(1)
	op := clerk.Op{Verb: key.Post, Method: "POST", URL: "https://example.invalid/v1/{to}", Content: "text"}
	if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{op, op}}, opub, clerk.NewSecrets(sealer(t)), nil); err == nil {
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

// planStep is s as a plan carries it; the kernel derives the rest.
func planStep(s key.Step) kernel.PlanStep {
	args := map[string]string{}
	for n, a := range s.Args {
		args[n] = a.Value
	}
	return kernel.PlanStep{Verb: s.Verb, Clerk: s.Clerk, Args: args, Content: s.Content, Labels: s.Labels}
}

// run submits one step as plan p1 and ticks the kernel once per probe period.
func (f *exitFix) run(t *testing.T, step key.Step, ticks int) kernel.StepState {
	t.Helper()
	if err := f.k.Submit(0, kernel.Plan{ID: "p1", Key: f.root, Steps: []kernel.PlanStep{planStep(step)}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < ticks; i++ {
		if err := f.k.Tick(int64(i) * kernel.ProbeEvery); err != nil {
			t.Fatal(err)
		}
	}
	return f.k.State().Plans["p1"].Steps[0]
}

func TestExitEncodesDeclaredBodyFieldsAsJSON(t *testing.T) {
	f := setupExitOps(t, nil, func(_ string, ops []clerk.Op) {
		ops[0].Type, ops[0].Body = clerk.TypeJSON, map[string]string{"text": "msg", "to": "to"}
	})
	v := `hi", "admin": true, "x": "`
	if r := f.x.Do(f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": v}), f.k.State()); r.Outcome != "ok" {
		t.Fatalf("%+v", r)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(f.got.body), &got); err != nil || f.got.ctype != clerk.TypeJSON {
		t.Fatalf("body is not the declared JSON (%v): %s %s", err, f.got.ctype, f.got.body)
	}
	if len(got) != 2 || got["text"] != v || got["to"] != "bob" {
		t.Fatalf("a value added or changed a body field: %v", got)
	}
}

func TestExitFormBodyValueStaysOneField(t *testing.T) {
	f := setupExit(t, nil)
	if r := f.x.Do(f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "a&admin=1"}), f.k.State()); r.Outcome != "ok" {
		t.Fatalf("%+v", r)
	}
	q, err := url.ParseQuery(f.got.body)
	if err != nil || len(q) != 1 || q.Get("msg") != "a&admin=1" {
		t.Fatalf("a value added a form field: %q", f.got.body)
	}
}

func TestExitSendsDeclaredQueryAndKeepsConstantQuery(t *testing.T) {
	f := setupExitOps(t, nil, func(base string, ops []clerk.Op) {
		ops[1].URL, ops[1].Query = base+"/v1/search?fixed=1&sp=%20x", map[string]string{"q": "url"}
	})
	if r := f.x.Do(f.req(key.Fetch, "i1", map[string]string{"url": "a&admin=1#f"}), f.k.State()); r.Outcome != "ok" {
		t.Fatalf("%+v", r)
	}
	q, err := url.ParseQuery(f.got.query)
	if err != nil || len(q) != 3 || q.Get("fixed") != "1" || q.Get("sp") != " x" || q.Get("q") != "a&admin=1#f" || f.got.path != "/v1/search" {
		t.Fatalf("query not as declared: %s?%s", f.got.path, f.got.query)
	}
}

func TestExitSendsFixedHeaders(t *testing.T) {
	f := setupExitOps(t, nil, func(_ string, ops []clerk.Op) {
		ops[1].Headers = map[string]string{"Accept": "application/json", "X-Api-Version": "2"}
	})
	if r := f.x.Do(f.req(key.Fetch, "i1", map[string]string{"url": "a"}), f.k.State()); r.Outcome != "ok" {
		t.Fatalf("%+v", r)
	}
	if f.got.header.Get("Accept") != "application/json" || f.got.header.Get("X-Api-Version") != "2" || f.got.auth != "" {
		t.Fatalf("headers not as declared: %v", f.got.header)
	}
}

func TestNewExitRefusesUnsafeShapes(t *testing.T) {
	opub, _ := gen(1)
	empty := clerk.NewSecrets(sealer(t))
	one := clerk.NewSecrets(sealer(t))
	if err := one.Put("web", []byte(canary)); err != nil {
		t.Fatal(err)
	}
	get := func(o clerk.Op) clerk.Op {
		o.Verb, o.Method = key.Fetch, "GET"
		if o.URL == "" {
			o.URL = "https://h.example/v1/{url}"
		}
		return o
	}
	cases := map[string]struct {
		op  clerk.Op
		sec *clerk.Secrets
	}{
		"query slot in constant": {get(clerk.Op{URL: "https://h.example/v1?q={url}"}), empty},
		"query names no arg":     {get(clerk.Op{Query: map[string]string{"q": "nope"}}), empty},
		"query overrides fixed":  {get(clerk.Op{URL: "https://h.example/v1?q=1", Query: map[string]string{"q": "url"}}), empty},
		"query empty param":      {get(clerk.Op{Query: map[string]string{"": "url"}}), empty},
		"escape in path":         {get(clerk.Op{URL: "https://h.example/v1/a%2Fb?x=%20"}), empty},
		"bad constant query":     {get(clerk.Op{URL: "https://h.example/v1?x=%zz"}), empty},
		"body without type":      {get(clerk.Op{Body: map[string]string{"u": "url"}}), empty},
		"type without body":      {get(clerk.Op{Type: clerk.TypeJSON}), empty},
		"unknown type":           {get(clerk.Op{Type: "text/xml", Body: map[string]string{"u": "url"}}), empty},
		"header without slot":    {get(clerk.Op{Header: "X-Key"}), empty},
		"prefix without slot":    {get(clerk.Op{Prefix: "Bearer "}), empty},
		"fixed authorization":    {get(clerk.Op{Headers: map[string]string{"authorization": "Bearer x"}}), empty},
		"fixed cookie":           {get(clerk.Op{Headers: map[string]string{"Cookie": "a=b"}}), empty},
		"fixed host":             {get(clerk.Op{Headers: map[string]string{"Host": "evil.example"}}), empty},
		"fixed content-type":     {get(clerk.Op{Headers: map[string]string{"Content-Type": "text/plain"}}), empty},
		"fixed idempotency key":  {get(clerk.Op{Headers: map[string]string{"Idempotency-Key": "k"}}), empty},
		"header CRLF":            {get(clerk.Op{Headers: map[string]string{"X-A": "1\r\nX-B: 2"}}), empty},
		"header bad name":        {get(clerk.Op{Headers: map[string]string{"X A": "1"}}), empty},
		"fixed is secret header": {get(clerk.Op{Slot: "web", Header: "X-Key", Headers: map[string]string{"x-key": "v"}}), one},
		"secret in host header":  {get(clerk.Op{Slot: "web", Header: "Host"}), one},
		"secret prefix CRLF":     {get(clerk.Op{Slot: "web", Prefix: "B\r\nX: "}), one},
		"secret in idempotency":  {get(clerk.Op{Slot: "web", Header: "Idempotency-Key"}), one},
		"secret in cookie":       {get(clerk.Op{Slot: "web", Header: "Cookie"}), one},
		"fixed proxy auth":       {get(clerk.Op{Headers: map[string]string{"Proxy-Authorization": "x"}}), empty},
		"fixed connection":       {get(clerk.Op{Headers: map[string]string{"Connection": "close"}}), empty},
		"fixed keep-alive":       {get(clerk.Op{Headers: map[string]string{"Keep-Alive": "timeout=5"}}), empty},
		"fixed upgrade":          {get(clerk.Op{Headers: map[string]string{"Upgrade": "h2c"}}), empty},
		"fixed te":               {get(clerk.Op{Headers: map[string]string{"TE": "trailers"}}), empty},
		"fixed trailer":          {get(clerk.Op{Headers: map[string]string{"Trailer": "X-A"}}), empty},
		"fixed proxy-connection": {get(clerk.Op{Headers: map[string]string{"Proxy-Connection": "keep-alive"}}), empty},
		"fixed transfer-enc":     {get(clerk.Op{Headers: map[string]string{"Transfer-Encoding": "chunked"}}), empty},
		"fixed content-length":   {get(clerk.Op{Headers: map[string]string{"Content-Length": "0"}}), empty},
	}
	for name, c := range cases {
		if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{c.op}}, opub, c.sec, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A constant query may hold escapes; only the path may not.
	ok := get(clerk.Op{URL: "https://h.example/v1/{url}?a=%20b", Query: map[string]string{"q": "url"}, Headers: map[string]string{"Accept": "*/*"}})
	if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{ok}}, opub, empty, nil); err != nil {
		t.Fatalf("a safe shape was refused: %v", err)
	}
	if _, err := clerk.NewExit(clerk.Declaration{Guard: pub, Ops: []clerk.Op{ok}}, opub, empty, nil); err == nil {
		t.Fatal("a nameless clerk was accepted")
	}
	// Declarable headers are an allowlist: version, X- and negotiation headers,
	// and a secret in Authorization or an X- header.
	versioned := get(clerk.Op{Headers: map[string]string{"Notion-Version": "2022-06-28", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "agentos"}})
	if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{versioned}}, opub, empty, nil); err != nil {
		t.Fatalf("a declarable header was refused: %v", err)
	}
	if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{get(clerk.Op{Slot: "web", Header: "X-Api-Key"})}}, opub, one, nil); err != nil {
		t.Fatalf("a secret in an X- header was refused: %v", err)
	}
}

// REQ: DEV-2
func TestNewExitRefusesAMissingGuard(t *testing.T) {
	opub, _ := gen(1)
	op := clerk.Op{Verb: key.Fetch, Method: "GET", URL: "https://h.example/v1/{url}"}
	if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Ops: []clerk.Op{op}}, opub, nil, nil); err == nil {
		t.Fatal("a clerk without the home-network policy was accepted (DEV-2)")
	}
}

func TestExitHoldsOneSecretSlot(t *testing.T) {
	opub, _ := gen(1)
	op := func(v key.Verb, slot string) clerk.Op {
		return clerk.Op{Verb: v, Method: "POST", URL: "https://h.example/v1", Slot: slot}
	}
	two := clerk.NewSecrets(sealer(t))
	for _, s := range []string{"web", "bank"} {
		if err := two.Put(s, []byte(canary)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{op(key.Post, "web"), op(key.Fetch, "bank")}}, opub, two, nil); err == nil {
		t.Fatal("a clerk declared two secret slots (CLK-1)")
	}
	if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{op(key.Post, "web")}}, opub, two, nil); err == nil {
		t.Fatal("a clerk was handed a store holding another account's secret (CLK-1)")
	}
	if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{op(key.Post, "")}}, opub, two, nil); err == nil {
		t.Fatal("a clerk with no slot was handed secrets (CLK-1)")
	}
	if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{op(key.Post, "")}}, opub, nil, nil); err != nil {
		t.Fatalf("a clerk with no secret needs no store: %v", err)
	}
}

func TestExitDetailsAreTypedAndValueFree(t *testing.T) {
	var status atomic.Int32
	f := setupExit(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://elsewhere.invalid/"+canary)
		w.WriteHeader(int(status.Load()))
		io.WriteString(w, "echo "+canary)
	})
	for i, c := range []struct {
		code    int
		outcome string
		detail  string
	}{
		{200, "ok", "sent http 200"},
		{201, "ok", "sent http 201"},
		{302, "unknown", "redirect http 302"},
		{400, "failed", "rejected http 400"},
		{401, "failed", "auth http 401"},
		{402, "failed", "declined http 402"},
		{403, "failed", "auth http 403"},
		{404, "failed", "notfound http 404"},
		{408, "unknown", "timeout http 408"},
		{409, "unknown", "conflict http 409"},
		{410, "failed", "notfound http 410"},
		{422, "failed", "rejected http 422"},
		{429, "unknown", "busy http 429"},
		{500, "unknown", "server http 500"},
		{503, "unknown", "server http 503"},
	} {
		status.Store(int32(c.code))
		r := f.x.Do(f.req(key.Post, "i"+string(rune('a'+i)), map[string]string{"to": "bob-" + canary, "msg": "msg-" + canary}), f.k.State())
		if r.Outcome != c.outcome || r.Detail != c.detail {
			t.Errorf("%d: got %+v, want %s %q", c.code, r, c.outcome, c.detail)
		}
	}
	bad := f.x.Do(f.req(key.Post, "j", map[string]string{"to": "a/" + canary, "msg": "hi"}), f.k.State())
	if bad.Outcome != "failed" || bad.Detail != clerk.DArg+" to" {
		t.Fatalf("a bad value must name its argument only: %+v", bad)
	}
}

func TestExitBusyIsSentAgainAfterRetryAfter(t *testing.T) {
	var n atomic.Int32
	f := setupExit(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(429)
		}
	})
	step := f.req(key.Post, "", map[string]string{"to": "bob", "msg": "hi"}).Step
	st := f.run(t, step, 6)
	if st.Phase != kernel.PDone || f.hits.Load() != 2 {
		t.Fatalf("a 429 must be sent again once Retry-After passes: phase %s, %d requests", st.Phase, f.hits.Load())
	}
}

func TestExitBusyWaitsForRetryAfter(t *testing.T) {
	f := setupExit(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
	})
	q := f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"})
	f.x.Do(q, f.k.State())
	if f.x.Probe(q, f.k.State()) != "unknown" {
		t.Fatal("a 429 must not be sent again before Retry-After")
	}
	q.Now += 120_000
	if f.x.Probe(q, f.k.State()) != "notdone" {
		t.Fatal("a 429 is safe to send again after Retry-After")
	}
}

func TestExitBusyWaitIsCapped(t *testing.T) {
	f := setupExit(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "9223372036854775807")
		w.WriteHeader(429)
	})
	q := f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"})
	f.x.Do(q, f.k.State())
	if f.x.Probe(q, f.k.State()) != "unknown" {
		t.Fatal("a huge Retry-After must not overflow into an immediate resend")
	}
	q.Now += 24 * 60 * 60 * 1000
	if f.x.Probe(q, f.k.State()) != "notdone" {
		t.Fatal("a Retry-After wait is capped at one day")
	}
}

func TestExitIdempotentOpIsSentAgainAfterRestart(t *testing.T) {
	var idems []string
	f := setupExitOps(t, nil, func(_ string, ops []clerk.Op) { ops[0].Idempotent = true })
	step := f.req(key.Post, "", map[string]string{"to": "bob", "msg": "hi"}).Step
	if err := f.k.Submit(0, kernel.Plan{ID: "p1", Key: f.root, Steps: []kernel.PlanStep{planStep(step)}}); err != nil {
		t.Fatal(err)
	}
	if err := f.k.Tick(0); err != nil {
		t.Fatal(err)
	}
	idems = append(idems, f.got.idem)
	f.cutLast(t, 1)
	x2, err := clerk.NewExit(f.decl(f.ops), f.opub, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	f.reboot(t, x2, 1)
	for i := int64(1); i < 4; i++ {
		if err := f.k.Tick(i * kernel.ProbeEvery); err != nil {
			t.Fatal(err)
		}
	}
	idems = append(idems, f.got.idem)
	if st := f.k.State().Plans["p1"].Steps[0]; st.Phase != kernel.PDone || f.hits.Load() != 2 || idems[0] != idems[1] || idems[0] == "" {
		t.Fatalf("an idempotent op must be sent again under the same key: phase %s, %d requests, keys %q", st.Phase, f.hits.Load(), idems)
	}
}

func TestExitRedoIsBounded(t *testing.T) {
	f := setupExitOps(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) },
		func(_ string, ops []clerk.Op) { ops[0].Idempotent = true })
	step := f.req(key.Post, "", map[string]string{"to": "bob", "msg": "hi"}).Step
	st := f.run(t, step, 6*kernel.MaxChecks)
	if st.Phase != kernel.PParked || f.hits.Load() > kernel.MaxChecks {
		t.Fatalf("a failing idempotent op must stop: phase %s after %d requests", st.Phase, f.hits.Load())
	}
}

func TestExitDoesNotHoldItsLockAcrossARequest(t *testing.T) {
	in, out := make(chan struct{}), make(chan struct{})
	f := setupExit(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/slow") {
			close(in)
			<-out
		}
	})
	go f.x.Do(f.req(key.Post, "slow", map[string]string{"to": "slow", "msg": "hi"}), f.k.State())
	<-in
	done := make(chan string)
	go func() {
		q := f.req(key.Post, "other", map[string]string{"to": "bob", "msg": "hi"})
		f.x.Do(q, f.k.State())
		done <- f.x.Probe(f.req(key.Post, "slow", map[string]string{"to": "slow", "msg": "hi"}), f.k.State())
	}()
	select {
	case p := <-done:
		if p != "unknown" {
			t.Errorf("a step being sent must probe unknown, got %s", p)
		}
	case <-time.After(5 * time.Second):
		t.Error("a slow request blocked every other step")
	}
	close(out)
}

func TestExitRefusesNonPublicAddressesNotDeclared(t *testing.T) {
	f := setupExit(t, nil)
	// The name rebinds to loopback: the home-network policy refuses it at dial.
	x, err := clerk.NewExit(clerk.Declaration{Name: "web", Ops: f.ops, Guard: f.guard(netip.MustParseAddr("127.0.0.1"))}, f.opub, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	r := x.Do(f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"}), f.k.State())
	if r.Outcome != "failed" || r.Detail != clerk.DBlocked || f.hits.Load() != 0 {
		t.Fatalf("a loopback address was reached without being declared: %+v, %d requests", r, f.hits.Load())
	}
}

func TestExitChecksTheKeyBeforeAnsweringDone(t *testing.T) {
	f := setupExit(t, nil)
	q := f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"})
	if r := f.x.Do(q, f.k.State()); r.Outcome != "ok" {
		t.Fatalf("%+v", r)
	}
	v, _ := key.Verify(f.root, opubOf())
	if err := f.k.Revoke(2, v.ID()); err != nil {
		t.Fatal(err)
	}
	q.Now = 3
	if r := f.x.Do(q, f.k.State()); r.Outcome != "failed" {
		t.Fatalf("a revoked key got an answer from memory: %+v", r)
	}
}

func TestExitRefusesARecipientClaimOtherThanTheObject(t *testing.T) {
	f := setupExit(t, nil)
	q := f.req(key.Post, "i1", map[string]string{"to": "mallory", "msg": "hi"})
	q.Step.Recipient = "bob"
	if r := f.x.Do(q, f.k.State()); r.Outcome != "failed" || r.Detail != clerk.RClaim || f.hits.Load() != 0 {
		t.Fatalf("a step claiming another recipient was sent: %+v", r)
	}
}
