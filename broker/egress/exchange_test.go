package egress

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// REQ: CRED-5, CRED-1, ADP-10
//
// CRED-5t: a broker-held plan route's token refresh. The proxy forwards a
// credential exchange's response only in its declared shape, with every
// credential the provider issued swapped for a placeholder; anything else
// is dropped, never forwarded to the CLI (trigger a). A response the
// declaration names as the provider refusing the login stops the route
// (trigger b). Either way the route stays stopped, so the CLI's retries
// never reach the provider, and the owner is told once. Only a refused
// login reopens on the owner's Resume.

// fakeSwapper stands in for the vault side of the swap. It stages a
// response's credentials, returns a fixed placeholder per field, and
// stores them only on commit. fail faults staging; badField gives that
// field a placeholder carrying its credential.
type fakeSwapper struct {
	mu       sync.Mutex
	got      map[string]string
	commits  int
	fail     error
	badField string
}

func (s *fakeSwapper) Swap(adapter string, creds map[string]string) (map[string]string, func() error, error) {
	if s.fail != nil {
		return nil, nil, s.fail
	}
	phs := map[string]string{}
	for k, v := range creds {
		phs[k] = "placeholder-" + k
		if k == s.badField {
			phs[k] = "ph-" + v
		}
	}
	return phs, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.commits++
		if s.got == nil {
			s.got = map[string]string{}
		}
		for k, v := range creds {
			s.got[adapter+"/"+k] = v
		}
		return nil
	}, nil
}

func (s *fakeSwapper) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

type failures struct {
	mu  sync.Mutex
	got []string
}

func (f *failures) told(adapter, reason string) {
	f.mu.Lock()
	f.got = append(f.got, adapter+": "+reason)
	f.mu.Unlock()
}

func (f *failures) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.got...)
}

// planAdapter is a broker-held plan relay as a declaration would give it:
// one inference endpoint and the CLI's own token refresh.
func planAdapter() Adapter {
	return Adapter{
		Name:       "plan",
		Host:       "plan.example",
		Credential: "openai-key",
		Inject:     Injection{Header: "Authorization", Prefix: "Bearer "},
		Operations: []Operation{
			{Name: "messages", Verb: VerbRead, Method: "POST", Path: "/v1/messages", Refused: []int{http.StatusForbidden}},
			{
				Name: "token.refresh", Verb: VerbRead, Method: "POST", Path: "/v1/oauth/token",
				Refused: []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden},
				Response: &ResponseRule{Fields: []Field{
					{Name: "access_token", Kind: FieldCredential},
					{Name: "refresh_token", Kind: FieldCredential},
					{Name: "expires_in", Kind: FieldNumber},
					{Name: "token_type", Kind: FieldText, Pattern: "Bearer"},
					{Name: "scope", Kind: FieldText, Pattern: "[a-z:._ ]{1,200}", Optional: true},
				}},
			},
		},
	}
}

type planRig struct {
	*rig
	swap  *fakeSwapper
	fails *failures
}

func newPlanRig(t *testing.T) *planRig {
	t.Helper()
	r := newRig(t, nil)
	pr := &planRig{rig: r, swap: &fakeSwapper{}, fails: &failures{}}
	p, err := New(Config{
		Adapters:    []Adapter{planAdapter()},
		Grants:      map[string][]string{"w1": {"plan"}},
		Vault:       r.vault,
		Transport:   r.transport,
		Audit:       r.audit,
		Swapper:     pr.swap,
		RouteFailed: pr.fails.told,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.proxy = p
	return pr
}

func refresh() *http.Request {
	req := httptest.NewRequest("POST", "/plan/v1/oauth/token", strings.NewReader(`{"grant_type":"refresh_token","refresh_token":"placeholder-refresh_token"}`))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func (r *planRig) answer(status int, contentType, body string) {
	r.provider.reply = func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.Header().Set("X-Request-Id", "req-1")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

// leaked reports whether s appears anywhere the CLI can read.
func leaked(w *httptest.ResponseRecorder, s string) bool {
	if strings.Contains(w.Body.String(), s) {
		return true
	}
	for _, vs := range w.Header() {
		for _, v := range vs {
			if strings.Contains(v, s) {
				return true
			}
		}
	}
	return false
}

// A refresh response in the declared shape reaches the CLI with each issued
// credential swapped for a placeholder; the credentials go to the swapper
// only.
func TestDeclaredRefreshIsSwapped(t *testing.T) {
	r := newPlanRig(t)
	access, refreshTok := synthetic(t, "canary-access-"), synthetic(t, "canary-refresh-")
	r.answer(200, "application/json; charset=utf-8",
		`{"access_token":"`+access+`","refresh_token":"`+refreshTok+`","expires_in":28800,"token_type":"Bearer","scope":"user:inference"}`)
	w := r.do(t, "w1", refresh())
	if w.Code != 200 {
		t.Fatalf("got %d %q", w.Code, w.Body)
	}
	if leaked(w, access) || leaked(w, refreshTok) || leaked(w, r.key) {
		t.Fatalf("issued credential reached the CLI: %v %q", w.Header(), w.Body)
	}
	for _, want := range []string{`"access_token":"placeholder-access_token"`, `"refresh_token":"placeholder-refresh_token"`, `"expires_in":28800`, `"token_type":"Bearer"`, `"scope":"user:inference"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("body %q lacks %s", w.Body, want)
		}
	}
	if r.swap.got["plan/access_token"] != access || r.swap.got["plan/refresh_token"] != refreshTok {
		t.Fatalf("swapper got %v", r.swap.got)
	}
	if got := r.fails.list(); len(got) != 0 {
		t.Fatalf("route failed: %v", got)
	}
	if r.provider.count() != 1 || r.provider.seen[0].Header.Get("Authorization") != "Bearer "+r.key {
		t.Fatal("refresh not sent with the vault credential")
	}
}

// Trigger (a): a refresh response the proxy cannot match to its declared
// shape is dropped whole. The synthetic canary in it never reaches the CLI
// (CRED-1), the swapper is never called, the denial is journaled with
// fixed text (ADP-10), the owner is told once, and the route stays stopped:
// the CLI's retries, on any operation, never reach the provider.
func TestUnswappableRefreshFailsClosed(t *testing.T) {
	const ok = `"expires_in":3600,"token_type":"Bearer"`
	cases := []struct {
		name, contentType, body string
	}{
		{"undeclared key", "application/json", `{"access_token":"A","refresh_token":"R",` + ok + `,"id_token":"CANARY"}`},
		{"nested object", "application/json", `{"access_token":"A","refresh_token":"R",` + ok + `,"scope":{"x":"CANARY"}}`},
		{"credential not a string", "application/json", `{"access_token":{"v":"CANARY"},"refresh_token":"R",` + ok + `}`},
		{"empty credential", "application/json", `{"access_token":"","refresh_token":"R",` + ok + `,"scope":"CANARY"}`},
		{"missing credential", "application/json", `{"access_token":"CANARY",` + ok + `}`},
		{"text off pattern", "application/json", `{"access_token":"A","refresh_token":"R","expires_in":3600,"token_type":"CANARY"}`},
		{"long number", "application/json", `{"access_token":"A","refresh_token":"R","expires_in":123456789012345678901234567890,"token_type":"Bearer"}`},
		{"number as string", "application/json", `{"access_token":"A","refresh_token":"R","expires_in":"CANARY","token_type":"Bearer"}`},
		{"top-level array", "application/json", `[{"access_token":"CANARY"}]`},
		{"trailing data", "application/json", `{"access_token":"A","refresh_token":"R",` + ok + `} {"t":"CANARY"}`},
		{"not json", "application/json", `access_token=CANARY&token_type=Bearer`},
		{"wrong content type", "text/plain", `{"access_token":"CANARY","refresh_token":"R",` + ok + `}`},
		{"no content type", "", `{"access_token":"CANARY","refresh_token":"R",` + ok + `}`},
		{"oversized", "application/json", `{"access_token":"CANARY","refresh_token":"R",` + ok + `,"scope":"` + strings.Repeat("a", MaxExchangeResponse) + `"}`},
		{"unexpected status", "application/json", `{"access_token":"CANARY","refresh_token":"R",` + ok + `}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newPlanRig(t)
			canary := synthetic(t, "canary-")
			body := strings.ReplaceAll(c.body, "CANARY", canary)
			status := 200
			if c.name == "unexpected status" {
				status = 201
			}
			r.answer(status, c.contentType, body)
			w := r.do(t, "w1", refresh())
			if w.Code != http.StatusBadGateway || w.Header().Get(DeniedHeader) != "1" {
				t.Fatalf("got %d %v %q", w.Code, w.Header(), w.Body)
			}
			if leaked(w, canary) || leaked(w, r.key) {
				t.Fatalf("canary reached the CLI: %v %q", w.Header(), w.Body)
			}
			if r.swap.calls() != 0 {
				t.Fatalf("swapper called on an unmatched response: %v", r.swap.got)
			}
			ev := r.audit.last(t)
			if ev.Allowed || ev.Adapter != "plan" || ev.Operation != "token.refresh" || ev.Reason != ReasonUnswappable {
				t.Fatalf("journaled %+v", ev)
			}
			if got := r.fails.list(); len(got) != 1 || got[0] != "plan: "+ReasonUnswappable {
				t.Fatalf("owner told %v", got)
			}
			// Retries, of the refresh and of inference, stop at the proxy.
			for _, req := range []*http.Request{refresh(), chat("/plan/v1/messages"), refresh()} {
				w := r.do(t, "w1", req)
				if w.Code != http.StatusServiceUnavailable || w.Header().Get(DeniedHeader) != "1" {
					t.Fatalf("retry got %d %q", w.Code, w.Body)
				}
			}
			if r.provider.count() != 1 {
				t.Fatalf("provider reached %d times after the route stopped", r.provider.count())
			}
			if got := r.fails.list(); len(got) != 1 {
				t.Fatalf("owner told more than once: %v", got)
			}
			if ev := r.audit.last(t); ev.Allowed || !strings.HasPrefix(ev.Reason, "route stopped") {
				t.Fatalf("retry journaled %+v", ev)
			}
		})
	}
}

// A swap the vault side cannot complete also fails closed: the issued
// credential cannot be held, so it is dropped and the route stops.
func TestFailedSwapFailsClosed(t *testing.T) {
	r := newPlanRig(t)
	r.swap.fail = errors.New("vault locked")
	canary := synthetic(t, "canary-")
	r.answer(200, "application/json", `{"access_token":"`+canary+`","refresh_token":"`+canary+`r","expires_in":1,"token_type":"Bearer"}`)
	w := r.do(t, "w1", refresh())
	if w.Code != http.StatusBadGateway || leaked(w, canary) {
		t.Fatalf("got %d %q", w.Code, w.Body)
	}
	if got := r.fails.list(); len(got) != 1 || got[0] != "plan: "+ReasonUnswappable {
		t.Fatalf("owner told %v", got)
	}
}

// An unswappable response keeps the route fallen back until a release
// requalifies the declaration: the owner's Resume does not reopen it, and
// a Proxy built again from the declaration (the release) does.
func TestUnswappableStopIsNotResumed(t *testing.T) {
	r := newPlanRig(t)
	canary := synthetic(t, "canary-")
	r.answer(200, "application/json", `{"access_token":"`+canary+`","refresh_token":"`+canary+`r","id_token":"`+canary+`i","expires_in":1,"token_type":"Bearer"}`)
	if w := r.do(t, "w1", refresh()); w.Code != http.StatusBadGateway {
		t.Fatalf("got %d", w.Code)
	}
	if err := r.proxy.Resume("plan"); !errors.Is(err, ErrRequalify) {
		t.Fatalf("Resume = %v, want ErrRequalify", err)
	}
	r.answer(200, "application/json", `{"content":[]}`)
	if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("after Resume got %d", w.Code)
	}
	if r.provider.count() != 1 {
		t.Fatalf("provider reached %d times", r.provider.count())
	}
	p, err := New(Config{
		Adapters: []Adapter{planAdapter()}, Grants: map[string][]string{"w1": {"plan"}},
		Vault: r.vault, Transport: r.transport, Audit: r.audit, RouteFailed: r.fails.told,
		Swapper: r.swap,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.proxy = p
	if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != 200 {
		t.Fatalf("after requalifying got %d %q", w.Code, w.Body)
	}
}

// A placeholder that carries a credential is no placeholder, and since the
// proxy checks every placeholder before it commits, a bad one on any field
// leaves nothing stored: a refresh is never held in part.
func TestPlaceholderMayNotCarryTheCredential(t *testing.T) {
	for _, field := range []string{"access_token", "refresh_token"} {
		t.Run(field, func(t *testing.T) {
			r := newPlanRig(t)
			r.swap.badField = field
			canary := synthetic(t, "canary-")
			r.answer(200, "application/json", `{"access_token":"`+canary+`","refresh_token":"`+canary+`r","expires_in":1,"token_type":"Bearer"}`)
			w := r.do(t, "w1", refresh())
			if w.Code != http.StatusBadGateway || leaked(w, canary) {
				t.Fatalf("got %d %q", w.Code, w.Body)
			}
			if r.swap.commits != 0 || r.swap.calls() != 0 {
				t.Fatalf("stored %v after a bad placeholder", r.swap.got)
			}
		})
	}
}

// The vault side gets one response's credentials in one call and commits
// them together, so a fault on any one stores none of them.
func TestPartialSwapStoresNothing(t *testing.T) {
	r := newPlanRig(t)
	rec := &recordingSwapper{faultOn: "refresh_token"}
	p, err := New(Config{
		Adapters: []Adapter{planAdapter()}, Grants: map[string][]string{"w1": {"plan"}},
		Vault: r.vault, Transport: r.transport, Audit: r.audit, RouteFailed: r.fails.told,
		Swapper: rec,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.proxy = p
	access, refreshTok := synthetic(t, "canary-access-"), synthetic(t, "canary-refresh-")
	r.answer(200, "application/json", `{"access_token":"`+access+`","refresh_token":"`+refreshTok+`","expires_in":1,"token_type":"Bearer"}`)
	w := r.do(t, "w1", refresh())
	if w.Code != http.StatusBadGateway || leaked(w, access) || leaked(w, refreshTok) {
		t.Fatalf("got %d %q", w.Code, w.Body)
	}
	if rec.calls != 1 || len(rec.seen) != 2 {
		t.Fatalf("swapper called %d times with %d fields; want one call with both", rec.calls, len(rec.seen))
	}
	if len(rec.stored) != 0 {
		t.Fatalf("stored %v after a fault", rec.stored)
	}
}

// recordingSwapper stages field by field, as a vault transaction would,
// and faults on faultOn; it stores only on commit.
type recordingSwapper struct {
	faultOn string
	calls   int
	seen    []string
	stored  map[string]string
}

func (s *recordingSwapper) Swap(_ string, creds map[string]string) (map[string]string, func() error, error) {
	s.calls++
	staged, phs := map[string]string{}, map[string]string{}
	for _, k := range []string{"access_token", "refresh_token"} {
		v, ok := creds[k]
		if !ok {
			continue
		}
		s.seen = append(s.seen, k)
		if k == s.faultOn {
			return nil, nil, errors.New("vault fault")
		}
		staged[k], phs[k] = v, "placeholder-"+k
	}
	return phs, func() error { s.stored = staged; return nil }, nil
}

// Trigger (b): a status the declaration names as the provider refusing the
// login stops the route. Its body is not forwarded, the owner is told once,
// and retries never reach the provider, since repeated retries can worsen
// an account restriction. Resume, after the owner has fixed it, reopens the
// route.
func TestRefusedLoginStopsRetrying(t *testing.T) {
	for _, c := range []struct {
		name string
		req  func() *http.Request
	}{
		{"refresh", refresh},
		{"inference", func() *http.Request { return chat("/plan/v1/messages") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newPlanRig(t)
			canary := synthetic(t, "canary-")
			r.answer(http.StatusForbidden, "application/json", `{"error":"account restricted","detail":"`+canary+`"}`)
			w := r.do(t, "w1", c.req())
			if w.Code != http.StatusServiceUnavailable || w.Header().Get(DeniedHeader) != "1" || leaked(w, canary) {
				t.Fatalf("got %d %v %q", w.Code, w.Header(), w.Body)
			}
			if ev := r.audit.last(t); ev.Allowed || ev.Reason != ReasonLoginRefused || ev.Status != http.StatusForbidden {
				t.Fatalf("journaled %+v", ev)
			}
			for i := 0; i < 3; i++ {
				if w := r.do(t, "w1", c.req()); w.Code != http.StatusServiceUnavailable {
					t.Fatalf("retry got %d", w.Code)
				}
			}
			if r.provider.count() != 1 {
				t.Fatalf("provider reached %d times", r.provider.count())
			}
			if got := r.fails.list(); len(got) != 1 || got[0] != "plan: "+ReasonLoginRefused {
				t.Fatalf("owner told %v", got)
			}

			if err := r.proxy.Resume("plan"); err != nil {
				t.Fatal(err)
			}
			r.answer(200, "application/json", `{"content":[]}`)
			if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != 200 {
				t.Fatalf("after Resume got %d %q", w.Code, w.Body)
			}
		})
	}
}

// A refusal status the declaration does not name is the provider's answer
// on an inference call, and does not stop the route. On a credential
// exchange no other status is forwarded, but only a declared refusal stops
// the route: a provider outage is not the login failing.
func TestUndeclaredStatusesDoNotStopTheRoute(t *testing.T) {
	r := newPlanRig(t)
	r.answer(http.StatusUnauthorized, "application/json", `{"error":"x"}`)
	if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != http.StatusUnauthorized {
		t.Fatalf("inference 401 got %d", w.Code)
	}
	r.answer(http.StatusServiceUnavailable, "application/json", `{"access_token":"x"}`)
	if w := r.do(t, "w1", refresh()); w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "access_token") {
		t.Fatalf("exchange 503 got %d %q", w.Code, w.Body)
	}
	if got := r.fails.list(); len(got) != 0 {
		t.Fatalf("route stopped: %v", got)
	}
	r.answer(200, "application/json", `{"content":[]}`)
	if w := r.do(t, "w1", chat("/plan/v1/messages")); w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
}

// A stopped route is the adapter's, not one machine's: one login per
// provider.
func TestStoppedRouteIsStoppedForEveryMachine(t *testing.T) {
	r := newRig(t, nil)
	fails := &failures{}
	p, err := New(Config{
		Adapters: []Adapter{planAdapter()}, Grants: map[string][]string{"w1": {"plan"}, "w2": {"plan"}},
		Vault: r.vault, Transport: r.transport, Audit: r.audit, Swapper: &fakeSwapper{}, RouteFailed: fails.told,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.proxy = p
	r.provider.reply = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }
	r.do(t, "w1", chat("/plan/v1/messages"))
	if w := r.do(t, "w2", chat("/plan/v1/messages")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("w2 got %d", w.Code)
	}
	if r.provider.count() != 1 {
		t.Fatalf("provider reached %d times", r.provider.count())
	}
}

// Declarations that would forward an exchange unswapped, or stop a route
// with nobody told, are refused.
func TestNewRefusesUnsafeExchangeDeclarations(t *testing.T) {
	base := func(mut func(*Adapter), cfg func(*Config)) error {
		a := planAdapter()
		if mut != nil {
			mut(&a)
		}
		c := Config{Adapters: []Adapter{a}, Vault: emptyVault{}, Audit: &auditLog{}, Swapper: &fakeSwapper{}, RouteFailed: func(string, string) {}}
		if cfg != nil {
			cfg(&c)
		}
		_, err := New(c)
		return err
	}
	if err := base(nil, nil); err != nil {
		t.Fatalf("valid declaration refused: %v", err)
	}
	exch := func(f func(*ResponseRule)) func(*Adapter) {
		return func(a *Adapter) { f(a.Operations[1].Response) }
	}
	bad := map[string]error{
		"no swapper":         base(nil, func(c *Config) { c.Swapper = nil }),
		"no route failed":    base(nil, func(c *Config) { c.RouteFailed = nil }),
		"refused, no notice": base(func(a *Adapter) { a.Operations = a.Operations[:1] }, func(c *Config) { c.RouteFailed = nil }),
		"no fields":          base(exch(func(r *ResponseRule) { r.Fields = nil }), nil),
		"no credential":      base(exch(func(r *ResponseRule) { r.Fields = r.Fields[2:] }), nil),
		"duplicate field":    base(exch(func(r *ResponseRule) { r.Fields = append(r.Fields, r.Fields[0]) }), nil),
		"unnamed field":      base(exch(func(r *ResponseRule) { r.Fields[2].Name = "" }), nil),
		"unknown kind":       base(exch(func(r *ResponseRule) { r.Fields[2].Kind = "object" }), nil),
		"text no pattern":    base(exch(func(r *ResponseRule) { r.Fields[3].Pattern = "" }), nil),
		"bad pattern":        base(exch(func(r *ResponseRule) { r.Fields[3].Pattern = "(" }), nil),
		"pattern on number":  base(exch(func(r *ResponseRule) { r.Fields[2].Pattern = ".*" }), nil),
		"refused 200":        base(func(a *Adapter) { a.Operations[0].Refused = []int{200} }, nil),
	}
	for name, err := range bad {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
