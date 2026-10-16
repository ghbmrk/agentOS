package holder

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-1, CRED-5, CRED-7, ADP-10

func canary(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + hex.EncodeToString(b)
}

// upstream stands in for the provider: it records what the holder sent.
type upstream struct {
	mu     sync.Mutex
	seen   []*http.Request
	bodies []string
	reply  func(r *http.Request) (*http.Response, error)
}

func (u *upstream) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	u.mu.Lock()
	u.seen = append(u.seen, r)
	u.bodies = append(u.bodies, string(body))
	u.mu.Unlock()
	return u.reply(r)
}

func (u *upstream) calls() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.seen)
}

func answer(status int, h http.Header, body string) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		if h == nil {
			h = http.Header{}
		}
		return &http.Response{StatusCode: status, Header: h.Clone(), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}
}

func planAdapter() egress.Adapter {
	return egress.Adapter{
		Name:       "plan",
		Host:       "plan.example",
		Credential: "plan-login",
		Inject:     egress.Injection{Header: "Authorization", Prefix: "Bearer "},
		Operations: []egress.Operation{
			{Name: "messages", Verb: egress.VerbRead, Method: "POST", Path: "/v1/messages", Refused: []int{http.StatusForbidden}},
			{Name: "send", Verb: egress.VerbSend, Method: "POST", Path: "/v1/send"},
			{
				Name: "token.refresh", Verb: egress.VerbRead, Method: "POST", Path: "/v1/oauth/token",
				Refused: []int{http.StatusUnauthorized},
				Response: &egress.ResponseRule{Fields: []egress.Field{
					{Name: "access_token", Kind: egress.FieldCredential},
					{Name: "refresh_token", Kind: egress.FieldCredential},
					{Name: "expires_in", Kind: egress.FieldNumber},
				}},
			},
		},
	}
}

type swapper struct{ got map[string]string }

func (s *swapper) Swap(_ string, creds map[string]string) (map[string]string, func() error, error) {
	out := map[string]string{}
	for k := range creds {
		out[k] = "placeholder-" + k
	}
	return out, func() error { s.got = creds; return nil }, nil
}

func newHolder(t *testing.T, up *upstream, sw egress.Swapper) *Holder {
	t.Helper()
	h, err := New(Config{Adapters: []egress.Adapter{planAdapter()}, Transport: up, Swapper: sw})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// req is the request egress hands the holder: the checked upstream request,
// with no credential.
func req(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, "http://plan.example"+path, strings.NewReader(body))
	r.Host = "plan.example"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept-Encoding", "identity")
	return r
}

// A request outside the declared shape gets no login: it never reaches the
// provider (ADP-10).
func TestShapeOutsideTheDeclarationGetsNoLogin(t *testing.T) {
	up := &upstream{reply: answer(200, nil, "{}")}
	h := newHolder(t, up, &swapper{})
	h.Hand([]byte(canary(t, "sk-canary-")))
	bad := map[string]*http.Request{
		"undeclared path": req("POST", "/v1/other", "{}"),
		"wrong method":    req("GET", "/v1/messages", ""),
		"non-read verb":   req("POST", "/v1/send", "{}"),
		"query string":    req("POST", "/v1/messages?model=other", "{}"),
		"unknown host":    func() *http.Request { r := req("POST", "/v1/messages", "{}"); r.Host = "other.example"; return r }(),
		"extra header": func() *http.Request {
			r := req("POST", "/v1/messages", "{}")
			r.Header.Set("X-Forwarded-For", "1")
			return r
		}(),
		"guest credential": func() *http.Request {
			r := req("POST", "/v1/messages", "{}")
			r.Header.Set("Authorization", "Bearer guest")
			return r
		}(),
		"encoding": func() *http.Request {
			r := req("POST", "/v1/messages", "{}")
			r.Header.Set("Accept-Encoding", "gzip")
			return r
		}(),
	}
	for name, r := range bad {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || w.Header().Get(ErrorHeader) != ErrRefused {
			t.Errorf("%s: status %d %q", name, w.Code, w.Header().Get(ErrorHeader))
		}
	}
	if n := up.calls(); n != 0 {
		t.Fatalf("provider reached %d times", n)
	}
}

// A holder with no secret sends nothing.
func TestNoSecretNoRequest(t *testing.T) {
	up := &upstream{reply: answer(200, nil, "{}")}
	h := newHolder(t, up, &swapper{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", "/v1/messages", "{}"))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get(ErrorHeader) != ErrNoSecret || up.calls() != 0 {
		t.Fatalf("status %d %q calls %d", w.Code, w.Header().Get(ErrorHeader), up.calls())
	}
	if h.Held() {
		t.Fatal("held before the hand")
	}
}

// The holder writes its own login into the declared header, and redacts it
// from everything it returns (CRED-7).
func TestHolderInjectsAndRedactsItsSecret(t *testing.T) {
	key := canary(t, "sk-canary-")
	var sent string
	up := &upstream{reply: func(r *http.Request) (*http.Response, error) {
		sent = r.Header.Get("Authorization")
		if r.URL.String() != "https://plan.example/v1/messages" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("upstream request %s %v", r.URL, r.Header)
		}
		return answer(200, http.Header{"Content-Type": {"application/json"}, "X-Request-Id": {key}, "Set-Cookie": {"a=" + key}},
			`{"echo":"`+key+`"}`)(r)
	}}
	h := newHolder(t, up, &swapper{})
	h.Hand([]byte(key))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", "/v1/messages", `{"m":1}`))
	if sent != "Bearer "+key {
		t.Fatalf("injected %q", sent)
	}
	if w.Code != 200 || strings.Contains(w.Body.String(), key) || !strings.Contains(w.Body.String(), vault.Placeholder) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	for k, vs := range w.Header() {
		for _, v := range vs {
			if strings.Contains(v, key) {
				t.Fatalf("header %s carries the key", k)
			}
		}
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Fatal("undeclared response header forwarded")
	}
}

// The exchange is swapped in the holder, with the proxy's rule: a declared
// shape is forwarded with placeholders; any other is dropped with the
// reason egress needs to stop the route (CRED-5, CRED-5t).
func TestHolderSwapsTheExchange(t *testing.T) {
	sw := &swapper{}
	access, refresh := canary(t, "at-canary-"), canary(t, "rt-canary-")
	json := http.Header{"Content-Type": {"application/json"}}
	for _, tc := range []struct {
		name   string
		status int
		body   string
		code   int
		drop   string
	}{
		{"declared", 200, `{"access_token":"` + access + `","refresh_token":"` + refresh + `","expires_in":3600}`, 200, ""},
		{"undeclared field", 200, `{"access_token":"` + access + `","refresh_token":"x","expires_in":1,"id_token":"y"}`, 502, egress.DropUnswappable},
		{"provider error", 500, `{"error":"x"}`, 502, egress.DropExchangeError},
		{"refused login", 401, `{"error":"` + access + `"}`, 401, ""},
	} {
		up := &upstream{reply: answer(tc.status, json, tc.body)}
		h := newHolder(t, up, sw)
		h.Hand([]byte(canary(t, "sk-canary-")))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req("POST", "/v1/oauth/token", `{"grant_type":"refresh_token"}`))
		if w.Code != tc.code || w.Header().Get(egress.HolderDropHeader) != tc.drop {
			t.Fatalf("%s: status %d drop %q", tc.name, w.Code, w.Header().Get(egress.HolderDropHeader))
		}
		if strings.Contains(w.Body.String(), access) || strings.Contains(w.Body.String(), refresh) {
			t.Fatalf("%s: issued credential reached egress: %s", tc.name, w.Body)
		}
		if tc.name == "declared" {
			if !strings.Contains(w.Body.String(), "placeholder-access_token") || sw.got["refresh_token"] != refresh {
				t.Fatalf("not swapped: %s %v", w.Body, sw.got)
			}
		}
	}
}

func socketDir(t *testing.T) string {
	t.Helper()
	// Unix socket paths are short; t.TempDir can be too long.
	d, err := os.MkdirTemp("", "hld")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// serve runs h on dir's two sockets until the test ends or stop is called.
func serve(t *testing.T, h *Holder, dir string, handUID int) (stop func()) {
	t.Helper()
	reqs, err := Listen(filepath.Join(dir, RequestSocket), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	hand, err := Listen(filepath.Join(dir, HandSocket), handUID)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { h.Serve(reqs, hand); close(done) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			reqs.Close()
			hand.Close()
			<-done
		})
	}
	t.Cleanup(stop)
	return stop
}

// Through the socket, the client gives egress the holder's answer, and
// turns the holder's own failures back into errors, so egress journals a
// refused destination as it does for its own dials (DEV-2).
func TestClientOverTheSocket(t *testing.T) {
	dir := socketDir(t)
	key := canary(t, "sk-canary-")
	var denied bool
	up := &upstream{reply: func(r *http.Request) (*http.Response, error) {
		if denied {
			return nil, netguard.ErrDenied
		}
		return answer(200, http.Header{"Content-Type": {"application/json"}}, `{"k":"`+key+`"}`)(r)
	}}
	h := newHolder(t, up, &swapper{})
	h.Hand([]byte(key))
	serve(t, h, dir, os.Getuid())
	rt := Client(filepath.Join(dir, RequestSocket))
	r, _ := http.NewRequest("POST", "https://plan.example/v1/messages", strings.NewReader("{}"))
	r.Header.Set("Accept-Encoding", "identity")
	resp, err := rt.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || bytes.Contains(b, []byte(key)) || !bytes.Contains(b, []byte(vault.Placeholder)) {
		t.Fatalf("status %d body %s", resp.StatusCode, b)
	}
	denied = true
	r, _ = http.NewRequest("POST", "https://plan.example/v1/messages", strings.NewReader("{}"))
	r.Header.Set("Accept-Encoding", "identity")
	if _, err := rt.RoundTrip(r); !errors.Is(err, netguard.ErrDenied) {
		t.Fatalf("denied destination: %v", err)
	}
	r, _ = http.NewRequest("GET", "https://plan.example/v1/nothing", nil)
	if _, err := rt.RoundTrip(r); err == nil {
		t.Fatal("refused shape came back as a response")
	}
}

// The hand socket admits only the unlock step's uid; nobody else can give
// the holder a secret (or learn whether it holds one).
func TestHandAdmitsOnlyItsUID(t *testing.T) {
	dir := socketDir(t)
	h := newHolder(t, &upstream{reply: answer(200, nil, "")}, &swapper{})
	serve(t, h, dir, os.Getuid()+1)
	k := &Keeper{Socket: filepath.Join(dir, HandSocket), Secret: func() ([]byte, error) { return []byte("sk-canary-x"), nil }}
	if _, err := k.Check(context.Background()); err == nil {
		t.Fatal("hand from another uid accepted")
	}
	if h.Held() {
		t.Fatal("holder took a secret from another uid")
	}
}

// The unlock step's keeper hands the secret, and hands it again when the
// holder restarts empty (SIM-split).
func TestKeeperRehandsAfterRestart(t *testing.T) {
	dir := socketDir(t)
	key := canary(t, "sk-canary-")
	k := &Keeper{Socket: filepath.Join(dir, HandSocket), Secret: func() ([]byte, error) { return []byte(key), nil }, Every: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go k.Run(ctx)

	for round := 0; round < 2; round++ {
		h := newHolder(t, &upstream{reply: answer(200, nil, "")}, &swapper{})
		stop := serve(t, h, dir, os.Getuid())
		deadline := time.Now().Add(5 * time.Second)
		for !h.Held() {
			if time.Now().After(deadline) {
				t.Fatalf("round %d: keeper never handed the secret", round)
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !h.holds([]byte(key)) {
			t.Fatalf("round %d: wrong secret", round)
		}
		stop()
	}
}

func TestNewChecksTheDeclaration(t *testing.T) {
	a, b := planAdapter(), planAdapter()
	b.Name = "plan2"
	if _, err := New(Config{Adapters: []egress.Adapter{a, b}}); err == nil {
		t.Fatal("two adapters on one host accepted")
	}
	b.Host, b.Credential = "other.example", "other-login"
	if _, err := New(Config{Adapters: []egress.Adapter{a, b}, Swapper: &swapper{}}); err == nil {
		t.Fatal("two credentials in one holder accepted")
	}
	if _, err := New(Config{Adapters: []egress.Adapter{a}}); err == nil {
		t.Fatal("exchange without a swapper accepted")
	}
	if _, err := New(Config{}); err == nil {
		t.Fatal("no adapter accepted")
	}
}

// REQ: CRED-5
// A login the provider refused (a declared refused-login status) is
// revoked in the holder: it is spent no more, and handing the same login
// again is refused, so nothing retries it (#1925). A new login (the owner
// signed in again) replaces it.
func TestRefusedLoginIsNotHandedAgain(t *testing.T) {
	key := canary(t, "sk-canary-")
	up := &upstream{reply: answer(http.StatusForbidden, nil, "")}
	h := newHolder(t, up, &swapper{})
	if err := h.Hand([]byte(key)); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", "/v1/messages", "{}"))
	if w.Code != http.StatusForbidden || up.calls() != 1 {
		t.Fatalf("refusal: status %d calls %d", w.Code, up.calls())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", "/v1/messages", "{}"))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get(ErrorHeader) != ErrRevoked || up.calls() != 1 {
		t.Fatalf("revoked login spent again: status %d %q calls %d", w.Code, w.Header().Get(ErrorHeader), up.calls())
	}
	if err := h.Hand([]byte(key)); !errors.Is(err, ErrRevokedLogin) {
		t.Fatalf("hand of the revoked login: %v", err)
	}
	if !h.Revoked() || !h.holds([]byte(key)) {
		t.Fatal("a refused hand changed the holder")
	}
	// Over the hand socket too.
	dir := socketDir(t)
	serve(t, h, dir, os.Getuid())
	k := &Keeper{Socket: filepath.Join(dir, HandSocket), Secret: func() ([]byte, error) { return []byte(key), nil }}
	if handed, err := k.Check(context.Background()); handed || !errors.Is(err, ErrRevokedLogin) {
		t.Fatalf("keeper re-handed the revoked login: %v %v", handed, err)
	}

	fresh := canary(t, "sk-canary-")
	if err := h.Hand([]byte(fresh)); err != nil || h.Revoked() {
		t.Fatalf("new login: %v, revoked %v", err, h.Revoked())
	}
	up.reply = answer(200, nil, "{}")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", "/v1/messages", "{}"))
	if w.Code != 200 || up.calls() != 2 {
		t.Fatalf("new login: status %d calls %d", w.Code, up.calls())
	}
}

// REQ: CRED-5
// A holder that restarts empty after its login was refused is not handed
// that login again: the keeper remembers it. Once the vault has a new
// login (the owner signed in again), the keeper hands that one, also to a
// holder still holding the revoked login (#1925).
func TestKeeperDoesNotRehandARevokedLogin(t *testing.T) {
	dir := socketDir(t)
	var mu sync.Mutex
	key := canary(t, "sk-canary-")
	secret := func() ([]byte, error) { mu.Lock(); defer mu.Unlock(); return []byte(key), nil }
	k := &Keeper{Socket: filepath.Join(dir, HandSocket), Secret: secret}
	ctx := context.Background()

	up := &upstream{reply: answer(http.StatusForbidden, nil, "")}
	h := newHolder(t, up, &swapper{})
	stop := serve(t, h, dir, os.Getuid())
	if handed, err := k.Check(ctx); !handed || err != nil {
		t.Fatalf("first hand: %v %v", handed, err)
	}
	h.ServeHTTP(httptest.NewRecorder(), req("POST", "/v1/messages", "{}"))
	if !h.Revoked() {
		t.Fatal("the refusal did not revoke the login")
	}
	if handed, _ := k.Check(ctx); handed {
		t.Fatal("keeper handed the revoked login to the revoked holder")
	}
	stop()

	// The holder restarts empty.
	h = newHolder(t, up, &swapper{})
	stop = serve(t, h, dir, os.Getuid())
	for i := 0; i < 3; i++ {
		if handed, _ := k.Check(ctx); handed || h.Held() {
			t.Fatalf("round %d: keeper re-handed the revoked login after a restart", i)
		}
	}
	mu.Lock()
	key = canary(t, "sk-canary-")
	mu.Unlock()
	if handed, err := k.Check(ctx); !handed || err != nil || !h.holds([]byte(key)) {
		t.Fatalf("new login after a restart: %v %v", handed, err)
	}
	stop()

	// A holder holding a revoked login takes the new one without a restart.
	h = newHolder(t, up, &swapper{})
	serve(t, h, dir, os.Getuid())
	if handed, err := k.Check(ctx); !handed || err != nil {
		t.Fatalf("hand: %v %v", handed, err)
	}
	h.ServeHTTP(httptest.NewRecorder(), req("POST", "/v1/messages", "{}"))
	mu.Lock()
	key = canary(t, "sk-canary-")
	mu.Unlock()
	if handed, err := k.Check(ctx); !handed || err != nil || !h.holds([]byte(key)) || h.Revoked() {
		t.Fatalf("new login to a revoked holder: %v %v", handed, err)
	}
}
