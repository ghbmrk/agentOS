package egress

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-5

// sameAccount is a fresh synthetic token set for old's account, as a
// provider's refresh answer carries.
func sameAccount(t *testing.T, old canaryLogin) canaryLogin {
	t.Helper()
	c := newCanaryLogin(t)
	c.account = old.account
	c.idToken = fakeJWT(map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": old.account},
	}) + "." + synthetic(t, "sig")
	return c
}

// singleUseAuth is the provider's token endpoint: each refresh token works
// once, and a spent one is refused with invalid_grant.
type singleUseAuth struct {
	mu        sync.Mutex
	live      string        // the one refresh token it accepts now
	next      []canaryLogin // the token sets it issues, in order
	exchanges int
	gate      chan struct{} // when set, the next exchange waits on it
}

func (a *singleUseAuth) RoundTrip(r *http.Request) (*http.Response, error) {
	var body map[string]string
	json.NewDecoder(r.Body).Decode(&body)
	a.mu.Lock()
	a.exchanges++
	gate := a.gate
	a.gate = nil
	a.mu.Unlock()
	if gate != nil {
		<-gate
	}
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	a.mu.Lock()
	defer a.mu.Unlock()
	if body["refresh_token"] == "" || body["refresh_token"] != a.live || len(a.next) == 0 {
		rec.WriteHeader(http.StatusBadRequest)
		io.WriteString(rec, `{"error":"invalid_grant"}`)
		return rec.Result(), nil
	}
	n := a.next[0]
	a.next, a.live = a.next[1:], n.refresh
	json.NewEncoder(rec).Encode(map[string]any{
		"access_token": n.access, "refresh_token": n.refresh, "id_token": n.idToken,
		"expires_in": 864000, "token_type": "bearer",
	})
	return rec.Result(), nil
}

func (a *singleUseAuth) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.exchanges
}

func eventually(cond func() bool) bool {
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

// CRED-5 (#1749): one plan login serves many workers, so two workers that
// refresh at once must share one exchange of the single-use refresh token.
// Each gets its own placeholders for the new login, and the route stays up.
func TestConcurrentRefreshesShareOneExchange(t *testing.T) {
	r := newLoginRig(t)
	old := newCanaryLogin(t)
	r.store(t, "w1", old)
	ph := map[string]map[string]string{}
	for _, w := range []string{"w1", "w2"} {
		ph[w] = authTokens(t, must(r.logins.AuthJSON("codex", w)))
	}
	fresh, later := sameAccount(t, old), sameAccount(t, old)
	gate := make(chan struct{})
	auth := &singleUseAuth{live: old.refresh, next: []canaryLogin{fresh, later}, gate: gate}
	route := map[string]http.Handler{}
	for _, w := range []string{"w1", "w2"} {
		h, err := NewWorkerRoute(WorkerRouteConfig{Route: Codex(), Worker: w, Logins: r.logins, Transport: auth, Audit: &auditLog{}})
		if err != nil {
			t.Fatal(err)
		}
		route[w] = h
	}

	got := map[string]*httptest.ResponseRecorder{}
	var wg sync.WaitGroup
	run := func(w string) {
		rec := httptest.NewRecorder()
		got[w] = rec
		wg.Add(1)
		go func() {
			defer wg.Done()
			route[w].ServeHTTP(rec, refreshReq(ph[w]["refresh_token"]))
		}()
	}
	run("w1")
	if !eventually(func() bool { return auth.count() == 1 }) {
		t.Fatal("first refresh never reached the provider")
	}
	run("w2")
	// w2 arrives while w1's exchange is in flight; it must join it rather
	// than spend the same token again.
	joined := eventually(func() bool { return r.logins.joined("codex") == 1 })
	close(gate)
	wg.Wait()
	if !joined {
		t.Error("second refresh did not join the one in flight")
	}
	if n := auth.count(); n != 1 {
		t.Fatalf("%d exchanges upstream for two concurrent refreshes, want 1", n)
	}

	reals := append(old.all(), fresh.all()...)
	seen := map[string]bool{}
	for _, w := range []string{"w1", "w2"} {
		rec := got[w]
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", w, rec.Code, rec.Body)
		}
		for _, v := range reals {
			if bytes.Contains(rec.Body.Bytes(), []byte(v)) {
				t.Fatalf("%s: response carries a real value", w)
			}
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		for field, want := range map[string]string{"access_token": fresh.access, "refresh_token": fresh.refresh} {
			p, _ := out[field].(string)
			if seen[p] {
				t.Fatalf("%s: %s placeholder shared with another worker", w, field)
			}
			seen[p] = true
			if v, ok := r.logins.Resolve("codex", w, p); !ok || v != want {
				t.Fatalf("%s: %s placeholder does not resolve to the new login", w, field)
			}
		}
		if _, ok := r.logins.Resolve("codex", other(w), out["refresh_token"].(string)); ok {
			t.Fatalf("%s: placeholder resolves for the other worker", w)
		}
	}
	if e := r.entry(t); e["refresh_token"] != fresh.refresh || e["access_token"] != fresh.access {
		t.Fatal("vault does not hold the new login")
	}

	// The route stays up: the next refresh spends the new token.
	rec := httptest.NewRecorder()
	route["w2"].ServeHTTP(rec, refreshReq(ph["w2"]["refresh_token"]))
	if rec.Code != http.StatusOK || auth.count() != 2 {
		t.Fatalf("later refresh: status %d after %d exchanges", rec.Code, auth.count())
	}
	if e := r.entry(t); e["refresh_token"] != later.refresh {
		t.Fatal("later refresh not stored")
	}
}

func other(w string) string {
	if w == "w1" {
		return "w2"
	}
	return "w1"
}

// accessOnly is a refresh answer that omits the refresh token, which a
// provider may send when it keeps the old one.
func accessOnly(c canaryLogin) map[string]string {
	return map[string]string{"access_token": c.access, "id_token": c.idToken}
}

// #1749: a refresh answer that omits the refresh token must not write back
// the token set its swap loaded when another refresh committed in between.
func TestARefreshWithoutRefreshTokenKeepsTheNewerOne(t *testing.T) {
	r := newLoginRig(t)
	old := newCanaryLogin(t)
	r.store(t, "w1", old)
	full, partial := sameAccount(t, old), sameAccount(t, old)
	_, commitFull, err := r.logins.ForWorker("codex", "w1").Swap("codex", full.creds())
	if err != nil {
		t.Fatal(err)
	}
	_, commitPartial, err := r.logins.ForWorker("codex", "w2").Swap("codex", accessOnly(partial))
	if err != nil {
		t.Fatal(err)
	}
	if err := commitFull(); err != nil {
		t.Fatal(err)
	}
	if err := commitPartial(); err != nil {
		t.Fatal(err)
	}
	e := r.entry(t)
	if e["refresh_token"] != full.refresh {
		t.Fatal("a stale refresh token was written back over the newer one")
	}
	if e["access_token"] != partial.access {
		t.Fatal("the later access token was not stored")
	}
}

// pausingStore holds the first Secret read after it is armed until
// released, so a test can stop a commit between its load and its Put.
type pausingStore struct {
	LoginStore
	mu      sync.Mutex
	armed   bool
	paused  chan struct{}
	release chan struct{}
}

func (s *pausingStore) Secret(name string) (vault.Secret, bool) {
	sec, ok := s.LoginStore.Secret(name)
	s.mu.Lock()
	a := s.armed
	s.armed = false
	s.mu.Unlock()
	if a {
		close(s.paused)
		<-s.release
	}
	return sec, ok
}

// #1749: a commit holds the provider's lock from its load to its Put, so a
// commit that lands while another is between the two is not lost.
func TestCommitsHoldTheProviderLockFromLoadToPut(t *testing.T) {
	r := newLoginRig(t)
	ps := &pausingStore{LoginStore: r.v, paused: make(chan struct{}), release: make(chan struct{})}
	p := NewPlanLogins(func() (LoginStore, error) { return ps, nil }, nil)
	old := newCanaryLogin(t)
	if _, c, err := p.ForSignIn("codex", "w1").Swap("codex", old.creds()); err != nil || c() != nil {
		t.Fatal("sign-in failed")
	}
	partial, full := sameAccount(t, old), sameAccount(t, old)
	_, commitPartial, err := p.ForWorker("codex", "w1").Swap("codex", accessOnly(partial))
	if err != nil {
		t.Fatal(err)
	}
	_, commitFull, err := p.ForWorker("codex", "w2").Swap("codex", full.creds())
	if err != nil {
		t.Fatal(err)
	}

	ps.mu.Lock()
	ps.armed = true
	ps.mu.Unlock()
	errs := make(chan error, 2)
	go func() { errs <- commitPartial() }()
	select {
	case <-ps.paused:
	case <-time.After(2 * time.Second):
		close(ps.release)
		t.Fatal("commit does not load the login it writes over")
	}
	fullDone := make(chan struct{})
	go func() { errs <- commitFull(); close(fullDone) }()
	select {
	case <-fullDone: // no lock: the second commit lands mid-way through the first
	case <-time.After(100 * time.Millisecond): // it waits on the lock
	}
	close(ps.release)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	e := r.entry(t)
	if e["refresh_token"] != full.refresh {
		t.Fatal("a commit wrote back the token set it loaded before another commit")
	}
}
