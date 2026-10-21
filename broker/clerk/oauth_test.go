package clerk_test

// REQ: CLK-1, CLK-2, CLK-4, OWN-17

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// oauthFix is an exit whose slot holds a refresh grant, against a server that
// is both the token endpoint (/token) and the API, which accepts only the
// access token it issued last.
type oauthFix struct {
	*exitFix
	mu      sync.Mutex
	redeems int
	grants  []url.Values // each token request's form
	api     []string     // each API request's Authorization
	live    string       // the access token the API accepts
	expires int64        // expires_in the endpoint answers with
	rotate  bool         // answer with a new refresh token
	refuse  int          // token endpoint status, 0 for 200
	deny    int          // status the API answers every request with, 0 to check the token
	seal    *testSealer  // the store's sealer
	d       clerk.Declaration
	diskMu  sync.Mutex
	disk    []byte      // the store's at-rest form, as last written
	noWrite atomic.Bool // the store's writes fail
	issue   string      // the access token to issue, "" for canary-access-N
	answer  string      // a raw token endpoint answer, "" for a good one
	// While gate is set, a token request signals entered and waits for
	// release before it is answered.
	gate             atomic.Bool
	entered, release chan struct{}
}

func setupOAuth(t *testing.T) *oauthFix {
	t.Helper()
	o := &oauthFix{expires: 100, rotate: true, entered: make(chan struct{}), release: make(chan struct{})}
	o.exitFix = setupExitOps(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" && o.gate.Load() {
			o.entered <- struct{}{}
			<-o.release
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if r.URL.Path == "/token" {
			b, _ := io.ReadAll(r.Body)
			o.grants = append(o.grants, mustForm(t, string(b)))
			if r.Header.Get("Content-Type") != clerk.TypeForm {
				w.WriteHeader(415)
				return
			}
			if o.answer != "" {
				fmt.Fprint(w, o.answer)
				return
			}
			if o.refuse != 0 {
				// An error answer that also carries a token must still fail.
				w.WriteHeader(o.refuse)
				fmt.Fprintf(w, `{"error":"invalid_grant","access_token":"canary-access-x","echo":%q}`, b)
				return
			}
			o.redeems++
			o.live = fmt.Sprintf("canary-access-%d", o.redeems)
			if o.issue != "" {
				o.live = o.issue
			}
			a := map[string]any{"access_token": o.live, "token_type": "Bearer", "expires_in": o.expires}
			if o.rotate {
				a["refresh_token"] = fmt.Sprintf("canary-refresh-%d", o.redeems)
			}
			json.NewEncoder(w).Encode(a)
			return
		}
		o.api = append(o.api, r.Header.Get("Authorization"))
		if o.deny != 0 {
			w.WriteHeader(o.deny)
		} else if r.Header.Get("Authorization") != "Bearer "+o.live {
			w.WriteHeader(401)
			fmt.Fprintf(w, "refused %s", r.Header.Get("Authorization"))
		}
	}, nil)
	o.seal = &testSealer{Sealer: sealer(t)}
	sec := o.durable()
	if err := sec.Put("web", clerk.KindGrant, []byte(`{"refresh_token":"canary-refresh-0","client_id":"agentos-test","client_secret":"canary-client-secret"}`)); err != nil {
		t.Fatal(err)
	}
	o.d = o.decl(o.ops)
	o.d.Refresh = o.base() + "/token"
	x, err := clerk.NewExit(o.d, o.opub, sec, o.roots)
	if err != nil {
		t.Fatal(err)
	}
	o.x, o.sec = x, sec
	o.reboot(t, x, 0)
	return o
}

// durable is an empty durable store that writes to o.disk.
func (o *oauthFix) durable() *clerk.Secrets {
	return clerk.NewSecrets(o.seal, func(b []byte) error {
		if o.noWrite.Load() {
			return errors.New("write failed")
		}
		o.diskMu.Lock()
		o.disk = bytes.Clone(b)
		o.diskMu.Unlock()
		return nil
	})
}

// restart builds the exit again from the store's at-rest form, as a reboot
// of the core does: nothing survives in memory.
func (o *oauthFix) restart(t *testing.T, now int64) {
	t.Helper()
	sec := o.durable()
	o.diskMu.Lock()
	err := sec.UnmarshalBinary(o.disk)
	o.diskMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	x, err := clerk.NewExit(o.d, o.opub, sec, o.roots)
	if err != nil {
		t.Fatal(err)
	}
	o.x, o.sec = x, sec
	o.reboot(t, x, now)
}

// testSealer fails every Seal while fail is set, and runs onSeal first.
type testSealer struct {
	clerk.Sealer
	fail   atomic.Bool
	onSeal func()
}

func (s *testSealer) Seal(plain, aad []byte) ([]byte, error) {
	if s.onSeal != nil {
		s.onSeal()
	}
	if s.fail.Load() {
		return nil, errors.New("seal failed")
	}
	return s.Sealer.Seal(plain, aad)
}

func mustForm(t *testing.T, s string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(s)
	if err != nil {
		t.Errorf("token request is not a form: %v", err)
	}
	return v
}

func (o *oauthFix) post(idem string, now int64) kernel.Result {
	q := o.req(key.Post, idem, map[string]string{"to": "bob", "msg": "hi"})
	q.Now = now
	return o.x.Do(q, o.k.State())
}

// noCanary fails if any token or grant value reached a result detail, the
// log or the store's at-rest form.
func (o *oauthFix) noCanary(t *testing.T, details ...string) {
	t.Helper()
	for _, d := range details {
		if strings.Contains(d, "canary") {
			t.Fatalf("a token reached a detail: %q", d)
		}
	}
	if strings.Contains(string(o.store.B), "canary") {
		t.Fatal("a token reached the log")
	}
	b, err := o.sec.MarshalBinary()
	if err != nil || strings.Contains(string(b), "canary") {
		t.Fatalf("a token is in the store unsealed: %v", err)
	}
}

func TestExitRefreshesAnExpiredAccessTokenWithoutLeakingIt(t *testing.T) {
	o := setupOAuth(t)
	r1 := o.post("i1", 1)
	r2 := o.post("i2", 1+50_000) // inside the token's life: no redemption
	r3 := o.post("i3", 1+91_000) // past 90% of 100s: redeemed again
	for _, r := range []kernel.Result{r1, r2, r3} {
		if r.Outcome != "ok" {
			t.Fatalf("%+v", r)
		}
	}
	if o.redeems != 2 || len(o.api) != 3 || o.api[0] != "Bearer canary-access-1" || o.api[1] != "Bearer canary-access-1" || o.api[2] != "Bearer canary-access-2" {
		t.Fatalf("redeems %d, API saw %q", o.redeems, o.api)
	}
	g0, g1 := o.grants[0], o.grants[1]
	if g0.Get("grant_type") != "refresh_token" || g0.Get("refresh_token") != "canary-refresh-0" || g0.Get("client_id") != "agentos-test" || g0.Get("client_secret") != "canary-client-secret" {
		t.Fatalf("first token request: %v", g0)
	}
	if g1.Get("refresh_token") != "canary-refresh-1" {
		t.Fatalf("the rotated refresh token was not sealed back: %v", g1)
	}
	o.noCanary(t, r1.Detail, r2.Detail, r3.Detail)
}

func TestExitRefreshesOnceOn401UnderTheSameKey(t *testing.T) {
	o := setupOAuth(t)
	o.expires = 0 // no declared life: only a 401 triggers a redemption
	if r := o.post("i1", 1); r.Outcome != "ok" {
		t.Fatalf("%+v", r)
	}
	o.mu.Lock()
	o.live = "revoked" // the remote drops the access token early
	o.mu.Unlock()
	q := o.req(key.Post, "i2", map[string]string{"to": "bob", "msg": "hi"})
	r := o.x.Do(q, o.k.State())
	if r.Outcome != "ok" || o.redeems != 2 || len(o.api) != 3 || o.api[2] != "Bearer canary-access-2" {
		t.Fatalf("%+v, redeems %d, API saw %q", r, o.redeems, o.api)
	}
	if o.x.Probe(q, o.k.State()) != "done" {
		t.Fatal("the resent step must probe done")
	}
	o.noCanary(t, r.Detail)
}

func TestExitDoesNotLoopOnA401AfterRefresh(t *testing.T) {
	o := setupOAuth(t)
	o.post("i0", 1)
	o.mu.Lock()
	o.deny = 401 // every token the endpoint issues is now refused
	o.mu.Unlock()
	before := len(o.api)
	r := o.post("i1", 2)
	if r.Outcome != "failed" || r.Detail != clerk.DAuth+" http 401" || len(o.api)-before != 2 || o.redeems != 2 {
		t.Fatalf("one resend after a 401, then the 401 stands: %+v, %d requests", r, len(o.api)-before)
	}
	o.noCanary(t, r.Detail)
}

func TestExitDoesNotRefreshOn403(t *testing.T) {
	o := setupOAuth(t)
	o.deny = 403 // forbidden is about the account, not the token
	r := o.post("i1", 1)
	if r.Outcome != "failed" || r.Detail != clerk.DAuth+" http 403" || len(o.api) != 1 || o.redeems != 1 {
		t.Fatalf("a 403 must stand without a refresh: %+v, redeems %d, API saw %q", r, o.redeems, o.api)
	}
}

// posts runs n steps at once, each under its own key, and returns their results.
func (o *oauthFix) posts(t *testing.T, n int, now int64) []kernel.Result {
	t.Helper()
	res := make([]kernel.Result, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res[i] = o.post(fmt.Sprintf("c%d", i), now)
		}()
	}
	wg.Wait()
	return res
}

func TestExitRedeemsOnceForConcurrentSteps(t *testing.T) {
	o := setupOAuth(t)
	for _, r := range o.posts(t, 16, 1) {
		if r.Outcome != "ok" {
			t.Fatalf("%+v", r)
		}
	}
	if o.redeems != 1 || len(o.grants) != 1 {
		t.Fatalf("concurrent steps spent the refresh token %d times", len(o.grants))
	}
}

func TestExitRedeemsOnceForConcurrent401s(t *testing.T) {
	o := setupOAuth(t)
	o.expires = 0 // only a 401 triggers a redemption
	o.post("i0", 1)
	o.mu.Lock()
	o.live = "revoked"
	o.mu.Unlock()
	for _, r := range o.posts(t, 16, 2) {
		if r.Outcome != "ok" {
			t.Fatalf("%+v", r)
		}
	}
	if o.redeems != 2 {
		t.Fatalf("steps refused on the same stale token redeemed %d times, want once more", o.redeems-1)
	}
}

func TestExitRotationSealFailureSendsNothing(t *testing.T) {
	o := setupOAuth(t)
	o.seal.fail.Store(true)
	r := o.post("i1", 1)
	if r.Outcome != "failed" || r.Detail != clerk.DCredential || len(o.api) != 0 {
		t.Fatalf("a rotated grant that cannot be sealed must fail before the API is reached: %+v, API saw %q", r, o.api)
	}
	o.noCanary(t, r.Detail)
}

func TestExitRefreshFailureSendsNothing(t *testing.T) {
	for _, code := range []int{400, 401, 500} {
		o := setupOAuth(t)
		o.refuse = code
		want := clerk.DReconnect + " web"
		if code == 500 {
			want = clerk.DRefresh + " http 500"
		}
		r := o.post("i1", 1)
		if r.Outcome != "failed" || r.Detail != want || len(o.api) != 0 {
			t.Fatalf("%d: a refused grant must fail as %q before the API is reached: %+v, API saw %q", code, want, r, o.api)
		}
		o.noCanary(t, r.Detail)
	}
}

func TestExitAsksForReconnectOnceAndStopsRedeeming(t *testing.T) {
	o := setupOAuth(t)
	o.refuse = 400 // invalid_grant: the owner revoked the app
	var details []string
	for i := range 3 {
		details = append(details, o.post(fmt.Sprintf("i%d", i), int64(1+i)).Detail)
	}
	if len(o.grants) != 1 || len(o.api) != 0 {
		t.Fatalf("a refused grant was redeemed %d times; it must be once until the owner reconnects", len(o.grants))
	}
	for _, d := range details {
		if d != clerk.DReconnect+" web" {
			t.Fatalf("every step on the account must give the one reconnect detail: %q", details)
		}
	}
	o.noCanary(t, details...)
}

func TestExitReconnectReplacesTheGrantDurably(t *testing.T) {
	o := setupOAuth(t)
	o.refuse = 400
	o.post("i1", 1)
	if err := o.x.Reconnect([]byte(`{"scope":"x","refresh_token":"canary-new"}`)); err == nil {
		t.Fatal("a grant with an unknown field was accepted")
	}
	o.refuse = 0
	if err := o.x.Reconnect([]byte(`{"refresh_token":"canary-new","client_id":"agentos-test","client_secret":"canary-client-secret"}`)); err != nil {
		t.Fatal(err)
	}
	if r := o.post("i2", 2); r.Outcome != "ok" || o.grants[len(o.grants)-1].Get("refresh_token") != "canary-new" {
		t.Fatalf("after a reconnect the new grant must be redeemed: %+v, %v", r, o.grants)
	}
	o.restart(t, 3)
	o.post("i3", 3)
	if g := o.grants[len(o.grants)-1].Get("refresh_token"); g != "canary-refresh-1" {
		t.Fatalf("the reconnected, rotated grant did not survive a restart: redeemed %q", g)
	}
	o.noCanary(t)
}

func TestReconnectNeedsARefreshClerk(t *testing.T) {
	f := setupExit(t, nil)
	if err := f.x.Reconnect([]byte(`{"refresh_token":"canary-r"}`)); err == nil {
		t.Fatal("a clerk with a static secret took a refresh grant")
	}
}

// The #2638 R1 acceptance test: rotate, restart from the at-rest form, and the
// rotated token is the one redeemed.
func TestExitRotatedGrantSurvivesARestart(t *testing.T) {
	o := setupOAuth(t)
	if r := o.post("i1", 1); r.Outcome != "ok" {
		t.Fatalf("%+v", r)
	}
	o.restart(t, 2)
	if r := o.post("i2", 2); r.Outcome != "ok" {
		t.Fatalf("%+v", r)
	}
	if g := o.grants[1].Get("refresh_token"); g != "canary-refresh-1" {
		t.Fatalf("after a restart the clerk redeemed %q, not the rotated token", g)
	}
	o.noCanary(t)
	o.diskMu.Lock()
	defer o.diskMu.Unlock()
	if strings.Contains(string(o.disk), "canary") {
		t.Fatal("a token is on disk unsealed")
	}
}

func TestExitKeepsARotatedGrantItCouldNotSave(t *testing.T) {
	o := setupOAuth(t)
	o.noWrite.Store(true)
	r := o.post("i1", 1)
	if r.Outcome != "failed" || r.Detail != clerk.DCredential || len(o.api) != 0 {
		t.Fatalf("a rotated grant that is not durable must fail the step before the API is reached: %+v, API saw %q", r, o.api)
	}
	o.noWrite.Store(false)
	if r := o.post("i2", 2); r.Outcome != "ok" || o.redeems != 1 {
		t.Fatalf("the kept grant must be saved and its token used: %+v, redeems %d", r, o.redeems)
	}
	o.restart(t, 3)
	o.post("i3", 3)
	if g := o.grants[len(o.grants)-1].Get("refresh_token"); g != "canary-refresh-1" {
		t.Fatalf("the rotated grant was dropped when its write failed: redeemed %q", g)
	}
}

// revokeOnSeal revokes the step's key while the clerk seals a rotated grant,
// that is, after Check at the top of Do and before the send.
func (o *oauthFix) revokeOnSeal(t *testing.T) {
	o.seal.onSeal = func() {
		o.seal.onSeal = nil
		if err := o.k.Revoke(2, o.root.Tip()); err != nil {
			t.Error(err)
		}
	}
}

func TestExitChecksAgainAfterRedeeming(t *testing.T) {
	o := setupOAuth(t)
	o.revokeOnSeal(t)
	r := o.post("i1", 2)
	if r.Outcome != "failed" || len(o.api) != 0 {
		t.Fatalf("a key revoked during the redemption still reached the API: %+v, API saw %q", r, o.api)
	}
}

func TestExitChecksAgainBeforeThe401Resend(t *testing.T) {
	o := setupOAuth(t)
	o.expires = 0
	o.post("i0", 1)
	o.mu.Lock()
	o.live = "revoked"
	o.mu.Unlock()
	o.revokeOnSeal(t)
	r := o.post("i1", 2)
	if r.Outcome != "failed" || len(o.api) != 2 || o.redeems != 2 {
		t.Fatalf("a key revoked during the 401 redemption still got its resend: %+v, API saw %q", r, o.api)
	}
}

func TestExitRefusesAnAccessTokenThatIsNotPlain(t *testing.T) {
	o := setupOAuth(t)
	o.issue = "canary-access\r\nX-Injected: 1"
	r := o.post("i1", 1)
	if r.Outcome != "failed" || r.Detail != clerk.DRefresh+" http 200" || len(o.api) != 0 {
		t.Fatalf("a token that is not plain must fail before the API is reached: %+v, API saw %q", r, o.api)
	}
	o.noCanary(t, r.Detail)
}

func TestExitRefusesAMalformedTokenAnswer(t *testing.T) {
	o := setupOAuth(t)
	o.answer = `{"access_token":"canary-access-x","expires_in":true}`
	r := o.post("i1", 1)
	if r.Outcome != "failed" || r.Detail != clerk.DRefresh+" http 200" || len(o.api) != 0 {
		t.Fatalf("a token answer that does not decode must fail before the API is reached: %+v, API saw %q", r, o.api)
	}
	o.noCanary(t, r.Detail)
}

func TestExitCapsAccessTokenLifeAtADay(t *testing.T) {
	o := setupOAuth(t)
	o.expires = 30 * 24 * 60 * 60
	o.post("i1", 1)
	o.post("i2", 1+24*60*60*1000)
	if o.redeems != 2 {
		t.Fatalf("a token declared to live 30 days was kept past a day: redeems %d", o.redeems)
	}
}

func TestExitRefreshKeepsTheGrantWhenNotRotated(t *testing.T) {
	o := setupOAuth(t)
	o.rotate = false
	o.post("i1", 1)
	o.post("i2", 1+91_000)
	if o.redeems != 2 || o.grants[1].Get("refresh_token") != "canary-refresh-0" {
		t.Fatalf("redeems %d, second grant %v", o.redeems, o.grants[1])
	}
}

func TestNewExitRefusesABadRefreshDeclaration(t *testing.T) {
	opub, _ := gen(1)
	op := clerk.Op{Verb: key.Post, Method: "POST", URL: "https://h.example/v1", Slot: "web", Prefix: "Bearer "}
	store := func(g string) *clerk.Secrets {
		s := clerk.NewSecrets(sealer(t), nil)
		if err := s.Put("web", clerk.KindGrant, []byte(g)); err != nil {
			t.Fatal(err)
		}
		return s
	}
	good := `{"refresh_token":"canary-r","client_id":"c"}`
	for name, c := range map[string]struct {
		url, grant string
		ops        []clerk.Op
	}{
		"http endpoint":       {"http://h.example/token", good, []clerk.Op{op}},
		"userinfo endpoint":   {"https://u:p@h.example/token", good, []clerk.Op{op}},
		"fragment endpoint":   {"https://h.example/token#f", good, []clerk.Op{op}},
		"no host":             {"https:///token", good, []clerk.Op{op}},
		"grant not json":      {"https://h.example/token", "canary-r", []clerk.Op{op}},
		"no refresh token":    {"https://h.example/token", `{"client_id":"c"}`, []clerk.Op{op}},
		"unknown grant field": {"https://h.example/token", `{"refresh_token":"canary-r","scope":"all"}`, []clerk.Op{op}},
		"no slot":             {"https://h.example/token", good, []clerk.Op{{Verb: key.Post, Method: "POST", URL: "https://h.example/v1"}}},
	} {
		if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: c.ops, Refresh: c.url}, opub, store(c.grant), nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{op}, Refresh: "https://h.example/token"}, opub, store(good), nil); err != nil {
		t.Fatalf("a good refresh declaration was refused: %v", err)
	}
}

func TestExitIgnoresProxyEnvironment(t *testing.T) {
	for _, v := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"} {
		t.Setenv(v, "http://127.0.0.1:1")
	}
	t.Setenv("NO_PROXY", "")
	f := setupExit(t, nil)
	if r := f.x.Do(f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"}), f.k.State()); r.Outcome != "ok" || f.hits.Load() != 1 {
		t.Fatalf("the exit went through a proxy from the environment: %+v", r)
	}
}

// #2638 R2: a slot is declared static or grant, and each path opens only its
// own kind, so a refresh grant never goes out as a bearer header.
func TestNewExitRefusesASlotOfTheOtherKind(t *testing.T) {
	opub, _ := gen(1)
	op := clerk.Op{Verb: key.Post, Method: "POST", URL: "https://h.example/v1", Slot: "web", Prefix: "Bearer "}
	grant := `{"refresh_token":"canary-r","client_id":"c","client_secret":"canary-s"}`
	for name, c := range map[string]struct {
		kind    clerk.Kind
		refresh string
	}{
		"grant in a static clerk":   {clerk.KindGrant, ""},
		"static in a refresh clerk": {clerk.KindStatic, "https://h.example/token"},
	} {
		s := clerk.NewSecrets(sealer(t), nil)
		if err := s.Put("web", c.kind, []byte(grant)); err != nil {
			t.Fatal(err)
		}
		if _, err := clerk.NewExit(clerk.Declaration{Name: "web", Guard: pub, Ops: []clerk.Op{op}, Refresh: c.refresh}, opub, s, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExitStaticPathNeverSendsAGrant(t *testing.T) {
	f := setupExit(t, nil)
	// The slot is replaced with a grant after the clerk was built.
	if err := f.sec.Put("web", clerk.KindGrant, []byte(`{"refresh_token":"canary-r","client_secret":"canary-s"}`)); err != nil {
		t.Fatal(err)
	}
	r := f.x.Do(f.req(key.Post, "i1", map[string]string{"to": "bob", "msg": "hi"}), f.k.State())
	if r.Outcome != "failed" || r.Detail != clerk.DCredential || f.hits.Load() != 0 {
		t.Fatalf("a grant went out on the static path: %+v, auth %q", r, f.got.auth)
	}
}

// reconnectMidRedeem calls Reconnect while a step is redeeming the old grant,
// then lets the token endpoint answer as answer sets it up. It returns the
// step's result.
func (o *oauthFix) reconnectMidRedeem(t *testing.T, answer func()) kernel.Result {
	t.Helper()
	o.gate.Store(true)
	res := make(chan kernel.Result)
	go func() { res <- o.post("i1", 1) }()
	<-o.entered
	o.gate.Store(false)
	o.mu.Lock()
	answer()
	o.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		done <- o.x.Reconnect([]byte(`{"refresh_token":"canary-new","client_id":"agentos-test","client_secret":"canary-client-secret"}`))
	}()
	// Reconnect must wait for the redemption in flight; give it the chance
	// to run ahead of it before the endpoint answers.
	select {
	case err := <-done:
		done <- err
	case <-time.After(100 * time.Millisecond):
	}
	close(o.release)
	r := <-res
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReconnectDuringARefusedRedemptionIsNotLatched(t *testing.T) {
	o := setupOAuth(t)
	o.reconnectMidRedeem(t, func() { o.refuse = 400 })
	o.refuse = 0
	if r := o.post("i2", 2); r.Outcome != "ok" || o.grants[len(o.grants)-1].Get("refresh_token") != "canary-new" {
		t.Fatalf("an old grant's refusal undid the owner's reconnect: %+v", r)
	}
}

func TestReconnectDuringARotationKeepsTheNewGrant(t *testing.T) {
	o := setupOAuth(t)
	o.reconnectMidRedeem(t, func() {})
	n := len(o.grants)
	if r := o.post("i2", 2); r.Outcome != "ok" || len(o.grants) != n+1 || o.grants[n].Get("refresh_token") != "canary-new" {
		t.Fatalf("the old grant's rotation, or its access token, outlived the owner's reconnect: %+v, grants %v", r, o.grants)
	}
}

func TestReconnectOnALiveClerkSendsTheNewGrantsToken(t *testing.T) {
	o := setupOAuth(t)
	o.post("i1", 1) // canary-access-1 is cached for 90 s
	if err := o.x.Reconnect([]byte(`{"refresh_token":"canary-new","client_id":"agentos-test"}`)); err != nil {
		t.Fatal(err)
	}
	r := o.post("i2", 2)
	if r.Outcome != "ok" || len(o.grants) != 2 || o.grants[1].Get("refresh_token") != "canary-new" || o.api[1] != "Bearer canary-access-2" {
		t.Fatalf("the old access token outlived a reconnect: %+v, grants %v, API saw %q", r, o.grants, o.api)
	}
}

func TestReconnectThatCannotWriteChangesNothing(t *testing.T) {
	grant := []byte(`{"refresh_token":"canary-new","client_id":"agentos-test"}`)
	t.Run("latched", func(t *testing.T) {
		o := setupOAuth(t)
		o.refuse = 400
		o.post("i1", 1)
		o.noWrite.Store(true)
		if err := o.x.Reconnect(grant); err == nil {
			t.Fatal("a reconnect whose grant was not written reported success")
		}
		o.refuse = 0
		if r := o.post("i2", 2); r.Detail != clerk.DReconnect+" web" || len(o.grants) != 1 {
			t.Fatalf("a failed reconnect cleared the latch: %+v, %d token requests", r, len(o.grants))
		}
	})
	t.Run("unsaved", func(t *testing.T) {
		o := setupOAuth(t)
		o.noWrite.Store(true)
		o.post("i1", 1) // rotated to canary-refresh-1, not saved
		if err := o.x.Reconnect(grant); err == nil {
			t.Fatal("a reconnect whose grant was not written reported success")
		}
		o.noWrite.Store(false)
		if r := o.post("i2", 2); r.Outcome != "ok" {
			t.Fatalf("%+v", r)
		}
		o.restart(t, 3)
		o.post("i3", 3)
		if g := o.grants[len(o.grants)-1].Get("refresh_token"); g != "canary-refresh-1" {
			t.Fatalf("a failed reconnect dropped the kept rotated grant: redeemed %q", g)
		}
	})
}
