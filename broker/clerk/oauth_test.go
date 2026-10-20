package clerk_test

// REQ: CLK-1, CLK-4

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

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
	deny    bool         // the API refuses every token
	issue   string       // the access token to issue, "" for canary-access-N
}

func setupOAuth(t *testing.T) *oauthFix {
	t.Helper()
	o := &oauthFix{expires: 100, rotate: true}
	o.exitFix = setupExitOps(t, func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		defer o.mu.Unlock()
		if r.URL.Path == "/token" {
			o.grants = append(o.grants, mustForm(t, o.got.body))
			if o.refuse != 0 {
				w.WriteHeader(o.refuse)
				fmt.Fprintf(w, `{"error":"invalid_grant","echo":%q}`, o.got.body)
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
		if o.deny || r.Header.Get("Authorization") != "Bearer "+o.live {
			w.WriteHeader(401)
			fmt.Fprintf(w, "refused %s", r.Header.Get("Authorization"))
		}
	}, nil)
	sec := clerk.NewSecrets(sealer(t))
	if err := sec.Put("web", []byte(`{"refresh_token":"canary-refresh-0","client_id":"agentos-test","client_secret":"canary-client-secret"}`)); err != nil {
		t.Fatal(err)
	}
	d := o.decl(o.ops)
	d.Refresh = o.base() + "/token"
	x, err := clerk.NewExit(d, o.opub, sec, o.roots)
	if err != nil {
		t.Fatal(err)
	}
	o.x, o.sec = x, sec
	o.reboot(t, x, 0)
	return o
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
	o.deny = true // every token the endpoint issues is now refused
	o.mu.Unlock()
	before := len(o.api)
	r := o.post("i1", 2)
	if r.Outcome != "failed" || r.Detail != clerk.DAuth+" http 401" || len(o.api)-before != 2 || o.redeems != 2 {
		t.Fatalf("one resend after a 401, then the 401 stands: %+v, %d requests", r, len(o.api)-before)
	}
	o.noCanary(t, r.Detail)
}

func TestExitRefreshFailureSendsNothing(t *testing.T) {
	o := setupOAuth(t)
	o.refuse = 400
	r := o.post("i1", 1)
	if r.Outcome != "failed" || r.Detail != clerk.DRefresh+" http 400" || len(o.api) != 0 {
		t.Fatalf("a refused grant must fail before the API is reached: %+v, API saw %q", r, o.api)
	}
	o.noCanary(t, r.Detail)
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
		s := clerk.NewSecrets(sealer(t))
		if err := s.Put("web", []byte(g)); err != nil {
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
