package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-5, CAP-9, ONB-3, CRED-1

// setupCall sends one provider request to the verify socket's handler.
func setupCall(t *testing.T, c *custody, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	verifyHandler(c).ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
	return w
}

func listed(t *testing.T, w *httptest.ResponseRecorder) map[string]modelroute.SetupProvider {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var l modelroute.SetupProviderList
	if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	out := map[string]modelroute.SetupProvider{}
	for _, p := range l.Providers {
		out[p.ID] = p
	}
	return out
}

// providerRig is a setup rig whose vault holds no provider key yet
// (newFastRig seeds one for the proxy's tests).
func providerRig(t *testing.T) *fastRig {
	t.Helper()
	r := newSetupRig(t)
	v, err := vault.Open(r.path, r.key)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Delete("openai"); err != nil {
		t.Fatal(err)
	}
	return r
}

func keyBody(provider, key string) string {
	b, _ := json.Marshal(modelroute.SetupKeyRequest{Provider: provider, Key: key})
	return string(b)
}

// P2-2w c4e: setup's AI step lists the built-in providers, stores an API
// key in the vault under the adapter's credential name and records the
// owner's private-data answer, all inside the vault process. The list
// answers whether a key is held, never the key (CRED-1).
func TestSetupProvidersOverTheVerifySocket(t *testing.T) {
	r := providerRig(t)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/setup/providers", ""},
		{"POST", "/setup/providers/key", keyBody("openai", synthetic(t, "sk-canary-"))},
		{"POST", "/setup/providers/private", `{"provider":"openai","ok":true}`},
	} {
		if w := setupCall(t, r.c, c.method, c.path, c.body); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("locked %s: %d", c.path, w.Code)
		}
	}
	if r.c.privateAllowed("openai") {
		t.Fatal("locked vault allows private data")
	}
	r.c.confirm(r.unlock(t), r.code())

	ps := listed(t, setupCall(t, r.c, "GET", "/setup/providers", ""))
	if len(ps) != 2 || ps["openai"].Name != "OpenAI" || ps["anthropic"].Name != "Anthropic" ||
		ps["openai"].Connected || ps["openai"].PrivateOK {
		t.Fatalf("fresh list: %+v", ps)
	}

	key := synthetic(t, "sk-canary-")
	if w := setupCall(t, r.c, "POST", "/setup/providers/key", keyBody("openai", key)); w.Code != http.StatusOK {
		t.Fatalf("key: %d %s", w.Code, w.Body)
	}
	got, ok := r.c.v.Secret("openai")
	if !ok || got.Reveal() != key || !hasKind(r.c.v, "openai", vault.KindAPIKey) {
		t.Fatal("the key is not the vault's openai api_key entry")
	}
	if w := setupCall(t, r.c, "POST", "/setup/providers/private", `{"provider":"anthropic","ok":true}`); w.Code != http.StatusOK {
		t.Fatalf("private: %d %s", w.Code, w.Body)
	}
	w := setupCall(t, r.c, "GET", "/setup/providers", "")
	if strings.Contains(w.Body.String(), key) || strings.Contains(w.Body.String(), "canary") {
		t.Fatalf("the list carries the key: %s", w.Body)
	}
	ps = listed(t, w)
	if !ps["openai"].Connected || ps["openai"].PrivateOK || ps["anthropic"].Connected || !ps["anthropic"].PrivateOK {
		t.Fatalf("after: %+v", ps)
	}
	if !r.c.privateAllowed("anthropic") || r.c.privateAllowed("openai") {
		t.Fatal("privateAllowed does not follow the marks")
	}
	if w := setupCall(t, r.c, "POST", "/setup/providers/private", `{"provider":"anthropic","ok":false}`); w.Code != http.StatusOK {
		t.Fatalf("private off: %d", w.Code)
	}
	if listed(t, setupCall(t, r.c, "GET", "/setup/providers", ""))["anthropic"].PrivateOK || r.c.privateAllowed("anthropic") {
		t.Fatal("private answer not withdrawn")
	}

	// The answer is the vault's: locking it allows nothing private.
	setupCall(t, r.c, "POST", "/setup/providers/private", `{"provider":"anthropic","ok":true}`)
	r.c.lock()
	if r.c.privateAllowed("anthropic") {
		t.Fatal("locked vault allows private data")
	}
}

// Only a built-in adapter is accepted, never over an entry of another
// kind, and only a key the proxy could send: anything else is 400 and
// nothing is written. Wrong methods are 405.
func TestSetupProvidersRefuseWhatPutRefuses(t *testing.T) {
	r := providerRig(t)
	r.c.confirm(r.unlock(t), r.code())
	if err := r.c.v.Put("anthropic", vault.KindTOTPSeed, []byte(synthetic(t, "seed-"))); err != nil {
		t.Fatal(err)
	}
	before := len(r.c.v.List())
	for _, body := range []string{
		keyBody("anthropic", synthetic(t, "sk-canary-")),         // another kind holds the name
		keyBody(SeedName, synthetic(t, "sk-canary-")),            // not an adapter
		keyBody("", synthetic(t, "sk-canary-")),                  // no provider
		keyBody("openai", "short"),                               // shorter than the vault takes
		keyBody("openai", "sk-canary-\r\nX-Injected: 1"),         // not printable
		keyBody("openai", "sk-canary-"+strings.Repeat("a", 512)), // too long
		`not json`,
	} {
		if w := setupCall(t, r.c, "POST", "/setup/providers/key", body); w.Code != http.StatusBadRequest {
			t.Fatalf("key %.40q: %d", body, w.Code)
		}
	}
	for _, body := range []string{`{"provider":"other","ok":true}`, `{"provider":"","ok":true}`, `nope`} {
		if w := setupCall(t, r.c, "POST", "/setup/providers/private", body); w.Code != http.StatusBadRequest {
			t.Fatalf("private %q: %d", body, w.Code)
		}
	}
	if len(r.c.v.List()) != before || hasKind(r.c.v, "openai", vault.KindAPIKey) {
		t.Fatal("a refused request wrote to the vault")
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/setup/providers"}, {"GET", "/setup/providers/key"}, {"GET", "/setup/providers/private"},
	} {
		if w := setupCall(t, r.c, c.method, c.path, ""); w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: %d", c.method, c.path, w.Code)
		}
	}
}

// K17: setup's provider ops run only while setup's enrollment is open. A
// sealed vault answers 410 and one never opened for setup 412, as /enroll
// does, so a taken-over agentosd cannot replace a key or widen the
// private answer after setup.
func TestSetupProvidersCloseWithEnrollment(t *testing.T) {
	sealed := providerRig(t)
	sealed.c.confirm(sealed.unlock(t), sealed.code())
	if err := sealed.c.putMark(EnrolledName, KindEnrolled); err != nil {
		t.Fatal(err)
	}
	never := openRig(t)
	if err := never.c.v.Delete("openai"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		r    *fastRig
		want int
	}{{sealed, http.StatusGone}, {never, http.StatusPreconditionFailed}} {
		for _, q := range []struct{ method, path, body string }{
			{"GET", "/setup/providers", ""},
			{"POST", "/setup/providers/key", keyBody("openai", synthetic(t, "sk-canary-"))},
			{"POST", "/setup/providers/private", `{"provider":"openai","ok":true}`},
		} {
			if w := setupCall(t, c.r.c, q.method, q.path, q.body); w.Code != c.want {
				t.Fatalf("%s: %d, want %d", q.path, w.Code, c.want)
			}
		}
		if hasKind(c.r.c.v, "openai", vault.KindAPIKey) || c.r.c.privateAllowed("openai") {
			t.Fatal("a closed setup wrote to the vault")
		}
	}
}

// The verify socket serves the provider ops to modelroute.Verifier, and
// the router's private check follows the vault process's answer.
func TestSetupProvidersThroughTheVerifier(t *testing.T) {
	r := newSetupRig(t)
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, r.c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	v := modelroute.NewVerifier(filepath.Join(run, VerifySocket))
	if _, err := v.SetupProviders(); err != modelroute.ErrVaultLocked {
		t.Fatalf("locked: %v", err)
	}
	r.c.confirm(r.unlock(t), r.code())
	if err := v.SetupAPIKey("anthropic", synthetic(t, "sk-ant-canary-")); err != nil {
		t.Fatal(err)
	}
	if err := v.SetupAPIKey("nope", synthetic(t, "sk-canary-")); err != modelroute.ErrSetupRefused {
		t.Fatalf("unknown provider: %v", err)
	}
	if err := v.SetupPrivateOK("anthropic", true); err != nil {
		t.Fatal(err)
	}
	ps, err := v.SetupProviders()
	if err != nil || len(ps) != 2 {
		t.Fatalf("list: %v %v", ps, err)
	}
	for _, p := range ps {
		if (p.ID == "anthropic") != (p.Connected && p.PrivateOK) {
			t.Fatalf("%+v", p)
		}
	}
}

// main's router asks custody through privateHook: before custody exists,
// and while the vault holds no mark or is locked, a private call gets no
// route; with setup's mark it reaches the provider.
func TestTheRouterFollowsSetupsPrivateAnswer(t *testing.T) {
	var hook privateHook
	_, rt, err := modelRouting(route.Rule{"default": {{Provider: "openai", Model: "gpt-test"}}},
		grants{"agent": {"openai"}}, nil, hook.allowed, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	up := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "stub", http.StatusTeapot)
	})
	call := func() int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"default","messages":[{"role":"user","content":"hi"}]}`))
		rt.HandlerFor("agent", "private", up, nil).ServeHTTP(w, req)
		return w.Code
	}
	if code := call(); code != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("no custody: %d hits=%d", code, hits.Load())
	}
	r := providerRig(t)
	hook.c.Store(r.c)
	r.c.confirm(r.unlock(t), r.code())
	if code := call(); code != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("no mark: %d hits=%d", code, hits.Load())
	}
	if w := setupCall(t, r.c, "POST", "/setup/providers/private", `{"provider":"openai","ok":true}`); w.Code != http.StatusOK {
		t.Fatalf("private: %d", w.Code)
	}
	if call(); hits.Load() == 0 {
		t.Fatal("the marked provider got no call")
	}
	r.c.lock()
	n := hits.Load()
	if code := call(); code != http.StatusForbidden || hits.Load() != n {
		t.Fatalf("locked: %d", code)
	}
}
