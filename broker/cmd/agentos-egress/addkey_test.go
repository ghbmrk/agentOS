package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-1, CRED-5, ONB-3, CH-10 (brief CRED-5f-mr-addkey-1 and -4)

func keyReq(provider, key, code string) map[string]any {
	return map[string]any{"provider": provider, "key": key, "code": code}
}

func keyValue(r *fastRig, name string) string {
	s, _ := r.c.v.Secret(name)
	return s.Reveal()
}

// CRED-5f-mr-addkey-1: past setup the owner adds a provider's key on the
// unlock socket. The provider is asked first: a key it refuses, or gives
// no answer about, stores nothing and burns no code; an accepted key is
// stored under the adapter's credential, grants the provider (K24), is
// told to the owner and is never in an answer or a note.
func TestAddKeyRouteStoresThroughTheVault(t *testing.T) {
	r := newFastRig(t, true)
	call := handlerCall(t, r.c)
	key := synthetic(t, "sk-canary-")
	if st, _ := call("POST", "/providers/key", keyReq("anthropic", key, r.code())); st != http.StatusConflict {
		t.Fatalf("locked: %d", st)
	}
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	stored := func() bool { return hasKind(r.c.v, "anthropic", vault.KindAPIKey) }

	for _, c := range []struct {
		rt   http.RoundTripper
		want int
	}{
		{providerAnswers(http.StatusUnauthorized), http.StatusForbidden},
		{providerAnswers(http.StatusInternalServerError), http.StatusBadGateway},
		{keyCheckRT(func(*http.Request) (*http.Response, error) { return nil, errors.New("no route") }), http.StatusBadGateway},
	} {
		r.c.keyCheck = c.rt
		code := r.next()
		st, out := call("POST", "/providers/key", keyReq("anthropic", key, code))
		if st != c.want || stored() || strings.Contains(out["error"].(string), key) {
			t.Fatalf("want %d: got %d %v, stored %v", c.want, st, out, stored())
		}
	}

	var asked int
	r.c.keyCheck = keyCheckRT(func(req *http.Request) (*http.Response, error) {
		asked++
		if stored() {
			t.Error("the key was stored before the provider answered")
		}
		return providerAnswers(http.StatusOK)(req)
	})
	if st, out := call("POST", "/providers/key", keyReq("nobody", key, r.next())); st != http.StatusBadRequest || asked != 0 {
		t.Fatalf("unknown provider: %d %v, asked %d", st, out, asked)
	}
	st, out := call("POST", "/providers/key", keyReq("anthropic", key, r.next()))
	if st != http.StatusNoContent || asked != 1 || !stored() || keyValue(r, "anthropic") != key {
		t.Fatalf("add: %d %v, asked %d", st, out, asked)
	}
	if !hasNote(r.notes, "AI key added for Anthropic") {
		t.Fatalf("the owner was not told: %v", r.notes)
	}
	for _, n := range r.notes {
		if strings.Contains(n, key) {
			t.Fatalf("a note carries the key: %q", n)
		}
	}
	if p := listedProviders(t, r)["anthropic"]; !p.Connected {
		t.Fatalf("anthropic not connected after the add: %+v", p)
	}
}

// CRED-5f-mr-addkey-4: any add or replace needs the one-time code, for a
// provider that had no key and for one that had. No code, a wrong code and
// a used code store nothing, and a request with no code never reaches the
// provider.
func TestAddKeyNeedsTheOneTimeCode(t *testing.T) {
	r := newFastRig(t, true)
	call := handlerCall(t, r.c)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	var asked int
	r.c.keyCheck = keyCheckRT(func(req *http.Request) (*http.Response, error) {
		asked++
		return providerAnswers(http.StatusOK)(req)
	})
	old := keyValue(r, "openai")
	for i, p := range []string{"anthropic", "openai"} { // new provider; replacement
		key := synthetic(t, "sk-canary-")
		before := asked
		if st, out := call("POST", "/providers/key", keyReq(p, key, "")); st != http.StatusForbidden || asked != before {
			t.Fatalf("%s no code: %d %v, asked %d", p, st, out, asked-before)
		}
		// Wrong codes count toward a lockout, so one provider tries one.
		if i == 0 {
			st, out := call("POST", "/providers/key", keyReq(p, key, "000000"))
			if st != http.StatusForbidden || !strings.HasPrefix(out["error"].(string), "wrong code") {
				t.Fatalf("%s wrong code: %d %v", p, st, out)
			}
		}
		if i == 0 && hasKind(r.c.v, "anthropic", vault.KindAPIKey) || keyValue(r, "openai") != old && i == 1 {
			t.Fatalf("%s stored without a code", p)
		}
		code := r.next()
		if st, out := call("POST", "/providers/key", keyReq(p, key, code)); st != http.StatusNoContent {
			t.Fatalf("%s add: %d %v", p, st, out)
		}
		if keyValue(r, p) != key {
			t.Fatalf("%s not stored", p)
		}
		if i == 1 {
			if st, _ := call("POST", "/providers/key", keyReq(p, synthetic(t, "sk-canary-"), code)); st == http.StatusNoContent {
				t.Fatalf("%s a used code was taken again", p)
			}
		}
	}
	if !hasNote(r.notes, "wrong code for adding an AI key") {
		t.Fatalf("a wrong code was not told: %v", r.notes)
	}
}

// Security on #2519: past setup addKey is the one path that writes an
// adapter's key. /credential (put) is sealed once setup is done, so it
// neither adds nor replaces a key without the code; a malformed code, or
// any code during a lockout, never reaches the provider.
func TestAddKeyIsTheOnlyPathPastSetup(t *testing.T) {
	r := newFastRig(t, true)
	call := handlerCall(t, r.c)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	old := keyValue(r, "openai")
	for _, p := range []string{"anthropic", "openai"} {
		v := synthetic(t, "sk-canary-")
		if st, _ := call("POST", "/credential", map[string]any{"name": p, "value": v}); st != http.StatusGone {
			t.Fatalf("/credential %s past setup: %d", p, st)
		}
	}
	if hasKind(r.c.v, "anthropic", vault.KindAPIKey) || keyValue(r, "openai") != old {
		t.Fatal("/credential wrote a key past setup")
	}

	var asked int
	r.c.keyCheck = keyCheckRT(func(req *http.Request) (*http.Response, error) {
		asked++
		return providerAnswers(http.StatusOK)(req)
	})
	key := synthetic(t, "sk-canary-")
	for _, bad := range []string{"x", "12345", "1234567", "12345a", "１２３４５６"} {
		if st, _ := call("POST", "/providers/key", keyReq("anthropic", key, bad)); st != http.StatusForbidden || asked != 0 {
			t.Fatalf("code %q: %d, asked %d", bad, st, asked)
		}
	}
	for i := 0; i < MaxWrongCodes; i++ {
		call("POST", "/providers/key", keyReq("anthropic", key, "000000"))
	}
	asked = 0
	if st, _ := call("POST", "/providers/key", keyReq("anthropic", key, r.next())); st != http.StatusTooManyRequests || asked != 0 {
		t.Fatalf("locked out: %d, asked %d", st, asked)
	}
}

func listedProviders(t *testing.T, r *fastRig) map[string]modelroute.SetupProvider {
	t.Helper()
	w := httptest.NewRecorder()
	unlockHandler(r.c).ServeHTTP(w, httptest.NewRequest("GET", "/providers", nil))
	return listed(t, w)
}

// A key the provider refuses burns no code: the same code then adds a good key.
func TestAddKeyRefusedByProviderBurnsNoCode(t *testing.T) {
	r := newFastRig(t, true)
	call := handlerCall(t, r.c)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	stored := func() bool { return hasKind(r.c.v, "anthropic", vault.KindAPIKey) }
	code := r.next()
	r.c.keyCheck = providerAnswers(http.StatusUnauthorized)
	if st, out := call("POST", "/providers/key", keyReq("anthropic", "sk-canary-refused-0001", code)); st != http.StatusForbidden || stored() {
		t.Fatalf("refused key: %d %v", st, out)
	}
	r.c.keyCheck = providerAnswers(http.StatusOK)
	if st, out := call("POST", "/providers/key", keyReq("anthropic", "sk-canary-good-0002", code)); st != http.StatusNoContent || !stored() {
		t.Fatalf("same code, good key: %d %v", st, out)
	}
}
