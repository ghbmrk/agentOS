package clerk_test

// REQ: CLK-1, CLK-3, CLK-9

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
)

func signInDecl(f *apiFix) clerk.SignInDeclaration {
	return clerk.SignInDeclaration{Name: "acct", Auth: f.base() + "/auth", Token: f.base() + "/token", Revoke: f.base() + "/revoke",
		Redirect: "http://127.0.0.1:8521/cb", Uses: map[string]string{"read": "scope.read"}, Slot: "grant", Guard: f.guard()}
}

// A sign-in declaration is checked when it is built: https endpoints, a
// plain loopback redirect (RFC 8252 section 7.3), one scope per use, no
// parameter that replaces the clerk's own, and a store holding no other
// account's secret (CLK-1).
func TestNewSignInRefusesUnsafeDeclarations(t *testing.T) {
	f := newAPIFix(t, func(http.ResponseWriter, *http.Request) {})
	empty := clerk.NewSecrets(sealer(t), nil)
	if _, err := clerk.NewSignIn(signInDecl(f), empty, f.roots); err != nil {
		t.Fatalf("a good declaration: %v", err)
	}
	for name, mod := range map[string]func(*clerk.SignInDeclaration){
		"http auth":        func(d *clerk.SignInDeclaration) { d.Auth = "http://example.com/auth" },
		"query token":      func(d *clerk.SignInDeclaration) { d.Token += "?x=1" },
		"http revoke":      func(d *clerk.SignInDeclaration) { d.Revoke = "http://example.com/revoke" },
		"no auth":          func(d *clerk.SignInDeclaration) { d.Auth, d.Revoke = "", "" },
		"no token":         func(d *clerk.SignInDeclaration) { d.Token, d.Revoke = "", "" },
		"remote redirect":  func(d *clerk.SignInDeclaration) { d.Redirect = "http://example.com:8521/cb" },
		"https redirect":   func(d *clerk.SignInDeclaration) { d.Redirect = "https://127.0.0.1:8521/cb" },
		"no port":          func(d *clerk.SignInDeclaration) { d.Redirect = "http://127.0.0.1/cb" },
		"redirect query":   func(d *clerk.SignInDeclaration) { d.Redirect += "?a=1" },
		"two scopes":       func(d *clerk.SignInDeclaration) { d.Uses = map[string]string{"read": "a b"} },
		"no uses":          func(d *clerk.SignInDeclaration) { d.Uses = nil },
		"no slot":          func(d *clerk.SignInDeclaration) { d.Slot = "" },
		"no guard":         func(d *clerk.SignInDeclaration) { d.Guard = nil },
		"replaces scope":   func(d *clerk.SignInDeclaration) { d.Params = map[string]string{"scope": "all"} },
		"replaces challen": func(d *clerk.SignInDeclaration) { d.Params = map[string]string{"code_challenge_method": "plain"} },
	} {
		d := signInDecl(f)
		mod(&d)
		if _, err := clerk.NewSignIn(d, empty, f.roots); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := clerk.NewSignIn(signInDecl(f), f.sec, f.roots); err == nil {
		t.Error("a store holding another account's slot was accepted")
	}
}

// The clerks' TLS uses the hybrid post-quantum key exchange, X25519MLKEM768,
// with a server that offers it: an API call and a sign-in's code exchange
// both negotiate it (otherwise folded into #2571).
func TestClerkTLSUsesTheHybridKeyExchange(t *testing.T) {
	var curves []tls.CurveID
	f := newAPIFix(t, func(w http.ResponseWriter, r *http.Request) {
		curves = append(curves, r.TLS.CurveID)
		w.Write([]byte(`{}`))
	})
	a := f.api(t, f.label())
	if _, bad := a.Call(context.Background(), "label", map[string]string{"id": "m1", "label": "x"}); bad != "" {
		t.Fatal(bad)
	}
	in, err := clerk.NewSignIn(signInDecl(f), clerk.NewSecrets(sealer(t), nil), f.roots)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := in.Begin("read", &clerk.Registration{ID: "client", Secret: "canary-client-secret"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(addr)
	in.Finish(context.Background(), "read", "http://127.0.0.1:8521/cb?code=c&state="+u.Query().Get("state"))
	if len(curves) != 2 || curves[0] != tls.X25519MLKEM768 || curves[1] != tls.X25519MLKEM768 {
		t.Fatalf("negotiated %v, want X25519MLKEM768 for the call and the exchange", curves)
	}
}

// A sign-in waits 15 minutes for its paste on the clerk's own clock; a
// revoke the provider refuses keeps the grant, so the owner can try again.
func TestSignInRunsOutAndAKeptGrantStays(t *testing.T) {
	status := 503
	f := newAPIFix(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/revoke" {
			w.WriteHeader(status)
		}
	})
	var now int64 = 1_000_000
	d := signInDecl(f)
	d.Clock = func() int64 { return now }
	sec := clerk.NewSecrets(sealer(t), nil)
	in, err := clerk.NewSignIn(d, sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := in.Begin("read", &clerk.Registration{ID: "client", Secret: "canary-client-secret"})
	u, _ := url.Parse(addr)
	now += 15*60*1000 + 1
	if got := in.Finish(context.Background(), "read", "http://127.0.0.1:8521/cb?code=c&state="+u.Query().Get("state")); got != clerk.DNoSignIn {
		t.Fatalf("a late paste = %q", got)
	}
	_ = sec.Put("grant", clerk.KindGrant, []byte(`{"refresh_token":"canary-refresh","client_id":"client","client_secret":"s"}`))
	if got := in.Revoke(context.Background()); got != clerk.DNoRevoke+" http 503" || !sec.Has("grant") {
		t.Fatalf("refused revoke = %q, kept %v", got, sec.Has("grant"))
	}
	status = 400 // the provider no longer knows the grant: it is dead already
	if got := in.Revoke(context.Background()); got != clerk.DRevoked || sec.Has("grant") {
		t.Fatalf("revoke of a dead grant = %q", got)
	}
}
