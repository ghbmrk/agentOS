package plan_test

// REQ: CLK-1

import (
	"context"
	"net/http"
	"testing"
)

// The clerk's client follows no redirect (guarded): a provider's 302 is
// answered as it came, and the location it names is never asked.
func TestPlanProviderRedirectIsNotFollowed(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	f.usercode = func(w http.ResponseWriter) bool {
		w.Header().Set("Location", "/api/accounts/deviceauth/elsewhere")
		w.WriteHeader(http.StatusFound)
		return true
	}
	before := f.hits()
	p.Do(context.Background(), "s", jsonReq("/api/accounts/deviceauth/usercode", `{"client_id":"app_x"}`), nil)
	if n := f.hits() - before; n != 1 {
		t.Fatalf("the provider was asked %d times for one call: the redirect was followed", n)
	}
	if last, _ := f.last(); last.URL.Path != "/api/accounts/deviceauth/usercode" {
		t.Fatalf("the clerk asked %s", last.URL.Path)
	}
}
