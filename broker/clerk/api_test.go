package clerk_test

// REQ: CLK-1, CLK-3, CLK-4

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// apiFix is an API clerk over a test server under example.com, its static
// secret the canary.
type apiFix struct {
	srv   *httptest.Server
	got   *http.Request
	body  string
	roots *x509.CertPool
	sec   *clerk.Secrets
}

func newAPIFix(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *apiFix {
	t.Helper()
	f := &apiFix{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.got, f.body = r.Clone(context.Background()), string(b)
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.srv.Certificate())
	f.sec = clerk.NewSecrets(sealer(t), nil)
	if err := f.sec.Put("api", clerk.KindStatic, []byte(canary)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *apiFix) base() string {
	return "https://example.com:" + f.srv.URL[strings.LastIndex(f.srv.URL, ":")+1:]
}

func (f *apiFix) guard() *netguard.Policy {
	return (&exitFix{srv: f.srv}).guard(netip.MustParseAddr("8.8.8.8"))
}

func (f *apiFix) api(t *testing.T, calls ...clerk.Call) *clerk.API {
	t.Helper()
	a, err := clerk.NewAPI(clerk.APIDeclaration{Name: "api", Calls: calls, Guard: f.guard()}, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *apiFix) label() clerk.Call {
	return clerk.Call{Name: "label", Args: []string{"id", "label"}, Max: 1 << 10, Lists: []string{"add"},
		Op: clerk.Op{Method: "POST", URL: f.base() + "/m/{id}/modify?fixed=1", Slot: "api", Prefix: "Bearer ",
			Type: clerk.TypeJSON, Body: map[string]string{"add": "label"}}}
}

// A call sends its one declared shape with each value in its one place, the
// secret added by the clerk, and returns the answer with the secret redacted.
func TestAPICallSendsTheDeclaredShapeAndRedactsTheSecret(t *testing.T) {
	f := newAPIFix(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"echo":"` + r.Header.Get("Authorization") + `"}`))
	})
	a := f.api(t, f.label())
	ans, bad := a.Call(context.Background(), "label", map[string]string{"id": "m1", "label": `x","remove":["UNREAD"]`})
	if bad != "" || ans.Status != 200 {
		t.Fatalf("Call = %+v %q", ans, bad)
	}
	if f.got.URL.Path != "/m/m1/modify" || f.got.URL.RawQuery != "fixed=1" || f.got.Header.Get("Authorization") != "Bearer "+canary {
		t.Fatalf("sent %s %s %q", f.got.URL.Path, f.got.URL.RawQuery, f.got.Header.Get("Authorization"))
	}
	if f.body != `{"add":["x\",\"remove\":[\"UNREAD\"]"]}` {
		t.Fatalf("body %s: a value escaped its field", f.body)
	}
	if strings.Contains(string(ans.Body), canary) || !strings.Contains(string(ans.Body), "[redacted]") {
		t.Fatalf("the answer carries the secret: %s", ans.Body)
	}
}

// Nothing is sent for a call not declared, for arguments that are not
// exactly the declared ones, or for a value that would add a path segment.
func TestAPIRefusesWhatIsNotDeclared(t *testing.T) {
	hits := 0
	f := newAPIFix(t, func(w http.ResponseWriter, r *http.Request) { hits++ })
	a := f.api(t, f.label())
	ctx := context.Background()
	for name, c := range map[string]struct {
		call string
		args map[string]string
		want string
	}{
		"undeclared": {"delete", map[string]string{"id": "m1"}, clerk.DUndeclared},
		"missing":    {"label", map[string]string{"id": "m1"}, clerk.DArg},
		"extra":      {"label", map[string]string{"id": "m1", "label": "x", "q": "y"}, clerk.DArg},
		"renamed":    {"label", map[string]string{"id": "m1", "name": "x"}, clerk.DArg + " label"},
		"segment":    {"label", map[string]string{"id": "../delete", "label": "x"}, clerk.DArg + " id"},
	} {
		if _, bad := a.Call(ctx, c.call, c.args); bad != c.want {
			t.Errorf("%s: detail %q, want %q", name, bad, c.want)
		}
	}
	if hits != 0 {
		t.Fatalf("%d requests reached the server", hits)
	}
}

// An answer longer than the call's bound is not kept.
func TestAPIBoundsTheAnswer(t *testing.T) {
	f := newAPIFix(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", 2<<10))) })
	a := f.api(t, f.label())
	if ans, bad := a.Call(context.Background(), "label", map[string]string{"id": "m1", "label": "x"}); bad != clerk.DTooLarge || ans.Body != nil {
		t.Fatalf("Call = %d bytes, %q; want toolarge", len(ans.Body), bad)
	}
}

// A declaration that is a step's, unbounded, lists a field that is not a
// JSON body field, or holds another account's secret is refused.
func TestAPIDeclarationRefusals(t *testing.T) {
	f := newAPIFix(t, func(http.ResponseWriter, *http.Request) {})
	bad := map[string]func(c *clerk.Call){
		"a verb":         func(c *clerk.Call) { c.Verb = key.Post },
		"unbounded":      func(c *clerk.Call) { c.Max = 0 },
		"no name":        func(c *clerk.Call) { c.Name = "" },
		"list not body":  func(c *clerk.Call) { c.Lists = []string{"other"} },
		"list in a form": func(c *clerk.Call) { c.Type = clerk.TypeForm },
		"unknown arg":    func(c *clerk.Call) { c.Args = []string{"id"} },
	}
	for name, mod := range bad {
		c := f.label()
		mod(&c)
		if _, err := clerk.NewAPI(clerk.APIDeclaration{Name: "api", Calls: []clerk.Call{c}, Guard: f.guard()}, f.sec, f.roots); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := clerk.NewAPI(clerk.APIDeclaration{Name: "api", Calls: []clerk.Call{f.label(), f.label()}, Guard: f.guard()}, f.sec, f.roots); err == nil {
		t.Error("a call declared twice was accepted")
	}
	two := clerk.NewSecrets(sealer(t), nil)
	_ = two.Put("api", clerk.KindStatic, []byte(canary))
	_ = two.Put("bank", clerk.KindStatic, []byte("canary-bank"))
	if _, err := clerk.NewAPI(clerk.APIDeclaration{Name: "api", Calls: []clerk.Call{f.label()}, Guard: f.guard()}, two, f.roots); err == nil {
		t.Error("an API holding another account's secret was accepted (CLK-1)")
	}
}

// Every dial goes through the guard: an address it refuses sends nothing.
func TestAPIDialsOnlyThroughTheGuard(t *testing.T) {
	hits := 0
	f := newAPIFix(t, func(w http.ResponseWriter, r *http.Request) { hits++ })
	a, err := clerk.NewAPI(clerk.APIDeclaration{Name: "api", Calls: []clerk.Call{f.label()},
		Guard: (&exitFix{srv: f.srv}).guard(netip.MustParseAddr("192.168.1.10"))}, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, bad := a.Call(context.Background(), "label", map[string]string{"id": "m1", "label": "x"}); bad != clerk.DBlocked || hits != 0 {
		t.Fatalf("detail %q with %d hits, want blocked and none", bad, hits)
	}
}
