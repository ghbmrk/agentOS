package localui

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/pageca"
)

// REQ: CH-9

var testBuilt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// fakeCertifier is agentosd's OpCertify over a real authority.
type fakeCertifier struct {
	mu   sync.Mutex
	a    *pageca.Authority
	code string // a refusal to answer with
	fail bool
	pubs [][]byte
}

func (f *fakeCertifier) Call(_ context.Context, op string, args, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if op != localapi.OpCertify {
		return Refused(localapi.ErrBadArgs)
	}
	if f.code != "" {
		return Refused(f.code)
	}
	if f.fail {
		return errors.New("socket closed")
	}
	pub := args.(localapi.CertifyArgs).Pub
	f.pubs = append(f.pubs, pub)
	leaf, err := f.a.Issue(pub, testBuilt.Add(time.Hour), nil)
	if err != nil {
		return Refused(localapi.ErrBadArgs)
	}
	b, _ := json.Marshal(localapi.Certified{Leaf: leaf, Authority: f.a.Certificate()})
	return json.Unmarshal(b, out)
}

func newCertifier(t *testing.T) *fakeCertifier {
	t.Helper()
	a, err := pageca.New(DefaultPageName, testBuilt, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeCertifier{a: a}
}

// ticker drives PageTLS.Run: each wait is reported, each tick released.
type ticker struct {
	waits chan time.Duration
	ticks chan time.Time
}

func newTicker(p *PageTLS) *ticker {
	k := &ticker{waits: make(chan time.Duration), ticks: make(chan time.Time)}
	p.after = func(d time.Duration) <-chan time.Time { k.waits <- d; return k.ticks }
	return k
}

func TestRenewsDailyWithAFreshKey(t *testing.T) {
	f := newCertifier(t)
	p, err := NewPageTLS(context.Background(), DefaultPageName, f, nil, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	k := newTicker(p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	first := p.Leaf()
	for i := 0; i < 3; i++ {
		if d := <-k.waits; d != RenewEvery {
			t.Fatalf("wait %v", d)
		}
		k.ticks <- time.Time{}
	}
	<-k.waits
	if len(f.pubs) != 4 {
		t.Fatalf("%d certifications", len(f.pubs))
	}
	seen := map[string]bool{}
	for _, pub := range f.pubs {
		if seen[string(pub)] {
			t.Fatal("a serving key was reused")
		}
		seen[string(pub)] = true
	}
	if p.Leaf().Equal(first) {
		t.Error("the served certificate did not change")
	}
	got, _ := x509.MarshalPKIXPublicKey(p.Leaf().PublicKey)
	if string(got) != string(f.pubs[3]) {
		t.Error("serving a leaf for an older key")
	}
}

func TestFailedRenewalKeepsServing(t *testing.T) {
	f := newCertifier(t)
	var mu sync.Mutex
	var logged []string
	p, err := NewPageTLS(context.Background(), DefaultPageName, f, nil, func(s string) { mu.Lock(); logged = append(logged, s); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	k := newTicker(p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	before := p.Leaf()
	<-k.waits
	f.mu.Lock()
	f.fail = true
	f.mu.Unlock()
	k.ticks <- time.Time{}
	if d := <-k.waits; d != RetryEvery {
		t.Fatalf("after a failure, wait %v", d)
	}
	if !p.Leaf().Equal(before) {
		t.Fatal("a failed renewal changed the certificate")
	}
	cfg := p.Config()
	if c, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: DefaultPageName}); err != nil || c == nil {
		t.Fatalf("not serving after a failed renewal: %v", err)
	}
	mu.Lock()
	if len(logged) != 1 || logged[0] != LogRenewFailed {
		t.Errorf("logged %q", logged)
	}
	mu.Unlock()
	f.mu.Lock()
	f.fail = false
	f.mu.Unlock()
	k.ticks <- time.Time{}
	if d := <-k.waits; d != RenewEvery {
		t.Fatalf("after recovery, wait %v", d)
	}
	if p.Leaf().Equal(before) {
		t.Error("recovered renewal not swapped in")
	}
	// No authority at all: no HTTPS, told apart from a restore.
	for code, want := range map[string]error{localapi.ErrNoAuthority: ErrNoAuthority, localapi.ErrRestore: ErrRestore} {
		if _, err := NewPageTLS(context.Background(), DefaultPageName, &fakeCertifier{code: code}, nil, nil); err != want {
			t.Errorf("%s: %v", code, err)
		}
	}
	// A leaf for another name is refused, as is one for another key.
	other, _ := pageca.New("other.internal", testBuilt, nil)
	if _, err := NewPageTLS(context.Background(), DefaultPageName, &fakeCertifier{a: other}, nil, nil); err == nil {
		t.Error("took a leaf for another name")
	}
}

// handshake runs a TLS 1.3 handshake against the page's config.
func handshake(t *testing.T, p *PageTLS, sni string, roots *x509.CertPool) error {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go tls.Server(s, p.Config()).Handshake()
	cc := tls.Client(c, &tls.Config{ServerName: sni, RootCAs: roots, MinVersion: tls.VersionTLS13,
		Time: func() time.Time { return testBuilt.Add(2 * time.Hour) }, InsecureSkipVerify: sni == ""})
	c.SetDeadline(time.Now().Add(5 * time.Second))
	return cc.Handshake()
}

// tlsReq makes r an HTTPS request for host with SNI the page name.
func tlsReq(host string) func(*http.Request) {
	return func(r *http.Request) {
		r.Host = host
		r.URL.Scheme, r.URL.Host = "https", host
		r.TLS = &tls.ConnectionState{ServerName: DefaultPageName, Version: tls.VersionTLS13}
	}
}

func TestHTTPSRefusesOtherSNIAndHost(t *testing.T) {
	f := newCertifier(t)
	p, err := NewPageTLS(context.Background(), DefaultPageName, f, nil, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	ca, _ := x509.ParseCertificate(f.a.Certificate())
	roots.AddCert(ca)
	if err := handshake(t, p, DefaultPageName, roots); err != nil {
		t.Fatalf("the page name: %v", err)
	}
	for _, sni := range []string{"", "evil.example", "x." + DefaultPageName} {
		if err := handshake(t, p, sni, roots); err == nil {
			t.Errorf("SNI %q got a handshake", sni)
		}
	}
	if cfg := p.Config(); cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Error("not TLS 1.3 only")
	}
	r := newRig(t)
	for _, host := range []string{"evil.example", "10.42.0.1", "x." + DefaultPageName, DefaultPageName + ":80", ""} {
		w := r.do("GET", "/status", nil, tlsReq(host))
		if w.Code != http.StatusMisdirectedRequest || w.Header().Get("Location") != "" {
			t.Errorf("Host %q over HTTPS: %d %q", host, w.Code, w.Header().Get("Location"))
		}
	}
	for _, host := range []string{DefaultPageName, DefaultPageName + ":443"} {
		if w := r.do("GET", "/status", nil, tlsReq(host)); w.Code != http.StatusOK {
			t.Errorf("Host %q over HTTPS: %d", host, w.Code)
		}
	}
	// The source check still applies first.
	r.ip = "192.168.1.5:5000"
	if w := r.do("GET", "/status", nil, tlsReq(DefaultPageName)); w.Code != http.StatusForbidden {
		t.Errorf("off the access point: %d", w.Code)
	}
}

func TestHTTPSCookiesAreHostPrefixed(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	carrier := modem.NewCarrier()
	r.startChannel(carrier.Line(boxNum))
	https := tlsReq(DefaultPageName)
	origin := func(q *http.Request) { q.Header.Set("Origin", "https://"+DefaultPageName) }
	w := r.do("POST", "/unlock", url.Values{"code": {r.code()}, "next": {"/home"}}, https, origin)
	if w.Header().Get("Location") != "/home" {
		t.Fatalf("sign-in over HTTPS: %d %s", w.Code, w.Body.String())
	}
	cs := w.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("cookies %v", cs)
	}
	c := cs[0]
	if c.Name != "__Host-"+cookieName || !c.Secure || c.Path != "/" || c.Domain != "" || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie %+v", c)
	}
	home := func(cookie *http.Cookie, mod func(*http.Request)) int {
		return r.do("GET", "/home", nil, mod, func(q *http.Request) { q.Header.Del("Cookie"); q.AddCookie(cookie) }).Code
	}
	if code := home(c, https); code != http.StatusOK {
		t.Errorf("the __Host- cookie over HTTPS: %d", code)
	}
	plain := &http.Cookie{Name: cookieName, Value: c.Value}
	if code := home(plain, https); code == http.StatusOK {
		t.Error("an unprefixed cookie signed in over HTTPS")
	}
	if code := home(c, func(*http.Request) {}); code == http.StatusOK {
		t.Error("the __Host- cookie signed in over HTTP")
	}
	// The setup and claim cookies take the same form (one helper).
	rec := httptest.NewRecorder()
	q := httptest.NewRequest("GET", "https://"+DefaultPageName+"/setup", nil)
	q.TLS = &tls.ConnectionState{ServerName: DefaultPageName}
	setCookie(rec, q, &http.Cookie{Name: setupCookie, Value: "v", Path: "/setup", Domain: "agentos.internal"})
	if sc := rec.Result().Cookies()[0]; sc.Name != "__Host-"+setupCookie || sc.Path != "/" || sc.Domain != "" || !sc.Secure {
		t.Errorf("setup cookie %+v", sc)
	}
}

func TestHTTPSOriginIsTheName(t *testing.T) {
	r := newRig(t)
	https := tlsReq(DefaultPageName)
	for _, o := range []string{"http://10.42.0.1", "http://" + DefaultPageName, "https://x." + DefaultPageName, "https://evil.example", "null"} {
		w := r.do("POST", "/stop", url.Values{}, https, func(q *http.Request) { q.Header.Set("Origin", o) })
		if w.Code != http.StatusForbidden {
			t.Errorf("Origin %q over HTTPS: %d", o, w.Code)
		}
	}
	w := r.do("POST", "/stop", url.Values{}, https, func(q *http.Request) { q.Header.Set("Origin", "https://"+DefaultPageName) })
	if w.Code == http.StatusForbidden {
		t.Errorf("the page's own origin refused")
	}
	// Over HTTP the box's address stays its origin (L6 unchanged).
	if w := r.do("POST", "/stop", url.Values{}, func(q *http.Request) { q.Header.Set("Origin", "https://"+DefaultPageName) }); w.Code != http.StatusForbidden {
		t.Errorf("the HTTPS origin accepted over HTTP: %d", w.Code)
	}
}

func TestHTTPSSetsHSTSAndNoReferrer(t *testing.T) {
	r := newRig(t)
	w := r.do("GET", "/status", nil, tlsReq(DefaultPageName))
	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=63072000" {
		t.Errorf("HSTS %q", got)
	}
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy %q", got)
	}
	if w := r.do("GET", "/status", nil); w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS over plain HTTP")
	}
}

func TestHTTPSCSPAdmitsOnlyHashedScript(t *testing.T) {
	r := newRig(t)
	csp := r.do("GET", "/status", nil, tlsReq(DefaultPageName)).Header().Get("Content-Security-Policy")
	if csp != pageCSP || strings.Contains(csp, "script-src") {
		t.Errorf("HTTPS CSP %q", csp)
	}
	for _, want := range []string{"default-src 'none'", "form-action 'self'", "base-uri 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q", want)
		}
	}
	if got := cspWith("abc=", "def="); got != pageCSP+"; script-src 'sha256-abc=' 'sha256-def='" {
		t.Errorf("cspWith %q", got)
	}
	if cspWith() != pageCSP {
		t.Error("cspWith() admits a script")
	}
	h := sha256.Sum256([]byte(shrinkJS))
	if vaultCSP != cspWith(base64.StdEncoding.EncodeToString(h[:])) {
		t.Error("the vault page's CSP is not built by cspWith")
	}
}

func TestHTTPRedirectsThePageNameToHTTPS(t *testing.T) {
	for _, up := range []bool{true, false} {
		s, err := New(Config{AP: testAP(), HTTPS: up, PageRestore: !up})
		if err != nil {
			t.Fatal(err)
		}
		do := func(method, host, path string) *httptest.ResponseRecorder {
			q := httptest.NewRequest(method, "http://"+host+path, nil)
			q.RemoteAddr = phoneIP
			w := httptest.NewRecorder()
			s.ServeHTTP(w, q)
			return w
		}
		w := do("GET", DefaultPageName, "/status")
		if up {
			if w.Code != http.StatusFound || w.Header().Get("Location") != "https://"+DefaultPageName+"/status" {
				t.Errorf("HTTPS up: %d %q", w.Code, w.Header().Get("Location"))
			}
			if w := do("POST", DefaultPageName, "/stop"); w.Code != http.StatusForbidden {
				t.Errorf("HTTPS up, POST: %d", w.Code)
			}
		} else {
			// No authority: the page name is served on port 80, with the
			// restore text when agentosd asked for it.
			if w.Code != http.StatusOK || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "Restore me from my backup") {
				t.Errorf("HTTPS down: %d %q", w.Code, w.Header().Get("Location"))
			}
		}
		// The box's address and the captive answers are as before (L6).
		if w := do("GET", "10.42.0.1", "/status"); w.Code != http.StatusOK {
			t.Errorf("the box's address: %d", w.Code)
		}
		if w := do("GET", "captive.apple.com", "/hotspot-detect.html"); w.Code != http.StatusFound || w.Header().Get("Location") != "http://10.42.0.1/" {
			t.Errorf("captive check: %d %q", w.Code, w.Header().Get("Location"))
		}
	}
}
