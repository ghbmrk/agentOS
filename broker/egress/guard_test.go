package egress

// REQ: DEV-2, REV-5, ARC-6, CAP-2, CAP-13, EGRESS-NOPROXY-1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vault"
)

type stubResolver struct{ ans string }

func (s *stubResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr(s.ans)}, nil
}

func guardedProxy(t *testing.T, adapters []Adapter, g *netguard.Policy, audit *auditLog) *Proxy {
	t.Helper()
	kb := make([]byte, vault.KeySize)
	rand.Read(kb)
	v, err := vault.Create(filepath.Join(t.TempDir(), "vault"), kb)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	if err := v.Put("k", vault.KindAPIKey, []byte(synthetic(t, "sk-canary-"))); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range adapters {
		names = append(names, a.Name)
	}
	p, err := New(Config{Adapters: adapters, Grants: map[string][]string{"m1": names}, Vault: v, Guard: g, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func serveOne(p *Proxy, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	p.Handler("m1").ServeHTTP(w, req)
	return w
}

// Acceptance 3: a redirect through the proxy to a private address is never
// followed or forwarded.
func TestRedirectToPrivateAddressNotFollowed(t *testing.T) {
	r := newRig(t, nil)
	r.provider.reply = func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "http://192.168.1.1/admin", http.StatusFound)
	}
	w := r.do(t, "m1", chat("/openai/v1/chat/completions"))
	if r.provider.count() != 1 {
		t.Fatalf("the provider saw %d requests; the redirect must not be followed", r.provider.count())
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("Location reached the guest: %q", loc)
	}
}

// Acceptance 3: CONNECT is denied and journaled, whatever it names.
func TestConnectToPrivateAddressDenied(t *testing.T) {
	r := newRig(t, nil)
	for _, target := range []string{"192.168.1.1:443", "10.0.0.1:22", "127.0.0.1:8080", "api.openai.com:443"} {
		req := httptest.NewRequest("CONNECT", "http://"+target, nil)
		req.RequestURI = target
		w := r.do(t, "m1", req)
		if w.Code != http.StatusForbidden || w.Header().Get(DeniedHeader) == "" {
			t.Fatalf("CONNECT %s: status %d", target, w.Code)
		}
		ev := r.audit.last(t)
		if ev.Allowed || ev.Method != "CONNECT" || !strings.Contains(ev.Reason, "CONNECT") {
			t.Fatalf("CONNECT %s journaled as %+v", target, ev)
		}
	}
}

// The default transport dials through the guard: a provider name that now
// resolves into the home network is refused, journaled, and never dialed.
func TestDefaultTransportRefusesPrivateAnswer(t *testing.T) {
	var dialed atomic.Int32
	g := netguard.New(netguard.Config{
		Resolver: &stubResolver{"10.0.0.9"},
		Connect: func(context.Context, string, string) (net.Conn, error) {
			dialed.Add(1)
			return nil, net.ErrClosed
		},
	})
	audit := &auditLog{}
	p := guardedProxy(t, []Adapter{OpenAI("k")}, g, audit)
	w := serveOne(p, chat("/openai/v1/chat/completions"))
	if w.Code != http.StatusForbidden || w.Header().Get(DeniedHeader) == "" {
		t.Fatalf("status %d", w.Code)
	}
	if ev := audit.last(t); ev.Allowed || ev.Adapter != "openai" {
		t.Fatalf("journaled as %+v", ev)
	}
	if dialed.Load() != 0 {
		t.Fatal("a refused address must not be connected")
	}
}

// EGRESS-NOPROXY-1 (#1611, DEV-2): the default transport takes no proxy
// from the environment. A proxy resolves the provider's name itself, so
// netguard's address policy would never see the answer; the owner host's
// HTTPS_PROXY must not route the proxy's upstream traffic or setup's key
// check around it.
func TestDefaultTransportTakesNoProxyFromTheEnvironment(t *testing.T) {
	for _, v := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(v, "http://proxy.home.example:3128")
	}
	if tr := DefaultTransport(netguard.New(netguard.Config{})); tr.Proxy != nil {
		t.Fatal("DefaultTransport sets Proxy; the guard must resolve the provider's name itself")
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "hosted.home.example"},
		DNSNames:  []string{"hosted.home.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func hostedAdapter() Adapter {
	a := OpenAI("k")
	a.Name, a.Host = "hosted", "hosted.home.example"
	a.Operations = append(a.Operations, Operation{Name: "models", Verb: VerbRead, Method: "GET", Path: "/v1/models"})
	return a
}

// Acceptance 4: a pinned private hosted route is reached by its inference
// operation only; any other path is denied and journaled, and a rebound
// name fails at the handshake with no request sent.
func TestHostedPinReachedByInferenceOnly(t *testing.T) {
	fp := &fakeProvider{}
	real := httptest.NewTLSServer(fp)
	defer real.Close()
	rogueFP := &fakeProvider{}
	rogue := httptest.NewUnstartedServer(rogueFP)
	rogue.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	rogue.StartTLS()
	defer rogue.Close()

	var target atomic.Value
	target.Store(real.Listener.Addr().String())
	g := netguard.New(netguard.Config{
		Resolver: &stubResolver{"192.168.1.77"},
		Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, target.Load().(string))
		},
	})
	g.Learn(netguard.Network{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}})
	if err := g.SetPins([]netguard.Pin{{Kind: netguard.PinHosted, Name: "hosted.home.example", Key: netguard.KeyHash(real.Certificate())}}); err != nil {
		t.Fatal(err)
	}
	audit := &auditLog{}
	p := guardedProxy(t, []Adapter{hostedAdapter()}, g, audit)

	if w := serveOne(p, chat("/hosted/v1/chat/completions")); w.Code != http.StatusOK {
		t.Fatalf("inference to the pinned route: %d %s", w.Code, w.Body.String())
	}
	if fp.count() != 1 {
		t.Fatalf("hosted saw %d", fp.count())
	}

	req := httptest.NewRequest("GET", "/hosted/v1/models", nil)
	w := serveOne(p, req)
	if w.Code != http.StatusForbidden || w.Header().Get(DeniedHeader) == "" {
		t.Fatalf("non-inference path: %d", w.Code)
	}
	if ev := audit.last(t); ev.Allowed || ev.Adapter != "hosted" {
		t.Fatalf("non-inference path journaled as %+v", ev)
	}
	if fp.count() != 1 {
		t.Fatal("the non-inference path must not reach the host")
	}

	// The name now answers at another host. A pooled connection is still
	// the verified one; the rebound answer matters at the next dial.
	p.rtModel.(*http.Transport).CloseIdleConnections()
	target.Store(rogue.Listener.Addr().String())
	w = serveOne(p, chat("/hosted/v1/chat/completions"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("rebound pinned name: %d", w.Code)
	}
	if rogueFP.count() != 0 {
		t.Fatal("no request byte may reach a rebound host")
	}
}
