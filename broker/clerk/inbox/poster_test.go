package inbox

// REQ: CLK-2, VRB-2, DEV-2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// fakeResolver answers each name from a table and counts its lookups.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	lookups int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	a, ok := f.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return a, nil
}

// public is a public address the fake resolver gives (TEST-NET would be
// refused by the policy, so this is a documentation-free global address).
var public = netip.MustParseAddr("93.184.216.34")

// posterRig is a Poster whose policy resolves through a fake resolver and
// whose connect to a checked address reaches a local TLS server instead.
type posterRig struct {
	res      *fakeResolver
	srv      *httptest.Server
	hits     int
	dialed   []string
	poster   *Poster
	mu       sync.Mutex
	response func(w http.ResponseWriter, r *http.Request)
	got      *http.Request
	gotBody  string
}

func newPosterRig(t *testing.T, answers map[string][]netip.Addr) *posterRig {
	t.Helper()
	rg := &posterRig{res: &fakeResolver{answers: answers}}
	rg.response = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	rg.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rg.mu.Lock()
		rg.hits++
		rg.got, rg.gotBody = r, string(b)
		rg.mu.Unlock()
		rg.response(w, r)
	}))
	t.Cleanup(rg.srv.Close)
	g := netguard.New(netguard.Config{Resolver: rg.res, Connect: func(ctx context.Context, network, addr string) (net.Conn, error) {
		rg.mu.Lock()
		rg.dialed = append(rg.dialed, addr)
		rg.mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, rg.srv.Listener.Addr().String())
	}})
	roots := x509.NewCertPool()
	roots.AddCert(rg.srv.Certificate())
	rg.poster = NewPoster(g, &tls.Config{RootCAs: roots})
	return rg
}

func onePost(u string) Post {
	return Post{Method: "POST", URL: u, Body: "List-Unsubscribe=One-Click",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}
}

func wantNotDone(t *testing.T, err error, want NotDone) {
	t.Helper()
	var nd NotDone
	if !errors.As(err, &nd) || nd != want {
		t.Fatalf("Post = %v, want %v", err, want)
	}
}

// A one-click POST to a public https name is sent once, to the address the
// name resolved to and the policy checked, with the clerk's body.
func TestPosterSendsOneClickToAPublicName(t *testing.T) {
	rg := newPosterRig(t, map[string][]netip.Addr{"example.com": {public}})
	if err := rg.poster.Post(context.Background(), onePost("https://example.com/u?id=7")); err != nil {
		t.Fatal(err)
	}
	if rg.hits != 1 || rg.got.Method != "POST" || rg.got.URL.RequestURI() != "/u?id=7" || rg.gotBody != "List-Unsubscribe=One-Click" ||
		rg.got.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || rg.got.Host != "example.com" || rg.got.Header["User-Agent"] != nil {
		t.Fatalf("hits %d request %+v body %q", rg.hits, rg.got, rg.gotBody)
	}
	// Pinned: one lookup, and the connect went to the checked literal.
	if rg.res.lookups != 1 || len(rg.dialed) != 1 || rg.dialed[0] != "93.184.216.34:443" {
		t.Fatalf("lookups %d dialed %v", rg.res.lookups, rg.dialed)
	}
}

// Every rejected shape is refused before anything is resolved or sent.
func TestPosterRefusesBadURLShapes(t *testing.T) {
	rg := newPosterRig(t, map[string][]netip.Addr{"example.com": {public}, "evil.test": {public}})
	for _, u := range []string{
		"http://example.com/u",                                    // not https
		"https://user@example.com/u",                              // userinfo
		"https://user:pw@example.com/u",                           // userinfo with a password
		"https://evil.test:443@example.com/u",                     // userinfo that urlHost reads as the host
		"https://example.com:8443/u",                              // not 443
		"https://example.com:80/u",                                // not 443
		"https://example.com/u u",                                 // whitespace
		"https://example.com/u\tx",                                // control character
		"https://example.com/u\r\nX-Evil: 1",                      // header injection
		"https://example.com/u\x00",                               // NUL
		"https://example.com/u\x7f",                               // DEL
		"https://exämple.com/u",                                   // non-ASCII
		"https://example.com\\@evil.test/u",                       // backslash parser differential
		"https://example.com#@evil.test/u",                        // fragment
		"https://example.com/u#x",                                 // fragment
		"https://93.184.216.34/u",                                 // an address, not a name
		"https://[2606:2800:220:1::1]/u",                          // an IPv6 address
		"https://localhost/u",                                     // a single label
		"https://ex%61mple.com/u",                                 // an escaped host
		"https:example.com/u",                                     // opaque
		"https:///u",                                              // no host
		"mailto:u@example.com",                                    // not https
		"https://-example.com/u",                                  // not LDH
		"https://1.2.3.04/u",                                      // an all-digit last label reads as an address
		"https://example.com/" + string(make([]byte, postURLMax)), // too long (and NULs)
	} {
		wantNotDone(t, rg.poster.Post(context.Background(), onePost(u)), nBadURL)
	}
	p := onePost("https://example.com/u")
	p.Method = "GET"
	wantNotDone(t, rg.poster.Post(context.Background(), p), nBadURL)
	if rg.hits != 0 || rg.res.lookups != 0 {
		t.Fatalf("hits %d lookups %d after refused shapes", rg.hits, rg.res.lookups)
	}
}

// A name that resolves to any private, loopback, link-local or otherwise
// special address is refused after resolution, before any connect.
func TestPosterRefusesPrivateAnswers(t *testing.T) {
	for _, a := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.5", "127.0.0.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1", "64:ff9b::a00:1"} {
		rg := newPosterRig(t, map[string][]netip.Addr{"example.com": {netip.MustParseAddr(a)}})
		wantNotDone(t, rg.poster.Post(context.Background(), onePost("https://example.com/u")), nEgress)
		if rg.hits != 0 || len(rg.dialed) != 0 {
			t.Fatalf("%s: hits %d dialed %v", a, rg.hits, rg.dialed)
		}
	}
	// One private answer among public ones refuses the name.
	rg := newPosterRig(t, map[string][]netip.Addr{"example.com": {public, netip.MustParseAddr("10.1.2.3")}})
	wantNotDone(t, rg.poster.Post(context.Background(), onePost("https://example.com/u")), nEgress)
	if rg.hits != 0 || len(rg.dialed) != 0 {
		t.Fatalf("mixed answers: hits %d dialed %v", rg.hits, rg.dialed)
	}
}

// A redirect is not followed and does not confirm the unsubscribe.
func TestPosterFollowsNoRedirect(t *testing.T) {
	rg := newPosterRig(t, map[string][]netip.Addr{"example.com": {public}})
	rg.response = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/u" {
			http.Redirect(w, r, "https://example.com/next", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
	err := rg.poster.Post(context.Background(), onePost("https://example.com/u"))
	if !errors.Is(err, errUnconfirmed) || rg.hits != 1 {
		t.Fatalf("Post = %v, hits %d", err, rg.hits)
	}
}

// A refusal by the endpoint is unconfirmed, not not-done: the request
// reached it.
func TestPosterTreatsAnErrorStatusAsUnconfirmed(t *testing.T) {
	rg := newPosterRig(t, map[string][]netip.Addr{"example.com": {public}})
	rg.response = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }
	if err := rg.poster.Post(context.Background(), onePost("https://example.com/u")); !errors.Is(err, errUnconfirmed) {
		t.Fatalf("Post = %v", err)
	}
}

// A name that does not resolve, or a certificate that does not verify,
// sends nothing.
func TestPosterSendsNothingWithoutAConnection(t *testing.T) {
	rg := newPosterRig(t, map[string][]netip.Addr{"example.com": {public}})
	wantNotDone(t, rg.poster.Post(context.Background(), onePost("https://unknown.example/u")), nNotSent)
	// The test server's certificate names example.com, not other.example.
	rg.res.answers["other.example"] = []netip.Addr{public}
	wantNotDone(t, rg.poster.Post(context.Background(), onePost("https://other.example/u")), nNotSent)
	if rg.hits != 0 {
		t.Fatalf("hits %d", rg.hits)
	}
}

// The live mailbox posts only once WithPoster turns it on, and then through
// the store's own address policy.
func TestLivePostsThroughTheStoresPolicy(t *testing.T) {
	res := &fakeResolver{answers: map[string][]netip.Addr{"shop.test": {netip.MustParseAddr("192.168.0.9")}}}
	connects := 0
	g := netguard.New(netguard.Config{Resolver: res, Connect: func(context.Context, string, string) (net.Conn, error) {
		connects++
		return nil, errors.New("unreachable in test")
	}})
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: "imap.test:993", SMTP: "smtp.test:465", From: "o@example.test", Guard: g,
		Credential: func(context.Context) (imapsmtp.Login, error) { return imapsmtp.Login{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	// NewLive alone keeps unsubscribes refused until the bounded save
	// lands (#2841).
	wantNotDone(t, NewLive(st).Post(context.Background(), onePost("https://shop.test/u")), nNoPoster)
	if res.lookups != 0 {
		t.Fatalf("lookups %d without a poster", res.lookups)
	}
	wantNotDone(t, NewLive(st).WithPoster().Post(context.Background(), onePost("https://shop.test/u")), nEgress)
	if res.lookups != 1 || connects != 0 {
		t.Fatalf("lookups %d connects %d", res.lookups, connects)
	}
}

// FuzzPostURL: whatever postURL accepts is https to a DNS name on 443
// with no userinfo or fragment, and its host is the one VRB-2 reads.
func FuzzPostURL(f *testing.F) {
	for _, s := range []string{"https://example.com/u", "https://a@b.c/", "https://b.c:443/x?y", "https://b.c\\@d.e/", "HTTPS://B.C/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, ok := postURL(raw)
		if !ok {
			return
		}
		if u.Scheme != "https" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") ||
			!hostName.MatchString(strings.ToLower(u.Hostname())) || strings.ToLower(u.Hostname()) != urlHost(raw) {
			t.Fatalf("accepted %q as %+v", raw, u)
		}
	})
}
