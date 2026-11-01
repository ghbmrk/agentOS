package page

// REQ: NET-4, NET-6, NET-2, NET-1, NET-7

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const rp = "enforcer.home.arpa"

// zone is the owner's time zone in the tests: not UTC, so a time shown in
// UTC is caught.
var zone = time.FixedZone("PST", -8*60*60)

// The test home's segments: the Owner network and the admin port may reach
// the page; nothing else may.
var (
	ownerAddr = netip.MustParseAddr("127.0.0.2")
	adminAddr = netip.MustParseAddr("127.0.0.3")
	others    = map[string]netip.Addr{
		"household": netip.MustParseAddr("127.0.0.4"), "guests": netip.MustParseAddr("127.0.0.5"),
		"devices": netip.MustParseAddr("127.0.0.6"), "core": netip.MustParseAddr("127.0.0.7"),
		"edge": netip.MustParseAddr("127.0.0.8"),
	}
)

// authenticator is the owner's phone: an ES256 passkey that answers a
// get() for a challenge the page served, as a browser on origin would.
type authenticator struct {
	t           *testing.T
	priv        *ecdsa.PrivateKey
	rpID        string // the RP ID hashed into authenticator data
	origin      string
	crossOrigin bool
	flags       byte
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{t: t, priv: p, rpID: rp, origin: "https://" + rp, flags: 0x01 | 0x04 | 0x08}
}

func (a *authenticator) Public() key.PublicKey {
	point, _ := a.priv.PublicKey.Bytes()
	pk, err := key.ES256(rp, point)
	if err != nil {
		a.t.Fatal(err)
	}
	return pk
}

// get signs challenge (base64url, as the page serves it).
func (a *authenticator) get(challenge string) assertion {
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": a.origin, "crossOrigin": a.crossOrigin})
	h := sha256.Sum256([]byte(a.rpID))
	ad := append(h[:], a.flags, 0, 0, 0, 0)
	cdh := sha256.Sum256(cd)
	m := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, m[:])
	if err != nil {
		a.t.Fatal(err)
	}
	e := base64.RawURLEncoding.EncodeToString
	return assertion{AuthenticatorData: e(ad), ClientDataJSON: e(cd), Signature: e(sig)}
}

type memStore struct{ b []byte }

func (m *memStore) Load() ([]byte, error) { return m.b, nil }
func (m *memStore) Save(b []byte) error   { m.b = slices.Clone(b); return nil }

type fakeChannel struct{ paused bool }

func (c *fakeChannel) Paused() bool  { return c.paused }
func (c *fakeChannel) Resume() error { c.paused = false; return nil }

func home(v uint64) policy.Document {
	return policy.Document{
		Version:      v,
		Destinations: []string{"models.example"},
		Devices: []policy.Device{
			{ID: "cam", Network: policy.NetDevices, WiFi: "vlan102", Allow: []string{"cam.example"}, VendorCloud: true, Class: policy.ClassCamera},
			{ID: "lock", Network: policy.NetDevices, Allow: []string{"lock.example"}, Class: policy.ClassLock, Secure: "lock", Label: policy.LabelExceptRadio},
			{ID: "tv", Network: policy.NetDevices, WiFi: "vlan104", Allow: []string{"a.example"}, VendorCloud: true, Everyday: true, Label: policy.LabelContained},
		},
	}
}

type rig struct {
	t      *testing.T
	s      *Server
	e      *policy.Engine
	a      *authenticator
	ch     *fakeChannel
	now    time.Time
	cert   Cert
	remote netip.Addr
	// The phone browser's anti-forgery cookie and token, from the last
	// screen g.s drew (csrf.go); do posts with them.
	cookie, token string
	tokenOf       *Server
}

// newRig is a page over an engine holding home(1), on a fake clock.
func newRig(t *testing.T) *rig {
	t.Helper()
	a := newAuthenticator(t)
	e, err := policy.Open(a.Public(), &memStore{})
	if err != nil {
		t.Fatal(err)
	}
	p := policy.Proposal{Doc: home(1), Diff: []byte("v1")}
	r, _ := p.Root(a.Public())
	if _, err := e.Propose(p, a.signMsg(key.RootMsg(r)), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Tick(policy.Wait); err != nil {
		t.Fatal(err)
	}
	g := &rig{t: t, e: e, a: a, ch: &fakeChannel{}, now: time.Now(), remote: ownerAddr}
	g.cert, err = NewCert(rp, g.now)
	if err != nil {
		t.Fatal(err)
	}
	g.s, err = New(Config{
		Name: rp, Owner: a.Public(),
		Addrs:  []netip.AddrPort{netip.AddrPortFrom(ownerAddr, 443), netip.AddrPortFrom(adminAddr, 443)},
		Allow:  []netip.Prefix{netip.PrefixFrom(ownerAddr, 32), netip.PrefixFrom(adminAddr, 32)},
		Policy: e, Channel: g.ch, Cert: g.cert.Leaf, Zone: zone,
		Now: func() time.Time { return g.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// signMsg is a tap over msg itself (the challenge is its SHA-256).
func (a *authenticator) signMsg(msg []byte) []byte {
	c := key.Challenge(msg)
	x := a.get(base64.RawURLEncoding.EncodeToString(c[:]))
	d := base64.RawURLEncoding.DecodeString
	ad, _ := d(x.AuthenticatorData)
	cd, _ := d(x.ClientDataJSON)
	sig, _ := d(x.Signature)
	b, err := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	if err != nil {
		a.t.Fatal(err)
	}
	return b
}

// do sends one request to the page as the phone's browser on the page's
// own origin would, from g.remote.
func (g *rig) do(method, path string, body any, hdr ...string) *httptest.ResponseRecorder {
	g.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	if method != http.MethodGet && g.tokenOf != g.s {
		g.screen()
	}
	req := httptest.NewRequest(method, "https://"+rp+path, rd)
	req.RemoteAddr = netip.AddrPortFrom(g.remote, 50000).String()
	if method != http.MethodGet {
		req.Header.Set("Origin", "https://"+rp)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Cookie", tokenCookie+"="+g.cookie)
		req.Header.Set(tokenHeader, g.token)
	} else {
		req.Header.Set("Sec-Fetch-Site", "cross-site") // opened from a text
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
		} else if hdr[i+1] == "" {
			req.Header.Del(hdr[i])
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	w := httptest.NewRecorder()
	g.s.ServeHTTP(w, req)
	g.keep(w)
	return w
}

var reToken = regexp.MustCompile(`<meta name="enforcer-token" content="([A-Za-z0-9_-]+)">`)

// keep keeps the anti-forgery cookie and token a screen of g.s set, as the
// phone's browser would.
func (g *rig) keep(w *httptest.ResponseRecorder) {
	g.t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == tokenCookie {
			m := reToken.FindStringSubmatch(w.Body.String())
			if m == nil {
				g.t.Fatalf("a screen set the cookie with no token:\n%s", w.Body)
			}
			g.cookie, g.token, g.tokenOf = c.Value, m[1], g.s
		}
	}
}

// screen opens a screen of g.s, for its token: the enrolment screen when
// the page has one, else home.
func (g *rig) screen() {
	g.t.Helper()
	path := "/"
	if g.s.cfg.Enrol != nil {
		path = "/enrol"
	}
	g.do(http.MethodGet, path, nil)
	if g.tokenOf != g.s {
		g.t.Fatalf("%s drew no token", path)
	}
}

// linkFor is the proposal link the core would text for next.
func linkFor(next policy.Document, summary string) string {
	b, err := policy.Encode(next)
	if err != nil {
		panic(err)
	}
	return "/p?d=" + base64.RawURLEncoding.EncodeToString(b) + "&s=" + strings.ReplaceAll(summary, " ", "+")
}

var (
	reID   = regexp.MustCompile(`data-id="([0-9a-f]+)"`)
	reChal = regexp.MustCompile(`data-challenge="([A-Za-z0-9_-]+)"`)
)

// open opens a proposal link and returns the screen, its challenge ID and
// the challenge.
func (g *rig) open(next policy.Document, summary string) (string, string, string) {
	g.t.Helper()
	w := g.do(http.MethodGet, linkFor(next, summary), nil)
	if w.Code != http.StatusOK {
		g.t.Fatalf("open: %d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	id, ch := reID.FindStringSubmatch(body), reChal.FindStringSubmatch(body)
	if id == nil || ch == nil {
		g.t.Fatalf("no challenge on the screen:\n%s", body)
	}
	return body, id[1], ch[1]
}

func (g *rig) approve(id string, a assertion) *httptest.ResponseRecorder {
	a.ID = id
	return g.do(http.MethodPost, "/approve", a)
}

func edit(v uint64, f func(d *policy.Document)) policy.Document {
	d := home(v)
	f(&d)
	return d
}

func dev(d *policy.Document, id string) *policy.Device {
	for i := range d.Devices {
		if d.Devices[i].ID == id {
			return &d.Devices[i]
		}
	}
	panic(id)
}

// NET-6: the page answers only the Owner network and the wired admin port.
// A connection from Household, Guests, Devices, the core's or the edge's
// segment is closed before the TLS handshake, with no answer; a request
// that reached the handler from one anyway is aborted unanswered; and the
// page never binds an unspecified address or one off those networks.
func TestServedOnlyToOwnerAndAdmin(t *testing.T) {
	g := newRig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go g.s.Serve(ln)
	defer ln.Close()
	roots := x509.NewCertPool()
	rc, _ := x509.ParseCertificate(g.cert.Root)
	roots.AddCert(rc)

	get := func(from netip.Addr) (int, error) {
		d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: from.AsSlice()}, Timeout: 2 * time.Second}
		c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return d.DialContext(ctx, "tcp", ln.Addr().String())
			},
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: rp},
		}}
		res, err := c.Get("https://" + rp + "/")
		if err != nil {
			return 0, err
		}
		res.Body.Close()
		return res.StatusCode, nil
	}
	for name, from := range map[string]netip.Addr{"owner": ownerAddr, "admin": adminAddr} {
		if code, err := get(from); err != nil || code != http.StatusOK {
			t.Errorf("from the %s network: %d %v, want the page", name, code, err)
		}
	}
	for name, from := range others {
		if code, err := get(from); err == nil {
			t.Errorf("from the %s segment: answered %d", name, code)
		}
		// Not even a TLS handshake: the connection is closed first.
		d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: from.AsSlice()}, Timeout: 2 * time.Second}
		if c, err := tls.DialWithDialer(d, "tcp", ln.Addr().String(), &tls.Config{RootCAs: roots, ServerName: rp}); err == nil {
			c.Close()
			t.Errorf("from the %s segment: the TLS handshake completed", name)
		}
	}

	for name, from := range others {
		g.remote = from
		func() {
			defer func() {
				if r := recover(); r != http.ErrAbortHandler {
					t.Errorf("from the %s segment, the handler did not abort: %v", name, r)
				}
			}()
			g.do(http.MethodGet, "/", nil)
		}()
	}

	cfg := g.s.cfg
	for name, addrs := range map[string][]netip.AddrPort{
		"every interface":     {netip.MustParseAddrPort("0.0.0.0:443")},
		"every v6 interface":  {netip.MustParseAddrPort("[::]:443")},
		"the devices network": {netip.AddrPortFrom(others["devices"], 443)},
		"none":                nil,
	} {
		c := cfg
		c.Addrs = addrs
		if _, err := New(c); !errors.Is(err, ErrConfig) {
			t.Errorf("binding %s: %v, want refused", name, err)
		}
	}
	c := cfg
	c.Owner, _ = key.ES256("agentos.home.arpa", g.a.Public().Bytes())
	if _, err := New(c); !errors.Is(err, ErrConfig) {
		t.Errorf("a passkey on another RP ID: %v, want refused", err)
	}

	// The root the phone trusts vouches for the enforcer's name only.
	root, rootKey, err := newRoot(rp, g.now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := issue(root, rootKey, "bank.example", g.now)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	oc, _ := x509.ParseCertificate(other.Certificate[0])
	if _, err := oc.Verify(x509.VerifyOptions{Roots: pool, DNSName: "bank.example", CurrentTime: g.now}); err == nil {
		t.Error("the enforcer's root vouches for another name")
	}
}

// NET-4: a proposal link whose summary says one thing and whose change does
// another shows the change, drawn by the enforcer from the policy, and the
// owner's tap signs that rendered diff. A diff drawn against a policy that
// has moved since is refused, not applied over the move.
func TestFalseDiffShowsTrueDiff(t *testing.T) {
	g := newRig(t)
	next := edit(7, func(d *policy.Document) { dev(d, "tv").Allow = append(dev(d, "tv").Allow, "x.example") })
	body, id, ch := g.open(next, "Isolate the camera")
	if strings.Contains(body, "Isolate") || strings.Contains(body, "camera") {
		t.Errorf("the screen shows the link's summary:\n%s", body)
	}
	for _, want := range []string{"Let tv reach x.example.", "applies 10 minutes after you approve"} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen lacks %q:\n%s", want, body)
		}
	}
	if w := g.approve(id, g.a.get(ch)); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	p := g.e.Pending()
	if len(p) != 1 || !strings.Contains(string(p[0].Diff), "Let tv reach x.example.") || strings.Contains(string(p[0].Diff), "camera") {
		t.Fatalf("pending: %+v", p)
	}
	doc, _ := policy.Decode(p[0].Doc)
	if err := policy.Check(g.a.Public(), p[0].Key, policy.Proposal{Doc: doc, Diff: p[0].Diff}); err != nil {
		t.Errorf("the owner's key does not commit to the rendered diff: %v", err)
	}
	if doc.Version <= 1 {
		t.Errorf("version %d: the page did not pick a rising version", doc.Version)
	}
	if err := g.e.Cancel(p[0].ID); err != nil {
		t.Fatal(err)
	}

	// The core tightens after the screen is drawn: approving it would undo
	// that cut without the screen saying so.
	next = edit(8, func(d *policy.Document) { dev(d, "tv").Allow = append(dev(d, "tv").Allow, "y.example") })
	_, id, ch = g.open(next, "")
	if err := g.e.Tighten(policy.Op{Kind: policy.CutVendorCloud, Device: "tv"}, g.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if w := g.approve(id, g.a.get(ch)); w.Code != http.StatusConflict {
		t.Errorf("a diff drawn before a move: %d %s, want refused", w.Code, w.Body)
	}
	if len(g.e.Pending()) != 0 || !strings.Contains(g.do(http.MethodGet, "/", nil).Body.String(), "Nothing.") {
		t.Error("a stale diff was applied")
	}

	// The core's names cannot reorder a line: a right-to-left override is
	// shown escaped.
	lines := Describe(home(1), edit(2, func(d *policy.Document) { dev(d, "tv").Allow = []string{"a.example", "moc.\u202eevil"} }), zone)
	if !slices.Contains(lines, `Let tv reach "moc.\u202eevil".`) {
		t.Errorf("an override shown raw: %q", lines)
	}

	// A tightening applies at once.
	cut := g.e.Current()
	dev(&cut, "tv").Allow = nil
	body, id, ch = g.open(cut, "")
	if !strings.Contains(body, "applies as soon as you approve") {
		t.Errorf("a tightening's screen:\n%s", body)
	}
	if w := g.approve(id, g.a.get(ch)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"applied":true`) {
		t.Errorf("a tightening: %d %s", w.Code, w.Body)
	}
}

// NET-4 Passkey rules: the page takes only the owner's passkey, with user
// verification, on the enforcer's RP ID and origin, not cross-origin, over
// the diff it drew, once. Each refusal leaves the policy as it was.
func TestAssertionRefusals(t *testing.T) {
	g := newRig(t)
	next := edit(2, func(d *policy.Document) { dev(d, "cam").Allow = append(dev(d, "cam").Allow, "x.example") })
	stranger := newAuthenticator(t)
	for name, f := range map[string]func(ch string) assertion{
		"none":  func(string) assertion { return assertion{} },
		"no UV": func(ch string) assertion { a := *g.a; a.flags = 0x01; return a.get(ch) },
		"wrong RP ID": func(ch string) assertion {
			a := *g.a
			a.rpID, a.origin = "home.arpa", "https://home.arpa"
			return a.get(ch)
		},
		"wrong origin": func(ch string) assertion { a := *g.a; a.origin = "https://agentos." + rp; return a.get(ch) },
		"cross-origin": func(ch string) assertion { a := *g.a; a.crossOrigin = true; return a.get(ch) },
		"another key":  func(ch string) assertion { return stranger.get(ch) },
		"another diff": func(string) assertion {
			p := policy.Proposal{Doc: next, Diff: []byte("Isolate the camera")}
			r, _ := p.Root(g.a.Public())
			c := key.Challenge(key.RootMsg(r))
			return g.a.get(base64.RawURLEncoding.EncodeToString(c[:]))
		},
		"another challenge": func(string) assertion {
			c := key.Challenge([]byte("anything else"))
			return g.a.get(base64.RawURLEncoding.EncodeToString(c[:]))
		},
	} {
		_, id, ch := g.open(next, "")
		if w := g.approve(id, f(ch)); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d %s, want refused", name, w.Code, w.Body)
		}
		if w := g.approve(id, g.a.get(ch)); w.Code != http.StatusGone {
			t.Errorf("%s: the challenge outlived a refused tap: %d", name, w.Code)
		}
	}
	if len(g.e.Pending()) != 0 || g.e.Current().Version != 1 {
		t.Fatalf("a refused tap changed the policy: %d pending, version %d", len(g.e.Pending()), g.e.Current().Version)
	}

	// Sent from another origin, the tap is refused before it is read.
	_, id, ch := g.open(next, "")
	for name, hdr := range map[string][]string{
		"another origin":   {"Origin", "https://agentos.home.arpa"},
		"no origin":        {"Origin", ""},
		"cross-site fetch": {"Sec-Fetch-Site", "cross-site"},
		"a form post":      {"Content-Type", "application/x-www-form-urlencoded"},
	} {
		a := g.a.get(ch)
		a.ID = id
		if w := g.do(http.MethodPost, "/approve", a, hdr...); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d, want refused", name, w.Code)
		}
	}

	// Replayed: the same tap again, or on a fresh screen for the same link.
	good := g.a.get(ch)
	if w := g.approve(id, good); w.Code != http.StatusOK {
		t.Fatalf("the owner's tap: %d %s", w.Code, w.Body)
	}
	if w := g.approve(id, good); w.Code != http.StatusGone {
		t.Errorf("replayed: %d, want refused", w.Code)
	}
	if err := g.e.Cancel(g.e.Pending()[0].ID); err != nil {
		t.Fatal(err)
	}
	_, id2, _ := g.open(next, "")
	if w := g.approve(id2, good); w.Code != http.StatusForbidden {
		t.Errorf("replayed on a fresh screen: %d, want refused", w.Code)
	}
	if len(g.e.Pending()) != 0 {
		t.Error("a replayed tap is pending")
	}

	// Malformed and flooding links are refused.
	g.now = g.now.Add(LinkWindow)
	for name, path := range map[string]string{
		"no document":   "/p",
		"not base64":    "/p?d=%%%",
		"not canonical": "/p?d=" + base64.RawURLEncoding.EncodeToString([]byte(`{"version":1, "devices":[]}`)),
		"extra field":   linkFor(next, "") + "&x=1",
		"no change":     linkFor(home(5), ""),
		"too long":      "/p?d=" + strings.Repeat("A", maxLink+4),
	} {
		if w := g.do(http.MethodGet, path, nil); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want refused", name, w.Code)
		}
	}
	g.now = g.now.Add(LinkWindow)
	var limited bool
	for range LinkLimit + 1 {
		limited = g.do(http.MethodGet, linkFor(next, ""), nil).Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Error("proposal links are not rate-limited")
	}
}

// NET-4: no answer from the page can be framed, by agentOS's pages or
// anyone's, and a request the browser marks as a frame load or a
// cross-site subresource gets nothing.
func TestNotFramable(t *testing.T) {
	g := newRig(t)
	next := edit(2, func(d *policy.Document) { dev(d, "tv").Isolated = true })
	for _, path := range []string{"/", linkFor(next, ""), "/p?d=bad", "/page.js", "/nothing"} {
		w := g.do(http.MethodGet, path, nil)
		h := w.Header()
		if h.Get("X-Frame-Options") != "DENY" || !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s: framing headers %q, %q", path, h.Get("X-Frame-Options"), h.Get("Content-Security-Policy"))
		}
	}
	if w := g.do(http.MethodPost, "/approve", assertion{}); w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("a refusal is framable")
	}
	for _, dest := range []string{"iframe", "frame", "embed", "object"} {
		w := g.do(http.MethodGet, linkFor(next, ""), nil, "Sec-Fetch-Dest", dest)
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "data-challenge") {
			t.Errorf("loaded as %s: %d", dest, w.Code)
		}
	}
	if w := g.do(http.MethodGet, "/", nil, "Sec-Fetch-Mode", "no-cors"); w.Code != http.StatusForbidden {
		t.Errorf("a cross-site subresource load: %d", w.Code)
	}
	if w := g.do(http.MethodGet, "/", nil, "Host", "evil.example"); w.Code == http.StatusOK {
		t.Error("answered for another host name (DNS rebinding)")
	}
}

// NET-2 Channel, NET-6: a paused channel resumes only by the owner's tap on
// this page, on a resume challenge, once.
func TestResumeOnlyFromPage(t *testing.T) {
	g := newRig(t)
	g.ch.paused = true
	if !strings.Contains(g.do(http.MethodGet, "/", nil).Body.String(), "The channel is paused.") {
		t.Error("the page does not show the pause")
	}
	resume := func(id string, a assertion) int {
		var b struct {
			assertion
			Action string `json:"action"`
		}
		b.assertion, b.Action = a, ActResume
		b.ID = id
		return g.do(http.MethodPost, "/act", b).Code
	}
	chal := func(action, target string, hdr ...string) (string, string) {
		w := g.do(http.MethodPost, "/challenge", map[string]string{"action": action, "target": target}, hdr...)
		var c struct{ ID, Challenge string }
		json.Unmarshal(w.Body.Bytes(), &c)
		return c.ID, c.Challenge
	}

	if code := resume("", g.a.get("x")); code != http.StatusGone {
		t.Errorf("no challenge: %d", code)
	}
	if id, _ := chal(ActResume, "", "Origin", "https://agentos.home.arpa"); id != "" {
		t.Error("another origin drew a resume challenge")
	}
	id, ch := chal(ActResume, "")
	a := *g.a
	a.flags = 0x01
	if code := resume(id, a.get(ch)); code != http.StatusForbidden || !g.ch.paused {
		t.Errorf("without user verification: %d, paused %v", code, g.ch.paused)
	}
	// A tap for a cancel does not resume.
	g.open(edit(2, func(d *policy.Document) { dev(d, "tv").Allow = nil; dev(d, "cam").VendorCloud = false }), "")
	id, ch = chal(ActResume, "")
	c := key.Challenge(actMsg(ActCancel, "", id))
	if code := resume(id, g.a.get(base64.RawURLEncoding.EncodeToString(c[:]))); code != http.StatusForbidden || !g.ch.paused {
		t.Errorf("a cancel's tap: %d, paused %v", code, g.ch.paused)
	}
	id, ch = chal(ActResume, "")
	good := g.a.get(ch)
	if code := resume(id, good); code != http.StatusOK || g.ch.paused {
		t.Fatalf("the owner's tap: %d, paused %v", code, g.ch.paused)
	}
	g.ch.paused = true
	if code := resume(id, good); code != http.StatusGone || !g.ch.paused {
		t.Errorf("replayed: %d, paused %v", code, g.ch.paused)
	}
	g.remote = others["core"]
	func() {
		defer func() { recover() }()
		resume(id, good)
	}()
	if !g.ch.paused {
		t.Error("the core's segment resumed the channel")
	}
}

// NET-4 Loosening: the page shows the loosening waiting and cancels it on
// the owner's tap over that one cancel.
func TestCancelPending(t *testing.T) {
	g := newRig(t)
	next := edit(2, func(d *policy.Document) { dev(d, "cam").Allow = append(dev(d, "cam").Allow, "x.example") })
	_, id, ch := g.open(next, "")
	if w := g.approve(id, g.a.get(ch)); w.Code != http.StatusOK {
		t.Fatal(w.Body)
	}
	pid := g.e.Pending()[0].ID
	if body := g.do(http.MethodGet, "/", nil).Body.String(); !strings.Contains(body, "Let cam reach x.example.") || !strings.Contains(body, "Cancel with your passkey") {
		t.Errorf("home does not show the pending loosening:\n%s", body)
	}
	w := g.do(http.MethodPost, "/challenge", map[string]string{"action": ActCancel, "target": pid})
	var c struct{ ID, Challenge string }
	json.Unmarshal(w.Body.Bytes(), &c)
	a := g.a.get(c.Challenge)
	a.ID = c.ID
	if w := g.do(http.MethodPost, "/act", struct {
		assertion
		Action string `json:"action"`
	}{a, ActCancel}); w.Code != http.StatusOK || len(g.e.Pending()) != 0 {
		t.Errorf("cancel: %d %s", w.Code, w.Body)
	}
	if w := g.do(http.MethodPost, "/challenge", map[string]string{"action": ActCancel, "target": "policy/nope"}); w.Code != http.StatusNotFound {
		t.Errorf("cancel of nothing: %d", w.Code)
	}
}

// NET-1: the page's limits are SPEC's words, and each device's label is the
// signed policy's, never what the device calls itself. NET-4: the page
// shows whether the passkey is synced.
func TestLimitsWordingAndLabels(t *testing.T) {
	spec, err := os.ReadFile("../../../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	in := false
	for _, l := range strings.Split(string(spec), "\n") {
		switch {
		case strings.HasPrefix(l, "- **NET-1**"):
			in = true
		case in && strings.HasPrefix(l, "  - "):
			l = strings.TrimPrefix(l, "  - ")
			l = strings.ReplaceAll(strings.ReplaceAll(l, " [Fact]", ""), "`", "")
			want = append(want, l)
		case in:
			in = false
		}
	}
	if len(want) == 0 || !slices.Equal(Limits, want) {
		t.Errorf("the limits differ from SPEC NET-1:\n got %q\nwant %q", Limits, want)
	}

	g := newRig(t)
	body := g.do(http.MethodGet, "/", nil).Body.String()
	for _, l := range Limits {
		if !strings.Contains(body, template_escape(l)) {
			t.Errorf("home lacks the limit %q", l)
		}
	}
	// A device that calls itself "contained" has no label in the policy.
	next := edit(2, func(d *policy.Document) {
		d.Devices = append(d.Devices, policy.Device{ID: "contained", Network: policy.NetDevices, Everyday: true})
	})
	scr, id, ch := g.open(next, "")
	if !strings.Contains(scr, "Label contained not containable.") {
		t.Errorf("the add screen:\n%s", scr)
	}
	if w := g.approve(id, g.a.get(ch)); w.Code != http.StatusOK {
		t.Fatal(w.Body)
	}
	g.now = g.now.Add(11 * time.Minute)
	if _, err := g.e.Tick(g.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	body = g.do(http.MethodGet, "/", nil).Body.String()
	for _, row := range []string{
		"<td>contained</td><td>devices</td><td>not containable</td>",
		"<td>tv</td><td>devices</td><td>contained</td>",
		"<td>lock</td><td>devices</td><td>contained except radio</td>",
		"<td>cam</td><td>devices</td><td>not containable</td>",
	} {
		if !strings.Contains(body, row) {
			t.Errorf("home lacks the row %s", row)
		}
	}
	if !strings.Contains(body, "Your passkey is synced") {
		t.Error("home does not say the passkey is synced (its last tap set BE)")
	}
}

func template_escape(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '\'':
			b.WriteString("&#39;")
		case '"':
			b.WriteString("&#34;")
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// NET-4 Passkey rules: the diff the owner signs shows every field of the
// document it commits to. Each field of an added device, and each change
// to a field of a device, pair, rule or hold already there, changes the
// rendered diff, so the core cannot slip a value past the screen (such as
// a new lock whose at-once command is "unlock", L3 on #3746). A field
// added to the document without a row here fails.
func TestEveryFieldRendered(t *testing.T) {
	devs := map[string]func(d *policy.Device){
		"ID":          func(d *policy.Device) { d.ID = "other" },
		"Network":     func(d *policy.Device) { d.Network = policy.NetHousehold },
		"WiFi":        func(d *policy.Device) { d.WiFi = "vlan999" },
		"Allow":       func(d *policy.Device) { d.Allow = []string{"z.example"} },
		"VendorCloud": func(d *policy.Device) { d.VendorCloud = !d.VendorCloud },
		"Isolated":    func(d *policy.Device) { d.Isolated = !d.Isolated },
		"Everyday":    func(d *policy.Device) { d.Everyday = !d.Everyday; d.Class, d.Secure = "", "" },
		"Class":       func(d *policy.Device) { d.Class, d.Secure = policy.ClassSensor, "" },
		"Secure":      func(d *policy.Device) { d.Secure = map[string]string{"": "lock", "lock": ""}[d.Secure] },
		"Label":       func(d *policy.Device) { d.Label = policy.LabelContained },
		"Control":     func(d *policy.Device) { d.Control = append(d.Control, policy.Port{Proto: policy.ProtoUDP, Num: 80}) },
		"MDNS":        func(d *policy.Device) { d.MDNS = append(d.MDNS, []string{"z", "local"}) },
	}
	// A stream port only a camera or microphone carries, and a change
	// from one of those classes to the other, so these rows run on one.
	recorders := map[string]func(d *policy.Device){
		"Class":  func(d *policy.Device) { d.Class = policy.ClassMicrophone },
		"Stream": func(d *policy.Device) { d.Stream = append(d.Stream, policy.Port{Proto: policy.ProtoUDP, Num: 554}) },
	}
	docs := map[string]func(d *policy.Document){
		"Version":      nil, // the page picks it; it is in the serial, not the diff
		"Destinations": func(d *policy.Document) { d.Destinations = append(d.Destinations, "z.example") },
		"Devices":      nil, // the device rows above
		"Pairs":        func(d *policy.Document) { d.Pairs = append(d.Pairs, policy.Pair{A: "cam", B: "tv"}) },
		"Standing":     func(d *policy.Document) { d.Standing[0].ToMS++ },
		"Holds":        func(d *policy.Document) { d.Holds = append(d.Holds, policy.Hold{Device: "tv", Kind: policy.HoldFix}) },
		"Drone":        func(d *policy.Document) { d.Drone = strings.Repeat("ab", 32) },
	}
	rules := map[string]func(r *policy.StandingRule){
		"ID": func(r *policy.StandingRule) { r.ID = "other" }, "Device": func(r *policy.StandingRule) { r.Device = "cam" },
		"Action": func(r *policy.StandingRule) { r.Action = "unlock" }, "FromMS": func(r *policy.StandingRule) { r.FromMS-- },
		"ToMS": func(r *policy.StandingRule) { r.ToMS++ },
	}
	pairs := map[string]func(p *policy.Pair){
		"A": func(p *policy.Pair) { p.A = "tv" }, "B": func(p *policy.Pair) { p.B = "tv" },
	}
	holds := map[string]func(h *policy.Hold){
		"Device": func(h *policy.Hold) { h.Device = "tv" }, "Kind": func(h *policy.Hold) { h.Kind = policy.HoldFix },
	}
	for ty, m := range map[reflect.Type][]string{
		reflect.TypeOf(policy.Device{}): keys(devs, recorders), reflect.TypeOf(policy.Document{}): keys(docs),
		reflect.TypeOf(policy.StandingRule{}): keys(rules), reflect.TypeOf(policy.Pair{}): keys(pairs),
		reflect.TypeOf(policy.Hold{}): keys(holds), reflect.TypeOf(policy.Port{}): {"Num", "Proto"},
	} {
		var fields []string
		for i := range ty.NumField() {
			fields = append(fields, ty.Field(i).Name)
		}
		slices.Sort(fields)
		if !slices.Equal(fields, m) {
			t.Errorf("%s has fields %v; this test covers %v", ty.Name(), fields, m)
		}
	}

	base := edit(1, func(d *policy.Document) {
		d.Pairs = []policy.Pair{{A: "cam", B: "lock"}}
		d.Standing = []policy.StandingRule{{ID: "plumber", Device: "lock", Action: "keypad-code", FromMS: 1000, ToMS: 2000}}
		d.Holds = []policy.Hold{{Device: "cam", Kind: policy.HoldFirmware}}
		dev(d, "cam").Class, dev(d, "cam").Stream = policy.ClassCamera, []policy.Port{{Proto: policy.ProtoTCP, Num: 554}}
	})
	differs := func(name string, a, b policy.Document) {
		if _, err := policy.Encode(b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if slices.Equal(Describe(base, a, zone), Describe(base, b, zone)) {
			t.Errorf("%s: the diff does not show it: %q", name, Describe(base, b, zone))
		}
	}
	// A device added with each field set, against the same device without.
	nw := policy.Device{ID: "new", Network: policy.NetDevices, Allow: []string{"n.example"}, VendorCloud: true, Class: policy.ClassLock}
	added := func(f func(*policy.Device)) policy.Document {
		d := clone(base)
		v := nw
		v.Allow = slices.Clone(v.Allow)
		if f != nil {
			f(&v)
		}
		d.Devices = append(d.Devices, v)
		return d
	}
	for name, f := range devs {
		differs("a new device's "+name, added(nil), added(f))
	}
	for name, f := range recorders {
		camera := func(v *policy.Device) {
			v.Class, v.Stream = policy.ClassCamera, []policy.Port{{Proto: policy.ProtoTCP, Num: 554}}
		}
		differs("a new camera's "+name, added(camera), added(func(v *policy.Device) { camera(v); f(v) }))
		differs("the camera's "+name, base, func() policy.Document { d := clone(base); f(dev(&d, "cam")); return d }())
	}
	// Each field changed on a device, pair, rule or hold already there.
	for name, f := range devs {
		if name == "ID" {
			continue // a rename is a removal and an addition, both shown
		}
		differs("the lock's "+name, base, func() policy.Document { d := clone(base); f(dev(&d, "lock")); return d }())
	}
	// A class change alone, with the same secure command (L3 on #3873).
	heat := func(class string) policy.Document {
		d := clone(base)
		d.Devices = append(d.Devices, policy.Device{ID: "heat", Network: policy.NetDevices, Class: class, Secure: "off"})
		return d
	}
	if _, err := policy.Encode(heat(policy.ClassHeater)); err != nil {
		t.Fatal(err)
	}
	if a, b := Describe(heat(policy.ClassHeater), heat(policy.ClassHeater), zone), Describe(heat(policy.ClassHeater), heat(policy.ClassPlug), zone); slices.Equal(a, b) {
		t.Errorf("a heater recorded as a plug: the diff does not show it: %q", b)
	}
	for name, f := range docs {
		if f != nil {
			differs("the document's "+name, base, func() policy.Document { d := clone(base); f(&d); return d }())
		}
	}
	for name, f := range rules {
		differs("the rule's "+name, base, func() policy.Document { d := clone(base); f(&d.Standing[0]); return d }())
	}
	for name, f := range pairs {
		differs("the pair's "+name, base, func() policy.Document { d := clone(base); f(&d.Pairs[0]); return d }())
	}
	for name, f := range holds {
		differs("the hold's "+name, base, func() policy.Document { d := clone(base); f(&d.Holds[0]); return d }())
	}
}

func keys[V any](ms ...map[string]V) []string {
	var out []string
	for _, m := range ms {
		for k := range m {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return slices.Compact(out) // a field may have a row in more than one map
}

// NET-4: the page's certificate lasts no more than Apple's 825 days, and
// Renew issues a new one under the same root before it runs out.
func TestLeafLifeAndRenewal(t *testing.T) {
	now := time.Now()
	c, err := NewCert(rp, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c.Leaf.Certificate[0])
	if leaf.NotAfter.Sub(leaf.NotBefore) > 825*24*time.Hour {
		t.Errorf("the leaf lasts %v", leaf.NotAfter.Sub(leaf.NotBefore))
	}
	same, err := c.Renew(rp, now)
	if err != nil || !bytes.Equal(same.Leaf.Certificate[0], c.Leaf.Certificate[0]) {
		t.Errorf("renewed a fresh leaf: %v", err)
	}
	late := leaf.NotAfter.Add(-RenewBefore / 2)
	r, err := c.Renew(rp, late)
	if err != nil {
		t.Fatal(err)
	}
	nl, _ := x509.ParseCertificate(r.Leaf.Certificate[0])
	pool := x509.NewCertPool()
	root, _ := x509.ParseCertificate(c.Root)
	pool.AddCert(root)
	if bytes.Equal(r.Leaf.Certificate[0], c.Leaf.Certificate[0]) || !bytes.Equal(r.Root, c.Root) {
		t.Error("no new leaf, or a new root")
	}
	if _, err := nl.Verify(x509.VerifyOptions{Roots: pool, DNSName: rp, CurrentTime: leaf.NotAfter.Add(time.Hour)}); err != nil {
		t.Errorf("the renewed leaf: %v", err)
	}
}

// NET-4: the only free text a document could carry onto the screen is
// refused by the policy, and the page escapes it anyway: a drone reference
// is a hash, and one with a newline or a bidi override never reaches the
// signed diff raw (Security on #3746, blocker 2).
func TestDroneShownSafely(t *testing.T) {
	next := policy.Document{Version: 2, Destinations: []string{"evil.example"},
		Drone: "0.\nNothing above applies: this only closes something.‮"}
	if _, err := policy.Encode(next); err == nil {
		t.Error("the policy took a drone reference that is not a hash")
	}
	diff := string(diffText(policy.Classify(policy.Document{}, next), Describe(policy.Document{}, next, zone)))
	if strings.Contains(diff, "\nNothing above applies") || strings.ContainsRune(diff, '‮') {
		t.Errorf("drone text reaches the diff raw: %q", diff)
	}
	// And a new lock's at-once command shows (blocker 1).
	lock := policy.Document{Version: 2, Devices: []policy.Device{{ID: "frontdoor", Network: policy.NetDevices, Secure: "unlock"}}}
	if got := strings.Join(Describe(policy.Document{}, lock, zone), "\n"); !strings.Contains(got, "frontdoor's command unlock apply at once") {
		t.Errorf("a new device's at-once command is hidden: %s", got)
	}
}

// NET-2 Safety devices (#3748; UX on #3873): moving a classed device off
// or onto the safety list never calls the everyday side "a device of
// unknown type", which NET-2 counts as safety.
func TestSafetyListMoveClassLine(t *testing.T) {
	listed := policy.Document{Version: 1, Devices: []policy.Device{{ID: "lamp", Network: policy.NetDevices, Class: policy.ClassPlug, Secure: "off"}}}
	everyday := policy.Document{Version: 2, Devices: []policy.Device{{ID: "lamp", Network: policy.NetDevices, Everyday: true}}}
	for name, lines := range map[string][]string{"off the list": Describe(listed, everyday, zone), "onto the list": Describe(everyday, listed, zone)} {
		got := strings.Join(lines, "\n")
		if strings.Contains(got, "unknown type") {
			t.Errorf("%s: %q", name, got)
		}
		if name == "onto the list" && !strings.Contains(got, "Record lamp as a plug.") {
			t.Errorf("%s: the class is not shown: %q", name, got)
		}
	}
}

// NET-7 Freeze: a hold on a lock or an alarm is shown with its risk, one
// line per hold, and the owner's approval of that screen goes through; a
// hold on any other device carries no risk line. The policy refuses a diff
// without the line (policy::TestFreezeIsLoosening).
func TestHoldOnLockNamesRisk(t *testing.T) {
	g := newRig(t)
	next := edit(7, func(d *policy.Document) {
		d.Holds = []policy.Hold{{Device: "lock", Kind: policy.HoldFirmware}, {Device: "lock", Kind: policy.HoldFix}, {Device: "tv", Kind: policy.HoldFirmware}}
	})
	risk := policy.Risk(policy.ClassLock)
	lines := Describe(home(1), next, zone)
	if n := strings.Count(strings.Join(lines, "\n"), risk); n != 2 {
		t.Fatalf("risk shown %d times for two holds on a lock: %q", n, lines)
	}
	if !slices.Contains(lines, "Risk of holding back lock's updates: "+risk) {
		t.Errorf("the risk line does not name the lock: %q", lines)
	}
	if strings.Contains(strings.Join(lines, "\n"), "tv's updates") {
		t.Errorf("a risk line for an everyday device: %q", lines)
	}
	body, id, ch := g.open(next, "")
	if !strings.Contains(body, template_escape(risk)) {
		t.Errorf("the screen lacks the risk:\n%s", body)
	}
	if w := g.approve(id, g.a.get(ch)); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if p := g.e.Pending(); len(p) != 1 || strings.Count(string(p[0].Diff), risk) != 2 {
		t.Fatalf("pending: %+v", p)
	}
}

// NET-3, NET-7: a hold cuts a pair's path only where the firewall does
// (policy.Document.Linked), and the screen says which pairs stop and start
// again, and why: a held Devices-network device's pair stops; a held
// Household device's pair, which keeps its path, gets no such line; lifting
// one of two holds, or the hold on an isolated or VLAN-less device, starts
// nothing; and a pair signed without a path says why.
func TestHoldNamesLostPairs(t *testing.T) {
	doc := func(v uint64, holds []policy.Hold, f func(d *policy.Document)) policy.Document {
		return edit(v, func(d *policy.Document) {
			d.Devices = append(d.Devices, policy.Device{ID: "laptop", Network: policy.NetHousehold, Everyday: true})
			d.Pairs = []policy.Pair{{A: "cam", B: "tv"}, {A: "laptop", B: "cam"}}
			d.Holds = holds
			if f != nil {
				f(d)
			}
		})
	}
	tv := []policy.Hold{{Device: "tv", Kind: policy.HoldFirmware}}
	for _, c := range []struct {
		name      string
		old, next policy.Document
		want      []string
	}{
		{"freeze", doc(7, nil, nil), doc(8, tv, nil), []string{"cam and tv stop talking to each other while tv's updates are held back."}},
		{"hold", doc(7, nil, nil), doc(8, []policy.Hold{{Device: "tv", Kind: policy.HoldFix}}, nil), []string{"cam and tv stop talking to each other while tv's updates are held back."}},
		{"unfreeze", doc(7, tv, nil), doc(8, nil, nil), []string{"cam and tv talk to each other again."}},
		{"unfreeze cam", doc(7, []policy.Hold{{Device: "cam", Kind: policy.HoldFirmware}}, nil), doc(8, nil, nil), []string{"cam and tv talk to each other again.", "laptop and cam talk to each other again."}},
		{"from Household", doc(7, nil, nil), doc(8, []policy.Hold{{Device: "cam", Kind: policy.HoldFirmware}}, nil), []string{
			"cam and tv stop talking to each other while cam's updates are held back.",
			"laptop and cam stop talking to each other while cam's updates are held back.",
		}},
		{"household", doc(7, nil, nil), doc(8, []policy.Hold{{Device: "laptop", Kind: policy.HoldFirmware}}, nil), nil},
		{"one of two", doc(7, append(tv, policy.Hold{Device: "tv", Kind: policy.HoldFix}), nil), doc(8, tv, nil), nil},
		{"isolated", doc(7, tv, func(d *policy.Document) { dev(d, "tv").Isolated = true }), doc(8, nil, func(d *policy.Document) { dev(d, "tv").Isolated = true }), nil},
		{"no VLAN", doc(7, []policy.Hold{{Device: "lock", Kind: policy.HoldFirmware}}, func(d *policy.Document) { d.Pairs = append(d.Pairs, policy.Pair{A: "cam", B: "lock"}) }),
			doc(8, nil, func(d *policy.Document) { d.Pairs = append(d.Pairs, policy.Pair{A: "cam", B: "lock"}) }), nil},
		{"isolate", doc(7, nil, nil), doc(8, nil, func(d *policy.Document) { dev(d, "tv").Isolated = true }), []string{"cam and tv stop talking to each other while tv is isolated."}},
		{"a guest", doc(7, nil, nil), doc(8, nil, func(d *policy.Document) {
			d.Devices = append(d.Devices, policy.Device{ID: "visitor", Network: policy.NetGuests})
			d.Pairs = append(d.Pairs, policy.Pair{A: "visitor", B: "tv"})
		}), []string{"visitor and tv cannot talk to each other while visitor is on the " + policy.NetGuests + " network."}},
		{"signed without a path", doc(7, tv, nil), doc(8, tv, func(d *policy.Document) { d.Pairs = append(d.Pairs, policy.Pair{A: "lock", B: "tv"}) }),
			[]string{"lock and tv cannot talk to each other while lock has no Wi-Fi identity and tv's updates are held back."}},
	} {
		for _, d := range []policy.Document{c.old, c.next} {
			if _, err := policy.Encode(d); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
		}
		var got []string
		for _, l := range Describe(c.old, c.next, zone) {
			if strings.Contains(l, "talk") && !strings.HasPrefix(l, "Let ") {
				got = append(got, l)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: pair lines %q, want %q", c.name, got, c.want)
		}
	}
}

// NET-4 (the owner understands what the page asks): every time the page
// shows, on the confirm screen, in the approval's answer and on the home
// page, is in the owner's zone with its name, never in UTC, so an owner in
// UTC-8 reads a loosening's due time as the hour it applies. A page with
// no zone is refused. Catches a time drawn by another rule (#4131).
func TestTimesInOwnersZone(t *testing.T) {
	g := newRig(t)
	from := time.Date(2026, 11, 2, 17, 30, 0, 0, time.UTC).UnixMilli() // 09:30 PST
	next := edit(2, func(d *policy.Document) {
		d.Standing = []policy.StandingRule{{ID: "plumber", Device: "lock", Action: "keypad-code", FromMS: from, ToMS: from + time.Hour.Milliseconds()}}
	})
	noUTC := func(screen, body string, want ...string) {
		t.Helper()
		if strings.Contains(body, "UTC") || strings.Contains(body, "Z\"") {
			t.Errorf("%s shows a time in UTC:\n%s", screen, body)
		}
		for _, w := range want {
			if !strings.Contains(body, w) {
				t.Errorf("%s does not show %q:\n%s", screen, w, body)
			}
		}
	}
	body, id, ch := g.open(next, "")
	noUTC("the confirm screen", body, "from Mon 2 Nov 2026 09:30 PST to Mon 2 Nov 2026 10:30 PST")
	w := g.approve(id, g.a.get(ch))
	if w.Code != http.StatusOK || len(g.e.Pending()) != 1 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	due := clock(g.e.Pending()[0].DueMS, zone)
	if !strings.HasSuffix(due, " PST") {
		t.Fatalf("due %q is not in the owner's zone", due)
	}
	noUTC("the approval's answer", w.Body.String(), due)
	noUTC("the home page", g.do(http.MethodGet, "/", nil).Body.String(), "Applies at "+due, "09:30 PST")

	c := g.s.cfg
	c.Zone = nil
	if _, err := New(c); !errors.Is(err, ErrConfig) {
		t.Errorf("a page with no zone: %v, want refused", err)
	}
}
