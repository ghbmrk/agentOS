package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/channel"
	"github.com/ghbmrk/agentos/broker/enforcer/dns"
	"github.com/ghbmrk/agentos/broker/enforcer/enrol"
	"github.com/ghbmrk/agentos/broker/enforcer/mdns"
	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/traffic"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/enforcer/wol"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const (
	rp = "enforcer.home.arpa"
	// caseCode is a synthetic canary, never a real code.
	caseCode = "CANARY-CASE-CODE-AAAA-BBBB"
)

var (
	ownerAddr = netip.MustParseAddr("10.10.0.1")
	phoneAddr = netip.MustParseAddr("10.10.0.20")
	coreAddr  = netip.MustParseAddr("127.0.0.1") // the test's core dials over loopback
)

func testConfig(t *testing.T) Config {
	t.Helper()
	c := Config{
		Name: rp, Zone: "UTC",
		Layout: nft.Layout{
			WAN: "wan0", Owner: "own0", Household: "hh0", Guests: "gst0", Admin: "adm0",
			Core: "core0", Edge: "edge0", Trunk: "ap0", APMgmt: "apm0",
			APAdmin:     []netip.Addr{netip.MustParseAddr("10.70.0.2")},
			ISP:         []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			EdgeGateway: netip.MustParseAddr("10.60.0.1"),
			PagePort:    443, ChannelPort: 7443, CorePagePort: 443,
		},
		Page:      []netip.AddrPort{netip.AddrPortFrom(ownerAddr, 443)},
		PageAllow: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		Channel:   netip.AddrPortFrom(netip.MustParseAddr("10.50.0.1"), 7443),
		CoreAllow: []netip.Prefix{netip.PrefixFrom(coreAddr, 32)},
		Nft:       "/usr/sbin/nft",
		Dnsmasq:   "/usr/sbin/dnsmasq",
		DNS:       testDNS(),
	}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	return c
}

// testDNS serves the people's networks, the core's segment and the test
// policies' device VLANs (vlan101, vlan102).
func testDNS() dns.Setup {
	net := func(iface, p string) dns.Net {
		return dns.Net{Iface: iface, Prefix4: netip.MustParsePrefix(p), DHCP: true}
	}
	return dns.Setup{
		Upstream: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.53:53")},
		Nets: []dns.Net{net("own0", "10.10.0.0/24"), net("hh0", "10.20.0.0/24"), net("gst0", "10.30.0.0/24"),
			net("adm0", "10.40.0.0/24"), net("core0", "10.50.0.0/24"), net("ap0.101", "10.101.0.0/24"), net("ap0.102", "10.102.0.0/24")},
		LeaseFile: "/var/lib/agentos-enforcer/dhcp.leases",
	}
}

// authenticator is a fake ES256 passkey on rp with user verification.
type authenticator struct {
	t    *testing.T
	priv *ecdsa.PrivateKey
}

func newAuthenticator(t *testing.T) *authenticator {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{t: t, priv: p}
}

func (a *authenticator) Public() key.PublicKey {
	point, _ := a.priv.PublicKey.Bytes()
	pk, err := key.ES256(rp, point)
	if err != nil {
		a.t.Fatal(err)
	}
	return pk
}

func (a *authenticator) spki() string {
	der, err := x509.MarshalPKIXPublicKey(&a.priv.PublicKey)
	if err != nil {
		a.t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

// assertion is a tap over challenge (base64url, as the page serves it),
// in the page's JSON shape.
func (a *authenticator) assertion(id, challenge string) map[string]string {
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": "https://" + rp, "crossOrigin": false})
	ad, sig := a.signed(cd)
	e := base64.RawURLEncoding.EncodeToString
	return map[string]string{"id": id, "authenticator_data": e(ad), "client_data_json": e(cd), "signature": e(sig)}
}

// sign is a tap over msg in key.AssertionSig's encoding, as a package
// that checks a root signature takes it.
func (a *authenticator) sign(msg []byte) []byte {
	c := key.Challenge(msg)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(c[:]), "origin": "https://" + rp, "crossOrigin": false})
	ad, sig := a.signed(cd)
	b, err := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	if err != nil {
		a.t.Fatal(err)
	}
	return b
}

func (a *authenticator) signed(cd []byte) ([]byte, []byte) {
	h := sha256.Sum256([]byte(rp))
	ad := append(h[:], 0x01|0x04, 0, 0, 0, 0)
	cdh := sha256.Sum256(cd)
	m := sha256.Sum256(append(slices.Clone(ad), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, m[:])
	if err != nil {
		a.t.Fatal(err)
	}
	return ad, sig
}

// fakeFire is the nft loader: it keeps every ruleset loaded, with fail
// set refuses the next load as nft refuses a bad text, and with stall set
// hangs each load until its context ends, as a hung nft would.
type fakeFire struct {
	mu      sync.Mutex
	loads   []string
	updates []string
	fail    bool
	stall   bool
	listed  int
	// listing is what List returns: the running table as nft's JSON;
	// quotaErr fails QuotaPast.
	listing  []byte
	quotaErr error
	listErr  error
	// listAt, when set, answers the nth List (from 1) instead, when its
	// last result is true; quotaCtx and listCtx are the last contexts
	// QuotaPast and List were given.
	listAt   func(n int) ([]byte, error, bool)
	quotaCtx context.Context
	listCtx  context.Context
	// Each load's context, and the time it had left when the load began.
	ctxs []context.Context
	left []time.Duration
}

func (f *fakeFire) Load(ctx context.Context, s string) error {
	left := time.Duration(-1)
	if dl, ok := ctx.Deadline(); ok {
		left = time.Until(dl)
	}
	f.mu.Lock()
	stall := f.stall
	f.ctxs, f.left = append(f.ctxs, ctx), append(f.left, left)
	f.mu.Unlock()
	if stall {
		<-ctx.Done()
		return ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		f.fail = false
		return errors.New("nft: refused")
	}
	f.loads = append(f.loads, s)
	return nil
}

func (f *fakeFire) List(ctx context.Context, _ string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listed++
	f.listCtx = ctx
	if f.listAt != nil {
		if b, err, ok := f.listAt(f.listed); ok {
			return b, err
		}
	}
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listing, nil
}

func (f *fakeFire) Update(_ context.Context, s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, s)
	return nil
}

func (f *fakeFire) QuotaPast(ctx context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quotaCtx = ctx
	return f.quotaErr == nil, f.quotaErr
}

// fakeDNS is the resolver's instances: it records each Apply's files,
// and whether the load ran inside it, after the instances whose files
// change were stopped (dns/run's own tests check the processes).
type fakeDNS struct {
	mu      sync.Mutex
	applied []dns.Files
	inside  bool // a load ran inside Apply
	closed  int
}

func (f *fakeDNS) Apply(files dns.Files, load func() error) error {
	f.mu.Lock()
	f.inside = true
	f.mu.Unlock()
	err := load()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inside = false
	if err == nil {
		f.applied = append(f.applied, files)
	}
	return err
}

func (f *fakeDNS) Close() { f.mu.Lock(); f.closed++; f.mu.Unlock() }

func (f *fakeDNS) last() dns.Files {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applied) == 0 {
		return dns.Files{}
	}
	return f.applied[len(f.applied)-1]
}

// fakeMDNS is the pair relay: it records each plan it runs on and the
// filter it was given, and runs until stopped.
type fakeMDNS struct {
	mu      sync.Mutex
	plans   []mdns.Plan
	filters []*mdns.Filter
	active  int  // relays running
	fail    bool // the next relay ends at once
}

func (f *fakeMDNS) serve(ctx context.Context, p mdns.Plan, fl *mdns.Filter) error {
	f.mu.Lock()
	f.plans, f.filters = append(f.plans, p), append(f.filters, fl)
	if f.fail {
		f.fail = false
		f.mu.Unlock()
		return errors.New("mdns: socket refused")
	}
	f.active++
	f.mu.Unlock()
	<-ctx.Done()
	f.mu.Lock()
	f.active--
	f.mu.Unlock()
	return nil
}

func (f *fakeMDNS) last() (mdns.Plan, *mdns.Filter) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.plans) == 0 {
		return mdns.Plan{}, nil
	}
	return f.plans[len(f.plans)-1], f.filters[len(f.filters)-1]
}

func (f *fakeFire) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.loads) == 0 {
		return ""
	}
	return f.loads[len(f.loads)-1]
}

// fakeNetwork is the access point's side of enrolment: the setup
// network until Replace, then the Owner network's card.
type fakeNetwork struct {
	mu       sync.Mutex
	setup    bool
	replaced int
}

func (n *fakeNetwork) Replaced() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.replaced > 0
}

func (n *fakeNetwork) Replace() (enrol.Card, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.setup = false
	n.replaced++
	return enrol.Card{SSID: "Home", Shown: "CANA RYOW NERA AAAA", QR: "WIFI:T:WPA;S:Home;P:CANARYOWNERAAAA;;"}, nil
}

type fakeLight struct {
	mu sync.Mutex
	c  alert.Colour
}

func (l *fakeLight) Show(c alert.Colour) error { l.mu.Lock(); l.c = c; l.mu.Unlock(); return nil }

// box is one enforcer's disk, clocks and surroundings, across restarts.
type box struct {
	t     *testing.T
	dir   string
	cfg   Config
	fire  *fakeFire
	dns   *fakeDNS
	mdns  *fakeMDNS
	net   *fakeNetwork
	light *fakeLight
	core  ed25519.PrivateKey

	mu  sync.Mutex
	now time.Time
	el  time.Duration
	log []string
	// failing names the state files whose Save fails (fileStore.fault);
	// waits replaces the daemon's channel and firewall timeouts.
	failing map[string]bool
	// failNth names state files whose k-th Save from now fails alone
	// (failOn); saves counts the Saves since.
	failNth map[string]int
	saves   map[string]int
	waits   deps
	// offloads are the ports of each Offload call; offloadErr fails them.
	offloads   [][]string
	offloadErr error

	d *Enforcer
	b *browser
}

// newBox is a box at first boot: the image provisioned the case code
// and, with a core, pinned the kernel's channel sub-key.
func newBox(t *testing.T, withCore bool) *box {
	t.Helper()
	x := &box{t: t, dir: t.TempDir(), cfg: testConfig(t), fire: &fakeFire{}, dns: &fakeDNS{}, mdns: &fakeMDNS{}, net: &fakeNetwork{setup: true},
		light: &fakeLight{}, now: time.UnixMilli(1_800_000_000_000), el: time.Hour}
	if err := os.Chmod(x.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := enrol.Provision(fileStore{path: filepath.Join(x.dir, fileEnrol)}, caseCode, nil); err != nil {
		t.Fatal(err)
	}
	if withCore {
		_, x.core, _ = ed25519.GenerateKey(rand.Reader)
		pub := base64.StdEncoding.EncodeToString(x.core.Public().(ed25519.PublicKey))
		if err := (fileStore{path: filepath.Join(x.dir, fileCoreKey)}).Save([]byte(pub)); err != nil {
			t.Fatal(err)
		}
	}
	x.start()
	t.Cleanup(func() { x.d.Close() })
	return x
}

func (x *box) start() {
	x.t.Helper()
	d, err := x.open()
	if err != nil {
		x.t.Fatal(err)
	}
	x.d, x.b = d, &browser{x: x}
}

// open boots the daemon on this box's disk.
func (x *box) open() (*Enforcer, error) {
	dp := x.deps()
	dp.Logf = func(s string) { x.mu.Lock(); x.log = append(x.log, s); x.mu.Unlock() }
	dp.SaveFault = func(path string) error {
		x.mu.Lock()
		defer x.mu.Unlock()
		name := filepath.Base(path)
		if k := x.failNth[name]; k > 0 {
			if x.saves[name]++; x.saves[name] == k {
				return errors.New("disk: no space left")
			}
		}
		if x.failing[name] {
			return errors.New("disk: no space left")
		}
		return nil
	}
	dp.HelloWait, dp.IdleWait, dp.FireWait = x.waits.HelloWait, x.waits.IdleWait, x.waits.FireWait
	return open(x.cfg, x.dir, dp)
}

// deps is the box's pieces with its clocks and a silent log.
func (x *box) deps() deps {
	return deps{
		Now:     func() time.Time { x.mu.Lock(); defer x.mu.Unlock(); return x.now },
		Elapsed: func() time.Duration { x.mu.Lock(); defer x.mu.Unlock(); return x.el },
		Fire:    x.fire, Network: x.net, Light: x.light, Radio: noRadio{},
		Logf: func(string) {},
		DNS:  x.dns, MDNS: x.mdns.serve, Boot: func() (string, error) { return "boot-1", nil },
		Wake:    func(ctx context.Context, _ *wol.Relay) error { <-ctx.Done(); return nil },
		Offload: x.offload,
	}
}

// offload is the box's ports: it records each call's ports and fails
// while offloadErr is set.
func (x *box) offload(ports ...string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.offloads = append(x.offloads, slices.Clone(ports))
	return x.offloadErr
}

// fail makes Save of the state file name fail (on) or work again.
func (x *box) fail(name string, on bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.failing == nil {
		x.failing = map[string]bool{}
	}
	x.failing[name] = on
}

// failOn makes only the k-th Save of the state file name from now fail.
func (x *box) failOn(name string, k int) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.failNth == nil {
		x.failNth, x.saves = map[string]int{}, map[string]int{}
	}
	x.failNth[name], x.saves[name] = k, 0
}

// restart is a power loss and boot: nothing survives but the disk.
func (x *box) restart() {
	x.t.Helper()
	x.d.Close()
	x.start()
}

// advance moves both clocks on and runs the daemon's clock.
func (x *box) advance(d time.Duration) {
	x.mu.Lock()
	x.now, x.el = x.now.Add(d), x.el+d
	x.mu.Unlock()
	x.d.Tick(context.Background())
}

func (x *box) nowMS() int64 { x.mu.Lock(); defer x.mu.Unlock(); return x.now.UnixMilli() }

// current is the policy in force, read as the channel reads it.
func (x *box) current() policy.Document { return lockedPolicy{x.d}.Current() }

func (x *box) pending() []policy.Pending {
	x.d.mu.Lock()
	defer x.d.mu.Unlock()
	return x.d.engine.Pending()
}

// enforced is the ruleset the firewall last loaded, which must be the
// policy in force's.
func (x *box) enforced() string {
	x.t.Helper()
	want := x.fullLoad(x.current())
	got := x.fire.last()
	if got != want {
		x.t.Fatalf("the firewall holds a ruleset other than the policy in force's (version %d)", x.current().Version)
	}
	return got
}

// fullLoad is doc's full load on an empty running table: its ruleset and,
// in the same transaction, the byte caps' drop at no bytes sent.
func (x *box) fullLoad(doc policy.Document) string {
	x.t.Helper()
	text, err := nft.Reload(doc, x.cfg.Layout, nil)
	if err != nil {
		x.t.Fatal(err)
	}
	x.mu.Lock()
	now := x.now
	x.mu.Unlock()
	p := traffic.NewCounter(func() time.Time { return now }, traffic.CapsOf(doc)).Drop()
	p.Past = true
	drops, err := nft.Drops(doc, x.cfg.Layout, nil, p)
	if err != nil {
		x.t.Fatal(err)
	}
	return joinRules(text, drops)
}

func (x *box) opened(k alert.Kind) bool {
	return slices.ContainsFunc(x.d.alerts.Status().Open, func(r alert.Record) bool { return r.Kind == k })
}

func (x *box) logged(k alert.Kind) bool {
	return slices.ContainsFunc(x.d.alerts.Log(), func(r alert.Record) bool { return r.Kind == k })
}

// browser is the owner's phone on the Owner network, opening the page's
// own origin.
type browser struct {
	x             *box
	from          netip.Addr
	cookie, token string
	tokenOf       any
}

var (
	reToken = regexp.MustCompile(`<meta name="enforcer-token" content="([A-Za-z0-9_-]+)">`)
	reID    = regexp.MustCompile(`data-id="([0-9a-f]+)"`)
	reChal  = regexp.MustCompile(`data-challenge="([A-Za-z0-9_-]+)"`)
)

func (b *browser) do(method, path string, body any) *httptest.ResponseRecorder {
	t := b.x.t
	t.Helper()
	s := b.x.d.Page()
	if method != http.MethodGet && b.tokenOf != any(s) {
		b.do(http.MethodGet, "/enrol", nil) // any screen draws a token
		if b.tokenOf != any(s) {
			t.Fatal("no screen drew a token")
		}
	}
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req := httptest.NewRequest(method, "https://"+rp+path, rd)
	from := b.from
	if !from.IsValid() {
		from = phoneAddr
	}
	req.RemoteAddr = netip.AddrPortFrom(from, 50000).String()
	if method == http.MethodGet {
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	} else {
		req.Header.Set("Origin", "https://"+rp)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Cookie", "__Host-enforcer="+b.cookie)
		req.Header.Set("X-Enforcer-Token", b.token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-enforcer" {
			if m := reToken.FindStringSubmatch(w.Body.String()); m != nil {
				b.cookie, b.token, b.tokenOf = c.Value, m[1], any(s)
			}
		}
	}
	return w
}

func (b *browser) json(method, path string, body any, want int) map[string]any {
	t := b.x.t
	t.Helper()
	w := b.do(method, path, body)
	if w.Code != want {
		t.Fatalf("%s %s: %d, want %d: %s", method, path, w.Code, want, w.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

// enrol enrols a with code through the page's two enrolment steps.
func (b *browser) enrol(a *authenticator, code string) map[string]any {
	b.x.t.Helper()
	r := b.json(http.MethodPost, "/enrol/begin", map[string]string{"code": code, "public_key": a.spki()}, http.StatusOK)
	return b.json(http.MethodPost, "/enrol/finish", a.assertion(r["id"].(string), r["challenge"].(string)), http.StatusOK)
}

// link is the proposal link the core would text for next.
func link(next policy.Document) string {
	b, err := policy.Encode(next)
	if err != nil {
		panic(err)
	}
	return "/p?d=" + base64.RawURLEncoding.EncodeToString(b) + "&s=change"
}

// approve opens next's proposal link and taps it with a.
func (b *browser) approve(a *authenticator, next policy.Document) *httptest.ResponseRecorder {
	t := b.x.t
	t.Helper()
	w := b.do(http.MethodGet, link(next), nil)
	id, ch := reID.FindStringSubmatch(w.Body.String()), reChal.FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || id == nil || ch == nil {
		t.Fatalf("proposal screen: %d %s", w.Code, w.Body)
	}
	return b.do(http.MethodPost, "/approve", a.assertion(id[1], ch[1]))
}

// act taps a page action (cancel, resume) with a.
func (b *browser) act(a *authenticator, action, target string) *httptest.ResponseRecorder {
	b.x.t.Helper()
	r := b.json(http.MethodPost, "/challenge", map[string]string{"action": action, "target": target}, http.StatusOK)
	body := map[string]any{"action": action}
	for k, v := range a.assertion(r["id"].(string), r["challenge"].(string)) {
		body[k] = v
	}
	return b.do(http.MethodPost, "/act", body)
}

// home is a policy with one everyday device on the Devices network.
func home() policy.Document {
	return policy.Document{Devices: []policy.Device{{ID: "tv", Network: policy.NetDevices, WiFi: "vlan101", Everyday: true, Allow: []string{"tv.example"}}}}
}

// enrolled is a box with owner a enrolled through the page and home() in
// force after its wait.
func enrolled(t *testing.T, withCore bool) (*box, *authenticator) {
	x := newBox(t, withCore)
	a := newAuthenticator(t)
	x.b.enrol(a, caseCode)
	x.advance(time.Second)
	if w := x.b.approve(a, home()); w.Code != http.StatusOK {
		t.Fatalf("approve home: %d %s", w.Code, w.Body)
	}
	x.advance(time.Duration(policy.Wait) * time.Millisecond)
	if x.current().Device("tv") == nil {
		t.Fatal("home() not in force after its wait")
	}
	return x, a
}

// core is the kernel's end of the channel: a TLS client that sends the
// signed hello bound to the connection's exporter.
type core struct {
	t      *testing.T
	conn   *tls.Conn
	id     uint64
	alerts int
}

// serve runs the daemon's channel listener on loopback for this box.
func (x *box) serve() string {
	x.t.Helper()
	ln, err := net.Listen("tcp", netip.AddrPortFrom(coreAddr, 0).String())
	if err != nil {
		x.t.Fatal(err)
	}
	x.t.Cleanup(func() { ln.Close() })
	go func() {
		if err := x.d.ServeChannel(ln); !errors.Is(err, net.ErrClosed) {
			x.t.Errorf("the channel listener stopped: %v", err)
		}
	}()
	return ln.Addr().String()
}

// dial connects as the core with priv; ok reports whether the enforcer
// answered the hello with its own.
func (x *box) dial(addr string, priv ed25519.PrivateKey) (*core, bool) {
	x.t.Helper()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) // the hello authenticates
	if err != nil {
		x.t.Fatal(err)
	}
	cs := c.ConnectionState()
	exp, err := cs.ExportKeyingMaterial(wire.ExporterLabel, nil, wire.ExporterLen)
	if err != nil {
		x.t.Fatal(err)
	}
	cl := &core{t: x.t, conn: c}
	h, err := wire.SignHello(wire.RoleCore, priv, exp)
	if err != nil {
		x.t.Fatal(err)
	}
	cl.send(h)
	m, err := cl.recv()
	if err != nil {
		c.Close()
		return nil, false
	}
	eh, ok := m.(wire.Hello)
	enf, kerr := channelKey(fileStore{path: filepath.Join(x.dir, fileChannelKey)}, nil)
	if !ok || kerr != nil || eh.Verify(wire.RoleEnforcer, enf.Public().(ed25519.PublicKey), exp) != nil {
		x.t.Fatalf("the enforcer's hello does not verify: %T", m)
	}
	x.t.Cleanup(func() { c.Close() })
	return cl, true
}

func (c *core) send(m wire.Msg) {
	c.t.Helper()
	f, err := wire.Encode(wire.ToEnforcer, m)
	if err != nil {
		c.t.Fatal(err)
	}
	c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wire.WriteFrame(c.conn, wire.ToEnforcer, f); err != nil {
		c.t.Fatal(err)
	}
}

func (c *core) recv() (wire.Msg, error) {
	c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	f, err := wire.ReadFrame(c.conn, wire.ToCore)
	if err != nil {
		return nil, err
	}
	return wire.Decode(wire.ToCore, f)
}

// read asks for the policy export and returns the reply's code.
func (c *core) read() wire.Code {
	c.t.Helper()
	c.id++
	c.send(wire.Read{ID: c.id, What: wire.ReadExport})
	m, err := c.recv()
	for err == nil {
		if _, ok := m.(wire.Alert); !ok {
			break
		}
		c.alerts++ // a text the enforcer sent for the owner line
		m, err = c.recv()
	}
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	switch r := m.(type) {
	case wire.ReadReply:
		return wire.OK
	case wire.Result:
		return r.Code
	}
	c.t.Fatalf("reply %T", m)
	return 0
}

// TestLifecycle is the brief's lifecycle matrix (briefs/ENF.md, slice l),
// the rows ENF-l-a owns: each runs the whole daemon, its stores on disk,
// its page through HTTP and its channel through TLS, and restarts it
// where the row says power is lost. Catches pieces that pass alone and
// fail together.
func TestLifecycle(t *testing.T) {
	failSafeRows(t) // #4755: failsafe_test.go

	// First boot, factory state: only the enrolment page answers, and the
	// firewall holds default deny, the empty policy's ruleset.
	t.Run("first boot", func(t *testing.T) {
		x := newBox(t, false)
		if x.d.book.Phase() != enrol.Factory {
			t.Fatalf("phase %s", x.d.book.Phase())
		}
		if x.fire.last() != x.fullLoad(policy.Document{}) {
			t.Fatal("first boot did not load the empty policy's ruleset (default deny)")
		}
		if !x.net.setup {
			t.Fatal("the setup network went before any enrolment")
		}
		if w := x.b.do(http.MethodGet, "/enrol", nil); w.Code != http.StatusOK {
			t.Fatalf("enrolment screen: %d", w.Code)
		}
		if w := x.b.do(http.MethodGet, "/", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/enrol" {
			t.Fatalf("home before enrolment: %d %s", w.Code, w.Header().Get("Location"))
		}
		if w := x.b.do(http.MethodGet, link(home()), nil); w.Code != http.StatusForbidden {
			t.Fatalf("a proposal link before enrolment: %d", w.Code)
		}
		if w := x.b.do(http.MethodPost, "/approve", map[string]string{"id": "00"}); w.Code != http.StatusForbidden {
			t.Fatalf("an approval before enrolment: %d", w.Code)
		}
		// Another network gets no answer at all.
		x.b.from = netip.MustParseAddr("10.20.0.5")
		func() {
			defer func() {
				if recover() != http.ErrAbortHandler {
					t.Fatal("the page answered the Household network")
				}
			}()
			x.b.do(http.MethodGet, "/enrol", nil)
		}()
	})

	// Enrolment: the case code enrols the first passkey, the recovery
	// code is shown once, the setup network is replaced first, the owner
	// is texted, and the page rebuilt for the passkey takes its taps.
	t.Run("enrolment", func(t *testing.T) {
		x := newBox(t, false)
		a := newAuthenticator(t)
		bad := x.b.json(http.MethodPost, "/enrol/begin", map[string]string{"code": "CANARY-CASE-CODE-AAAA-BBBC", "public_key": a.spki()}, http.StatusForbidden)
		_ = bad
		res := x.b.enrol(a, caseCode)
		if res["recovery"] == "" || res["network"] == nil {
			t.Fatalf("enrolment answer: %v", res)
		}
		if x.net.setup || x.net.replaced != 1 {
			t.Fatal("the setup network was not replaced at enrolment")
		}
		if x.d.book.Phase() != enrol.Enrolled || x.d.book.Owner() != a.Public() {
			t.Fatal("the passkey is not in force")
		}
		if !x.logged(alert.Enrolment) {
			t.Fatal("no enrolment alert")
		}
		x.advance(time.Second)
		if w := x.b.do(http.MethodGet, "/", nil); w.Code != http.StatusOK {
			t.Fatalf("home after enrolment: %d", w.Code)
		}
		if w := x.b.approve(a, home()); w.Code != http.StatusOK {
			t.Fatalf("the page does not take the enrolled passkey's tap: %d %s", w.Code, w.Body)
		}
		x.restart()
		if x.d.book.Owner() != a.Public() || len(x.pending()) != 1 {
			t.Fatal("enrolment or its first proposal did not survive a restart")
		}
	})

	// Normal: version N is enforced and the channel is open. A loosening
	// reaches the firewall only after its wait; a closed-list tightening
	// over the channel reaches it at once.
	t.Run("normal", func(t *testing.T) {
		x, _ := enrolled(t, true)
		x.enforced()
		addr := x.serve()
		c, ok := x.dial(addr, x.core)
		if !ok {
			t.Fatal("the pinned core's hello was refused")
		}
		if c.read() != wire.OK {
			t.Fatal("the core's read of the export failed")
		}
		c.id++
		c.send(wire.Tighten{ID: c.id, Kind: wire.RemoveDevice, Device: "tv"})
		if m, err := c.recv(); err != nil || m.(wire.Result).Code != wire.OK {
			t.Fatalf("tightening: %v %v", m, err)
		}
		select {
		case <-x.d.changed:
		default:
			t.Fatal("a tightening did not kick the firewall")
		}
		x.d.Tick(context.Background())
		if x.current().Device("tv") != nil {
			t.Fatal("the tightening is not in force")
		}
		x.enforced()
		x.advance(time.Second)
		if x.page("Channel") != "open" {
			t.Fatal("the page does not show the channel open")
		}
	})

	// Loosening pending, then power loss: it survives with its original
	// deadline, a cancel still works, and nothing lands at the deadline.
	t.Run("loosening pending then power loss", func(t *testing.T) {
		x, a := enrolled(t, false)
		next := home()
		next.Devices = append(next.Devices, policy.Device{ID: "speaker", Network: policy.NetDevices, WiFi: "vlan102", Everyday: true})
		if w := x.b.approve(a, next); w.Code != http.StatusOK {
			t.Fatalf("approve: %d %s", w.Code, w.Body)
		}
		before := x.pending()
		if len(before) != 1 {
			t.Fatalf("pending: %v", before)
		}
		x.advance(time.Minute)
		x.restart()
		after := x.pending()
		if len(after) != 1 || after[0].ID != before[0].ID || after[0].DueMS != before[0].DueMS {
			t.Fatalf("pending after restart: %+v, before %+v", after, before)
		}
		if w := x.b.act(a, "cancel", after[0].ID); w.Code != http.StatusOK {
			t.Fatalf("cancel after restart: %d %s", w.Code, w.Body)
		}
		x.advance(time.Duration(policy.Wait) * time.Millisecond)
		if x.current().Device("speaker") != nil {
			t.Fatal("a cancelled loosening landed")
		}
		x.enforced()
	})

	// Core down or silent: the last signed policy stays enforced and the
	// page's status says the core is down; a hello brings it up.
	t.Run("core down", func(t *testing.T) {
		x, _ := enrolled(t, true)
		if !x.d.alerts.Status().CoreDown || x.page("Core") != "down" {
			t.Fatal("a core that never connected counts as up")
		}
		rules := x.enforced()
		c, _ := x.dial(x.serve(), x.core)
		c.read()
		x.advance(time.Second)
		if x.d.alerts.Status().CoreDown || x.page("Core") != "up" {
			t.Fatal("a connected core counts as down")
		}
		x.advance(Silence)
		if !x.d.alerts.Status().CoreDown || x.page("Core") != "down" {
			t.Fatal("a core silent for two beats counts as up")
		}
		if x.enforced() != rules || x.current().Device("tv") == nil {
			t.Fatal("a silent core changed the policy enforced")
		}
		x.restart()
		x.advance(time.Second)
		if !x.d.alerts.Status().CoreDown || x.page("Core") != "down" || x.enforced() != rules {
			t.Fatal("after a restart with the core silent the policy or the status changed")
		}
	})

	// Core reconnects inside Silence: an alert raised while no session was
	// open is offered to the next session that authenticates, though the
	// page never showed the core down (UX fix-list on #4754).
	t.Run("core reconnects", func(t *testing.T) {
		x, a := enrolled(t, true)
		addr := x.serve()
		c1, _ := x.dial(addr, x.core)
		c1.read()
		x.advance(time.Second)
		if x.d.alerts.Status().CoreDown {
			t.Fatal("a connected core counts as down")
		}
		c1.conn.Close()
		waitFor(t, func() bool { return x.d.conns.Load() == 0 }) // the enforcer saw the session end
		x.d.alerts.Raise(alert.HeadFork, "")
		if slices.ContainsFunc(x.d.alerts.Log(), func(r alert.Record) bool { return r.Kind == alert.HeadFork && r.Sent }) {
			t.Fatal("an alert counted as sent with no session open")
		}
		x.advance(time.Second)
		if x.d.alerts.Status().CoreDown {
			t.Fatal("a core gone for a second counts as down")
		}
		c2, _ := x.dial(addr, x.core)
		c2.read()
		c2.read()
		if c2.alerts == 0 {
			t.Fatal("the alert raised between sessions was never offered to the next one")
		}
		// The page is the record (#4750): it shows the alert until the
		// owner's passkey clears it there, and a stranger's cannot.
		words, _ := alert.Words(alert.HeadFork, "")
		if h := x.home(); !strings.Contains(h, html.EscapeString(words)) || !strings.Contains(h, `href="#revoke"`) {
			t.Fatal("the page does not show the open alert, or its choice to revoke the core's key")
		}
		var id string
		for _, r := range x.d.alerts.Status().Open {
			if r.Kind == alert.HeadFork {
				id = strconv.FormatUint(r.ID, 10)
			}
		}
		if w := x.b.act(newAuthenticator(t), "clear", id); w.Code == http.StatusOK || !x.opened(alert.HeadFork) {
			t.Fatal("a stranger's passkey cleared an alert")
		}
		if w := x.b.act(a, "clear", id); w.Code != http.StatusOK || x.opened(alert.HeadFork) {
			t.Fatalf("clear: %d %s", w.Code, w.Body)
		}
		if strings.Contains(x.home(), html.EscapeString(words)) {
			t.Fatal("the page still shows a cleared alert")
		}
	})

	// Channel burst: the core is cut, the channel paused, the light red;
	// a restart keeps it so, and only the page's passkey resume lifts it.
	t.Run("channel burst", func(t *testing.T) {
		x, a := enrolled(t, true)
		c, _ := x.dial(x.serve(), x.core)
		for range wire.Rate(wire.RateRead).Burst {
			if code := c.read(); code != wire.OK {
				t.Fatalf("a read inside the rate: %v", code)
			}
		}
		c.read() // past the rate: a burst
		waitFor(t, func() bool { return x.d.cut.Stage() == channel.Tripped })
		if code := c.read(); code != wire.Paused {
			t.Fatalf("a request after the trip: %v", code)
		}
		x.advance(time.Minute)
		if !x.opened(alert.ChannelPaused) || !x.opened(alert.Trip) || x.light.c != alert.Red || x.page("Light") != "red" {
			t.Fatalf("the trip does not show: %+v light %d", x.d.alerts.Status(), x.light.c)
		}
		for _, r := range x.d.alerts.Status().Open {
			// A paused channel's alert clears only by resuming (#4750).
			if clear := strings.Contains(x.home(), fmt.Sprintf(`data-action="clear" data-target="%d"`, r.ID)); clear == (r.Kind == alert.ChannelPaused) {
				t.Fatalf("alert %d (kind %d): clear offered %v", r.ID, r.Kind, clear)
			}
		}
		x.restart()
		x.advance(time.Second)
		if x.d.cut.Stage() != channel.Tripped || x.page("Channel") != "paused" {
			t.Fatal("a restart lifted the cut")
		}
		c, _ = x.dial(x.serve(), x.core)
		if code := c.read(); code != wire.Paused {
			t.Fatalf("a request after a restart while cut: %v", code)
		}
		if w := x.b.act(newAuthenticator(t), "resume", ""); w.Code == http.StatusOK {
			t.Fatal("a stranger's passkey resumed the channel")
		}
		if w := x.b.act(a, "resume", ""); w.Code != http.StatusOK {
			t.Fatalf("resume: %d %s", w.Code, w.Body)
		}
		x.advance(time.Minute)
		if x.d.cut.Stage() != channel.Open || x.opened(alert.ChannelPaused) || x.opened(alert.Trip) || x.light.c != alert.Off || x.page("Light") != "off" {
			t.Fatalf("the resume did not lift the cut: %+v", x.d.alerts.Status())
		}
		x.mu.Lock()
		x.el += time.Hour // the read bucket refills on the rate clock
		x.mu.Unlock()
		if code := c.read(); code != wire.OK {
			t.Fatalf("a request after the resume: %v", code)
		}
	})

	// Older policy offered: a version below the one in force is refused
	// without a fresh assertion; with one, it is a loosening and waits.
	t.Run("older policy offered", func(t *testing.T) {
		x, a := enrolled(t, false)
		v1 := x.current()
		old := policy.Proposal{Doc: v1, Diff: []byte("v1")}
		root, err := old.Root(a.Public())
		if err != nil {
			t.Fatal(err)
		}
		oldSig := a.sign(key.RootMsg(root))
		less := home()
		less.Devices = nil
		if w := x.b.approve(a, less); w.Code != http.StatusOK || len(x.pending()) != 0 {
			t.Fatalf("removing a device is a tightening, applied at once: %d %s", w.Code, w.Body)
		}
		x.advance(time.Second)
		if x.current().Device("tv") != nil {
			t.Fatal("the tightening is not in force")
		}
		x.enforced()
		x.d.mu.Lock()
		_, err = x.d.engine.Propose(old, oldSig, x.nowMS())
		x.d.mu.Unlock()
		if err == nil {
			t.Fatal("an older version was taken without a fresh assertion")
		}
		if w := x.b.approve(a, home()); w.Code != http.StatusOK || len(x.pending()) != 1 {
			t.Fatalf("the older policy with a fresh tap is not a waiting loosening: %d %s", w.Code, w.Body)
		}
		x.advance(time.Minute)
		if x.current().Device("tv") != nil {
			t.Fatal("the older policy landed before its wait")
		}
	})

	// Factory reset with the case code: the policy is kept and enforced,
	// and nothing loosens until a new passkey is enrolled and keeps it.
	t.Run("factory reset", func(t *testing.T) {
		x, a := enrolled(t, false)
		rules := x.enforced()
		x.b.json(http.MethodPost, "/enrol/reset", map[string]string{"code": caseCode}, http.StatusOK)
		x.advance(time.Second)
		if x.d.book.Phase() != enrol.Reset || x.enforced() != rules {
			t.Fatal("the reset changed the policy enforced")
		}
		if w := x.b.do(http.MethodGet, link(home()), nil); w.Code != http.StatusForbidden {
			t.Fatalf("a proposal after the reset: %d", w.Code)
		}
		next := home()
		next.Destinations = []string{"models.example"}
		x.d.mu.Lock()
		p := policy.Proposal{Doc: next, Diff: []byte("x")}
		p.Doc.Version = 9
		r, _ := p.Root(a.Public())
		_, err := x.d.engine.Propose(p, a.sign(key.RootMsg(r)), x.nowMS())
		x.d.mu.Unlock()
		if err == nil {
			t.Fatal("the old passkey loosened after the reset")
		}
		x.restart()
		b := newAuthenticator(t)
		x.b.enrol(b, caseCode)
		x.advance(time.Second)
		if x.d.book.Kept() {
			t.Fatal("the policy counts as kept before the new passkey signed it")
		}
		if w := x.b.act(b, "keep", ""); w.Code != http.StatusOK {
			t.Fatalf("keep: %d %s", w.Code, w.Body)
		}
		x.advance(time.Second)
		if x.current().Device("tv") == nil || !x.d.book.Kept() {
			t.Fatal("the policy was not kept under the new passkey")
		}
		x.enforced()
	})

	// Recovery code used: a replacement passkey only after the wait, with
	// a text and a page alert, and the old passkey stops at that point.
	t.Run("recovery code", func(t *testing.T) {
		x := newBox(t, false)
		a := newAuthenticator(t)
		res := x.b.enrol(a, caseCode)
		code := strings.ReplaceAll(res["recovery"].(string), " ", "")
		x.advance(time.Second)
		b := newAuthenticator(t)
		r := x.b.enrol(b, code)
		if r["due"] == nil {
			t.Fatalf("a recovery that does not wait: %v", r)
		}
		if !x.logged(alert.RecoveryCodeUsed) || !x.d.alerts.Status().Recovery {
			t.Fatal("the recovery is neither texted nor on the page")
		}
		if x.light.c != alert.Off {
			t.Fatal("a recovery lit the light")
		}
		x.restart()
		x.advance(time.Duration(policy.Wait)*time.Millisecond - time.Minute)
		if x.d.book.Owner() != a.Public() {
			t.Fatal("the replacement came into force before its wait")
		}
		x.advance(2 * time.Minute)
		if x.d.book.Owner() != b.Public() || x.d.alerts.Status().Recovery {
			t.Fatal("the replacement did not come into force after its wait")
		}
		if w := x.b.approve(a, home()); w.Code == http.StatusOK {
			t.Fatal("the replaced passkey still taps")
		}
		if w := x.b.approve(b, home()); w.Code != http.StatusOK {
			t.Fatalf("the page was not rebuilt for the replacement: %d %s", w.Code, w.Body)
		}
	})

	// Core key revoked (KEY-7, #4751): the owner revokes the core's
	// sub-key on the page, at home, without the core; the channel refuses
	// the revoked sub-key's hello and an open session's next frame, and
	// the head copies keep the revocation across a restart.
	t.Run("core key revoked", func(t *testing.T) {
		x, a := enrolled(t, true)
		addr := x.serve()
		open, ok := x.dial(addr, x.core)
		if !ok {
			t.Fatal("the pinned core was refused before any revocation")
		}
		if x.page("Key") != "live" {
			t.Fatal("the page offers no revocation")
		}
		if w := x.b.act(newAuthenticator(t), "revoke-core", ""); w.Code == http.StatusOK || x.d.heads.Revoked(x.core.Public().(ed25519.PublicKey)) {
			t.Fatal("a stranger's passkey revoked the core's sub-key")
		}
		if w := x.b.act(a, "revoke-core", ""); w.Code != http.StatusOK {
			t.Fatalf("revoke: %d %s", w.Code, w.Body)
		}
		if _, ok := x.dial(addr, x.core); ok {
			t.Fatal("the revoked sub-key's hello was answered")
		}
		open.id++
		open.send(wire.Read{ID: open.id, What: wire.ReadExport})
		for m, err := open.recv(); err == nil; m, err = open.recv() {
			if r, ok := m.(wire.ReadReply); ok {
				t.Fatalf("a session open before the revocation was still answered: %v", r)
			}
		}
		if x.page("Key") != "revoked" {
			t.Fatal("the page does not show the key revoked")
		}
		x.restart()
		if _, ok := x.dial(x.serve(), x.core); ok || x.page("Key") != "revoked" {
			t.Fatal("the revocation did not survive a restart")
		}
	})
}

// home is the page's home screen.
func (x *box) home() string {
	x.t.Helper()
	w := x.b.do(http.MethodGet, "/", nil)
	if w.Code != http.StatusOK {
		x.t.Fatalf("home: %d", w.Code)
	}
	return w.Body.String()
}

// page is one field of the page's home screen, read from its HTML.
func (x *box) page(field string) string {
	x.t.Helper()
	w := x.b.do(http.MethodGet, "/", nil)
	if w.Code != http.StatusOK {
		x.t.Fatalf("home: %d", w.Code)
	}
	body := w.Body.String()
	switch field {
	case "Channel":
		if m := regexp.MustCompile(`The channel is ([a-z ]+)\.`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case "Core":
		if strings.Contains(body, "The core is down") {
			return "down"
		}
		return "up"
	case "Light":
		if m := regexp.MustCompile(`The light is ([a-z]+)`).FindStringSubmatch(body); m != nil {
			return m[1]
		}
	case "Key":
		switch {
		case strings.Contains(body, "key is revoked"):
			return "revoked"
		case strings.Contains(body, `data-action="revoke-core"`):
			return "live"
		}
	}
	x.t.Fatalf("home shows no %s:\n%s", field, w.Body)
	return ""
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}
