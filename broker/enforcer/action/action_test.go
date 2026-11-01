package action_test

// REQ: NET-6, NET-4

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/action"
	"github.com/ghbmrk/agentos/broker/enforcer/channel"
	"github.com/ghbmrk/agentos/broker/enforcer/page"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const rp = "enforcer.home.arpa"

var (
	ownerAddr = netip.MustParseAddr("127.0.0.2")
	adminAddr = netip.MustParseAddr("127.0.0.3")
	others    = map[string]netip.Addr{
		"household": netip.MustParseAddr("127.0.0.4"), "guests": netip.MustParseAddr("127.0.0.5"),
		"devices": netip.MustParseAddr("127.0.0.6"), "core": netip.MustParseAddr("127.0.0.7"),
		"edge": netip.MustParseAddr("127.0.0.8"),
	}
)

// phone is the owner's passkey: it answers a get() as a browser on the
// enforcer's origin would.
type phone struct {
	t    *testing.T
	priv *ecdsa.PrivateKey
}

type wireAssertion struct {
	ID                string `json:"id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
}

func newPhone(t *testing.T) *phone {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &phone{t: t, priv: p}
}

func (p *phone) public() key.PublicKey {
	point, _ := p.priv.PublicKey.Bytes()
	pk, err := key.ES256(rp, point)
	if err != nil {
		p.t.Fatal(err)
	}
	return pk
}

// get signs challenge, base64url as the page serves it.
func (p *phone) get(challenge string) wireAssertion {
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": "https://" + rp, "crossOrigin": false})
	h := sha256.Sum256([]byte(rp))
	ad := append(h[:], 0x01|0x04, 0, 0, 0, 0)
	cdh := sha256.Sum256(cd)
	m := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.priv, m[:])
	if err != nil {
		p.t.Fatal(err)
	}
	e := base64.RawURLEncoding.EncodeToString
	return wireAssertion{AuthenticatorData: e(ad), ClientDataJSON: e(cd), Signature: e(sig)}
}

// sign is a tap over msg, in key.AssertionSig's form.
func (p *phone) sign(msg []byte) []byte {
	c := key.Challenge(msg)
	x := p.get(base64.RawURLEncoding.EncodeToString(c[:]))
	d := base64.RawURLEncoding.DecodeString
	ad, _ := d(x.AuthenticatorData)
	cd, _ := d(x.ClientDataJSON)
	sig, _ := d(x.Signature)
	b, err := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	if err != nil {
		p.t.Fatal(err)
	}
	return b
}

type done struct {
	device string
	act    action.Act
	route  string
}

// radio is the radio host or a driver behind it: it records what it was
// asked to do.
type radio struct{ did []done }

func (r *radio) Act(_ context.Context, device string, a action.Act, route string) error {
	r.did = append(r.did, done{device, a, route})
	return nil
}

var errRadio = errors.New("radio down")

type failing struct{}

func (failing) Act(context.Context, string, action.Act, string) error { return errRadio }

type memStore struct{ b []byte }

func (m *memStore) Load() ([]byte, error) { return m.b, nil }
func (m *memStore) Save(b []byte) error   { m.b = slices.Clone(b); return nil }

func safe(id, class, secure string) policy.Device {
	return policy.Device{ID: id, Network: policy.NetDevices, Class: class, Secure: secure}
}

// home is a house with one safety-list device of every class that takes
// an act, and an everyday plug.
func home() policy.Document {
	return policy.Document{
		Version: 1,
		Devices: []policy.Device{
			safe("heater", policy.ClassHeater, "off"),
			safe("boiler", policy.ClassPrimaryHeating, ""),
			safe("oven", policy.ClassOven, "off"),
			safe("plug", policy.ClassPlug, "off"),
			safe("relay", policy.ClassRelay, "off"),
			safe("valve", policy.ClassValve, "shut"),
			safe("sprinklers", policy.ClassFeedValve, ""),
			safe("garage", policy.ClassGarageDoor, "close"),
			safe("drone", policy.ClassDrone, "return-to-dock"),
			safe("door", policy.ClassLock, "lock"),
			safe("alarm", policy.ClassAlarm, ""),
			{ID: "cam", Network: policy.NetDevices, Allow: []string{"cam.example"}, VendorCloud: true, Class: policy.ClassCamera},
			safe("mic", policy.ClassMicrophone, ""),
			safe("siren", policy.ClassSiren, ""),
			safe("sensor", policy.ClassSensor, ""),
			{ID: "lamp", Network: policy.NetDevices, Everyday: true},
		},
	}
}

func device(d policy.Document, id string) policy.Device {
	if dev := d.Device(id); dev != nil {
		return *dev
	}
	panic(id)
}

func newBook(t *testing.T, p *phone) (*action.Book, *radio) {
	r := &radio{}
	b, err := action.NewBook(p.public(), r, 0)
	if err != nil {
		t.Fatal(err)
	}
	return b, r
}

// NET-6: every turn-on or open of a safety-list device runs only on the
// owner's assertion over a challenge naming that device, that action and
// an unexpired window, once. A second use, an assertion over another
// device's or action's challenge, an expired window, a forged or missing
// assertion, and a channel request are all refused, and nothing reaches
// the radio.
func TestTurnOnNeedsNamedOnceChallenge(t *testing.T) {
	rows := []struct {
		device string
		act    action.Act
		route  string
	}{
		{"heater", action.On, ""},
		{"boiler", action.On, ""},
		{"oven", action.On, ""},
		{"plug", action.On, ""},
		{"relay", action.On, ""},
		{"valve", action.Open, ""},
		{"sprinklers", action.Open, ""},
		{"garage", action.Open, ""},
		{"drone", action.Fly, "roof-survey"},
		{"door", action.Unlock, ""},
		{"alarm", action.Disarm, ""},
		{"cam", action.On, ""},
		{"mic", action.On, ""},
	}
	doc := home()
	for _, row := range rows {
		t.Run(row.device+"/"+string(row.act), func(t *testing.T) {
			p := newPhone(t)
			b, r := newBook(t, p)
			now := int64(1_000_000)

			// The challenge names the device, its class, the act, the
			// route and the window.
			c, err := b.Issue(doc, row.device, row.act, row.route, now)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{row.device, device(doc, row.device).Class, string(row.act), row.route, c.ID} {
				if !bytes.Contains(c.Msg, []byte(want)) {
					t.Fatalf("challenge %q does not name %q", c.Msg, want)
				}
			}
			if c.ExpiresMS != now+action.Window.Milliseconds() || action.Window > 5*time.Minute {
				t.Fatalf("window %d, want short", c.ExpiresMS-now)
			}

			// No assertion, or a forged one: refused, and the challenge
			// is spent.
			for _, sig := range [][]byte{nil, newPhone(t).sign(c.Msg)} {
				c, _ := b.Issue(doc, row.device, row.act, row.route, now)
				if _, err := b.Redeem(doc, c.ID, sig, now); !errors.Is(err, action.ErrNotOwner) {
					t.Fatalf("unsigned or forged: %v", err)
				}
				if _, err := b.Redeem(doc, c.ID, p.sign(c.Msg), now); !errors.Is(err, action.ErrGone) {
					t.Fatalf("a refused challenge is spent: %v", err)
				}
			}

			// An assertion over another device's or another act's
			// challenge does not redeem this one.
			other, err := b.Issue(doc, "plug", action.On, "", now)
			if row.device == "plug" {
				other, err = b.Issue(doc, "heater", action.On, "", now)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.Redeem(doc, c.ID, p.sign(other.Msg), now); !errors.Is(err, action.ErrNotOwner) {
				t.Fatalf("another device's assertion: %v", err)
			}
			if row.device == "alarm" {
				arm, _ := b.Issue(doc, "alarm", action.Arm, "", now)
				dis, _ := b.Issue(doc, "alarm", action.Disarm, "", now)
				if _, err := b.Redeem(doc, dis.ID, p.sign(arm.Msg), now); !errors.Is(err, action.ErrNotOwner) {
					t.Fatalf("another act's assertion: %v", err)
				}
			}

			// An expired window: refused.
			c, _ = b.Issue(doc, row.device, row.act, row.route, now)
			if _, err := b.Redeem(doc, c.ID, p.sign(c.Msg), c.ExpiresMS); !errors.Is(err, action.ErrGone) {
				t.Fatalf("expired: %v", err)
			}
			if len(r.did) != 0 {
				t.Fatalf("a refused challenge acted: %v", r.did)
			}

			// The owner's tap: done once, at once.
			c, _ = b.Issue(doc, row.device, row.act, row.route, now)
			if _, err := b.Redeem(doc, c.ID, p.sign(c.Msg), now+1); err != nil {
				t.Fatal(err)
			}
			if want := []done{{row.device, row.act, row.route}}; !slices.Equal(r.did, want) {
				t.Fatalf("did %v, want %v", r.did, want)
			}
			// A second use of the same tap: refused.
			if _, err := b.Redeem(doc, c.ID, p.sign(c.Msg), now+2); !errors.Is(err, action.ErrGone) {
				t.Fatalf("replay: %v", err)
			}
			if len(r.did) != 1 {
				t.Fatalf("replayed: %v", r.did)
			}

			// The channel carries no turn-on or open to a safety-list
			// device: at most its one named secure direction.
			dev := device(doc, row.device)
			for v := wire.VerbOn; v <= wire.VerbReturnToDock; v++ {
				if channel.Allowed(dev, v) && v != secureVerb[dev.Secure] {
					t.Fatalf("the channel carries verb %d to %s", v, row.device)
				}
			}
			if channel.Allowed(dev, wire.VerbOn) {
				t.Fatalf("the channel turns on %s", row.device)
			}
		})
	}

	// A device that does not take the act, or a malformed challenge, gets
	// no challenge at all.
	p := newPhone(t)
	b, _ := newBook(t, p)
	refused := []struct {
		device string
		act    action.Act
		route  string
	}{
		{"heater", action.Open, ""}, {"door", action.On, ""}, {"valve", action.On, ""},
		{"siren", action.On, ""}, {"sensor", action.On, ""}, {"lamp", action.On, ""},
		{"nobody", action.On, ""}, {"drone", action.Fly, ""}, {"heater", action.On, "route"},
		{"heater", "explode", ""},
	}
	for _, r := range refused {
		if _, err := b.Issue(home(), r.device, r.act, r.route, 0); err == nil {
			t.Errorf("challenge issued for %q %q %q", r.device, r.act, r.route)
		}
	}

	// Names are short printable ASCII with no space or separator, so no
	// field of the signed message can forge another; the edges are held.
	named := home()
	for _, id := range []string{strings.Repeat("h", 64), "heater~2", "a!"} {
		named.Devices = append(named.Devices, safe(id, policy.ClassHeater, "off"))
	}
	for _, id := range []string{strings.Repeat("h", 64), "heater~2", "a!"} {
		if _, err := b.Issue(named, id, action.On, "", 0); err != nil {
			t.Errorf("%q refused: %v", id, err)
		}
	}
	for _, id := range []string{strings.Repeat("h", 65), "heat er", "heat\x00er", "heat\x7fer", "h\u00e9", ""} {
		if _, err := b.Issue(named, id, action.On, "", 0); !errors.Is(err, action.ErrMalformed) {
			t.Errorf("%q: %v, want malformed", id, err)
		}
		if _, err := b.Issue(named, "drone", action.Fly, id, 0); !errors.Is(err, action.ErrMalformed) {
			t.Errorf("route %q: %v, want malformed", id, err)
		}
	}

	// The radio failing: the tap is spent and the failure reported as an
	// act that may have run, naming the challenge.
	fb, err := action.NewBook(p.public(), failing{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := fb.Issue(home(), "heater", action.On, "", 0)
	if got, err := fb.Redeem(home(), c.ID, p.sign(c.Msg), 1); !errors.Is(err, errRadio) || !errors.Is(err, action.ErrUnsure) || got.ID != c.ID {
		t.Fatalf("radio failure: %v, %+v", err, got)
	}
	if _, err := fb.Redeem(home(), c.ID, p.sign(c.Msg), 1); !errors.Is(err, action.ErrGone) {
		t.Fatalf("after a radio failure: %v", err)
	}

	// The links name the act, and only Fly carries a route.
	if l := action.Link(rp, "drone", action.Fly, "roof"); l != "https://"+rp+"/a?a=fly&d=drone&r=roof" {
		t.Errorf("fly link %s", l)
	}
	if l := action.Link(rp, "heater", action.On, ""); l != "https://"+rp+"/a?a=on&d=heater" {
		t.Errorf("on link %s", l)
	}

	// A device isolated, removed or reclassified after its challenge was
	// drawn: the tap is refused.
	for name, change := range map[string]func(d *policy.Document){
		"isolated":     func(d *policy.Document) { d.Devices[0].Isolated = true },
		"removed":      func(d *policy.Document) { d.Devices = d.Devices[1:] },
		"reclassified": func(d *policy.Document) { d.Devices[0].Class = policy.ClassOven },
		"everyday": func(d *policy.Document) {
			d.Devices[0].Everyday, d.Devices[0].Class, d.Devices[0].Secure = true, "", ""
		},
	} {
		b, r := newBook(t, p)
		c, _ := b.Issue(home(), "heater", action.On, "", 0)
		d := home()
		change(&d)
		if _, err := b.Redeem(d, c.ID, p.sign(c.Msg), 1); !errors.Is(err, action.ErrMoved) || len(r.did) != 0 {
			t.Errorf("%s: %v %v", name, err, r.did)
		}
	}

	// The book holds at most MaxLive challenges.
	b, _ = newBook(t, p)
	for i := 0; i < action.MaxLive; i++ {
		if _, err := b.Issue(home(), "heater", action.On, "", 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Issue(home(), "heater", action.On, "", 0); !errors.Is(err, action.ErrLimited) {
		t.Fatalf("over MaxLive: %v", err)
	}
	if _, err := b.Issue(home(), "heater", action.On, "", action.Window.Milliseconds()); err != nil {
		t.Fatalf("expired challenges are dropped: %v", err)
	}
}

var secureVerb = map[string]wire.Verb{
	channel.SecureLock: wire.VerbLock, channel.SecureShut: wire.VerbShut, channel.SecureOff: wire.VerbOff,
	channel.SecureClose: wire.VerbClose, channel.SecureReturn: wire.VerbReturnToDock,
}

// rig is the enforcer's page over a policy engine holding home(), with
// the book's actuator recording what it was asked to do.
type rig struct {
	t      *testing.T
	p      *phone
	e      *policy.Engine
	r      *radio
	s      *page.Server
	logs   []string
	now    time.Time
	remote netip.Addr
	// The phone browser's anti-forgery cookie and token from the last
	// screen the page drew; do posts with them.
	cookie, token string
}

func newRig(t *testing.T) *rig { t.Helper(); return newRigWith(t, nil) }

// newRigWith is newRig with cfg changed by set before the page is made.
func newRigWith(t *testing.T, set func(*page.Config)) *rig {
	t.Helper()
	p := newPhone(t)
	e, err := policy.Open(p.public(), &memStore{})
	if err != nil {
		t.Fatal(err)
	}
	prop := policy.Proposal{Doc: home(), Diff: []byte("v1")}
	root, _ := prop.Root(p.public())
	if _, err := e.Propose(prop, p.sign(key.RootMsg(root)), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Tick(policy.Wait); err != nil {
		t.Fatal(err)
	}
	g := &rig{t: t, p: p, e: e, r: &radio{}, now: time.Now(), remote: ownerAddr}
	cert, err := page.NewCert(rp, g.now)
	if err != nil {
		t.Fatal(err)
	}
	cfg := page.Config{
		Name: rp, Owner: p.public(),
		Addrs:  []netip.AddrPort{netip.AddrPortFrom(ownerAddr, 443), netip.AddrPortFrom(adminAddr, 443)},
		Allow:  []netip.Prefix{netip.PrefixFrom(ownerAddr, 32), netip.PrefixFrom(adminAddr, 32)},
		Policy: e, Act: g.r, Cert: cert.Leaf, Zone: time.UTC,
		Log: func(l string) { g.logs = append(g.logs, l) },
		Now: func() time.Time { return g.now },
	}
	if set != nil {
		set(&cfg)
	}
	g.s, err = page.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// do sends one request as the phone's browser on the page's origin would,
// from g.remote. aborted reports a request the page dropped unanswered.
func (g *rig) do(method, path string, body any) (w *httptest.ResponseRecorder, aborted bool) {
	g.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "https://"+rp+strings.TrimPrefix(path, "https://"+rp), rd)
	req.RemoteAddr = netip.AddrPortFrom(g.remote, 50000).String()
	if method == http.MethodPost {
		req.Header.Set("Origin", "https://"+rp)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Cookie", "__Host-enforcer="+g.cookie)
		req.Header.Set("X-Enforcer-Token", g.token)
	} else {
		req.Header.Set("Sec-Fetch-Site", "cross-site") // opened from a text
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	}
	w = httptest.NewRecorder()
	defer func() {
		if v := recover(); v != nil {
			if v != http.ErrAbortHandler {
				panic(v)
			}
			aborted = true
		}
	}()
	g.s.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if m := reToken.FindStringSubmatch(w.Body.String()); c.Name == "__Host-enforcer" && m != nil {
			g.cookie, g.token = c.Value, m[1]
		}
	}
	return w, false
}

var (
	reID    = regexp.MustCompile(`data-id="([0-9a-f]+)"`)
	reChal  = regexp.MustCompile(`data-challenge="([A-Za-z0-9_-]+)"`)
	reToken = regexp.MustCompile(`<meta name="enforcer-token" content="([A-Za-z0-9_-]+)">`)
)

// open opens a link and returns the screen, its challenge ID and the
// challenge.
func (g *rig) open(link string) (string, string, string) {
	g.t.Helper()
	w, aborted := g.do(http.MethodGet, link, nil)
	if aborted || w.Code != http.StatusOK {
		g.t.Fatalf("open %s: %d %s", link, w.Code, w.Body)
	}
	body := w.Body.String()
	id, ch := reID.FindStringSubmatch(body), reChal.FindStringSubmatch(body)
	if id == nil || ch == nil {
		g.t.Fatalf("no challenge on the screen:\n%s", body)
	}
	return body, id[1], ch[1]
}

// tap is the owner's tap on a screen's challenge, posted to path.
func (g *rig) tap(path, id, challenge string, p *phone) *httptest.ResponseRecorder {
	a := p.get(challenge)
	a.ID = id
	w, aborted := g.do(http.MethodPost, path, a)
	if aborted {
		g.t.Fatalf("%s aborted", path)
	}
	return w
}

// NET-4: the asserted tightenings of a safety-list device (cutting its
// vendor cloud, isolating it, removing it) and the device commands NET-4
// puts beside them (turning a camera off, arming an alarm) apply only with
// the owner's assertion, and then at once, with no 10-minute wait. The
// channel's request for one is refused and becomes a link the page renders
// itself. Locking and relocking need no assertion.
func TestSafetyTighteningNeedsAssertion(t *testing.T) {
	for _, kind := range []string{policy.CutVendorCloud, policy.IsolateDevice, policy.RemoveDevice} {
		t.Run(kind, func(t *testing.T) {
			g := newRig(t)
			op := policy.Op{Kind: kind, Device: "cam"}
			before := g.e.Current()
			// The channel's path: refused, needs the owner.
			if err := g.e.Tighten(op, 0); !errors.Is(err, policy.ErrNeedsOwner) {
				t.Fatalf("channel tightening: %v", err)
			}
			link, err := action.TighteningLink(rp, g.e.Current(), op)
			if err != nil {
				t.Fatal(err)
			}
			body, id, ch := g.open(link)
			if !strings.Contains(body, "applies as soon as you approve") || !strings.Contains(body, "cam") {
				t.Fatalf("screen does not say it applies at once on cam:\n%s", body)
			}
			// A tap by another passkey: refused, nothing changes.
			if w := g.tap("/approve", id, ch, newPhone(t)); w.Code != http.StatusForbidden {
				t.Fatalf("forged tap: %d %s", w.Code, w.Body)
			}
			if a, b := mustEncode(t, g.e.Current()), mustEncode(t, before); !bytes.Equal(a, b) {
				t.Fatal("a refused tap changed the policy")
			}
			// The owner's tap: applied at once, nothing pending.
			_, id, ch = g.open(link)
			w := g.tap("/approve", id, ch, g.p)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"applied":true`) {
				t.Fatalf("owner's tap: %d %s", w.Code, w.Body)
			}
			if len(g.e.Pending()) != 0 {
				t.Fatal("an asserted tightening waits")
			}
			want, _ := policy.Apply(before, op)
			want.Version = g.e.Current().Version
			if a, b := mustEncode(t, g.e.Current()), mustEncode(t, want); !bytes.Equal(a, b) {
				t.Fatalf("applied %s, want %s", a, b)
			}
		})
	}

	for _, c := range []struct {
		device string
		act    action.Act
	}{{"cam", action.Off}, {"mic", action.Off}, {"alarm", action.Arm}} {
		t.Run(c.device+"/"+string(c.act), func(t *testing.T) {
			g := newRig(t)
			// The channel carries no such command.
			for v := wire.VerbOn; v <= wire.VerbReturnToDock; v++ {
				if channel.Allowed(device(g.e.Current(), c.device), v) {
					t.Fatalf("the channel carries verb %d to %s", v, c.device)
				}
			}
			link := action.Link(rp, c.device, c.act, "")
			body, id, ch := g.open(link)
			if !strings.Contains(body, c.device) || !strings.Contains(body, "stop the device") {
				t.Fatalf("screen:\n%s", body)
			}
			if w := g.tap("/do", id, ch, newPhone(t)); w.Code != http.StatusForbidden || len(g.r.did) != 0 {
				t.Fatalf("forged tap: %d %s %v", w.Code, w.Body, g.r.did)
			}
			_, id, ch = g.open(link)
			if w := g.tap("/do", id, ch, g.p); w.Code != http.StatusOK {
				t.Fatalf("owner's tap: %d %s", w.Code, w.Body)
			}
			if want := []done{{c.device, c.act, ""}}; !slices.Equal(g.r.did, want) {
				t.Fatalf("did %v, want %v", g.r.did, want)
			}
			if w := g.tap("/do", id, ch, g.p); w.Code != http.StatusGone || len(g.r.did) != 1 {
				t.Fatalf("replay: %d %v", w.Code, g.r.did)
			}
		})
	}

	// Locking and relocking: no assertion, at once, through the channel.
	g := newRig(t)
	door := device(g.e.Current(), "door")
	if !channel.Allowed(door, wire.VerbLock) {
		t.Fatal("the channel does not carry the door's lock")
	}
	for i := 0; i < 2; i++ {
		if err := g.e.Secure("door", "lock", int64(i)); err != nil {
			t.Fatalf("lock %d: %v", i, err)
		}
	}
	if _, err := newBookOrFail(t, g.p).Issue(g.e.Current(), "door", "lock", "", 0); err == nil {
		t.Fatal("locking is not a challenge")
	}
}

func newBookOrFail(t *testing.T, p *phone) *action.Book {
	b, _ := newBook(t, p)
	return b
}

func mustEncode(t *testing.T, d policy.Document) []byte {
	b, err := policy.Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// NET-6: the action routes answer only the Owner network and the wired
// admin port. From Household, Guests, Devices, the core's or the edge's
// segment, opening an action link or posting a tap is dropped unanswered
// and nothing acts; the page refuses to listen anywhere else (New).
func TestServedOnlyAtHome(t *testing.T) {
	g := newRig(t)
	link := action.Link(rp, "heater", action.On, "")
	for _, at := range []netip.Addr{ownerAddr, adminAddr} {
		g.remote = at
		_, id, ch := g.open(link)
		if w := g.tap("/do", id, ch, g.p); w.Code != http.StatusOK {
			t.Fatalf("from %v: %d %s", at, w.Code, w.Body)
		}
	}
	if len(g.r.did) != 2 {
		t.Fatalf("did %v", g.r.did)
	}

	g.remote = ownerAddr
	_, id, ch := g.open(link)
	for name, at := range others {
		g.remote = at
		if w, aborted := g.do(http.MethodGet, link, nil); !aborted {
			t.Errorf("%s opened an action link: %d", name, w.Code)
		}
		a := g.p.get(ch)
		a.ID = id
		if w, aborted := g.do(http.MethodPost, "/do", a); !aborted {
			t.Errorf("%s posted a tap: %d", name, w.Code)
		}
	}
	if len(g.r.did) != 2 {
		t.Fatalf("a tap from away acted: %v", g.r.did)
	}
	// The challenge was never reached from away, so the owner's tap at
	// home still works once.
	g.remote = ownerAddr
	if w := g.tap("/do", id, ch, g.p); w.Code != http.StatusOK {
		t.Fatalf("owner at home: %d %s", w.Code, w.Body)
	}

	for name, at := range others {
		_, err := page.New(page.Config{
			Name: rp, Owner: g.p.public(), Policy: g.e, Act: g.r, Zone: time.UTC, Log: func(string) {},
			Addrs: []netip.AddrPort{netip.AddrPortFrom(at, 443)},
			Allow: []netip.Prefix{netip.PrefixFrom(ownerAddr, 32), netip.PrefixFrom(adminAddr, 32)},
		})
		if !errors.Is(err, page.ErrConfig) {
			t.Errorf("page listens on %s: %v", name, err)
		}
	}
}

// NET-4: the action screen tells the owner what to do. It names the
// window as a length, never as a clock time in a zone the owner must
// convert, and every refusal of a tap says what to do next.
func TestActionScreenWording(t *testing.T) {
	g := newRig(t)
	link := action.Link(rp, "heater", action.On, "")
	body, id, ch := g.open(link)
	if !strings.Contains(body, "within 2 minutes") {
		t.Fatalf("the screen does not name the window:\n%s", body)
	}
	if regexp.MustCompile(`UTC|\d\d:\d\d`).MatchString(body) {
		t.Fatalf("the screen shows a clock time:\n%s", body)
	}

	nextStep := func(w *httptest.ResponseRecorder, code int, words ...string) {
		t.Helper()
		var res struct{ Error string }
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || w.Code != code {
			t.Fatalf("%d %s, want %d", w.Code, w.Body, code)
		}
		for _, want := range words {
			if !strings.Contains(res.Error, want) {
				t.Errorf("%q does not say %q", res.Error, want)
			}
		}
	}
	// Another passkey: refused, and told to open the link and approve
	// with the passkey.
	nextStep(g.tap("/do", id, ch, newPhone(t)), http.StatusForbidden, "open the link again", "approve with your passkey")
	// The same challenge again: spent, and told to open the link again.
	nextStep(g.tap("/do", id, ch, g.p), http.StatusGone, "open the link again")
	// The device changed under the screen: told to open the link again
	// (the book's own test holds when it is returned).
	if !strings.Contains(action.ErrMoved.Error(), "open the link again") {
		t.Errorf("%q has no next step", action.ErrMoved)
	}
	if len(g.r.did) != 0 {
		t.Fatalf("a refused tap acted: %v", g.r.did)
	}
}

// NET-6: opening action links and proposal links are limited on separate
// counts, so a flood of either from the Owner network cannot delay the
// other's approval.
func TestActionLinkLimitIsItsOwn(t *testing.T) {
	g := newRig(t)
	plink, err := action.TighteningLink(rp, g.e.Current(), policy.Op{Kind: policy.CutVendorCloud, Device: "cam"})
	if err != nil {
		t.Fatal(err)
	}
	alink := action.Link(rp, "heater", action.On, "")
	flood := func(link string) {
		t.Helper()
		for i := 0; ; i++ {
			w, _ := g.do(http.MethodGet, link, nil)
			if w.Code == http.StatusTooManyRequests {
				if i != page.LinkLimit {
					t.Fatalf("%s limited after %d, want %d", link, i, page.LinkLimit)
				}
				return
			}
			if w.Code != http.StatusOK || i > page.LinkLimit {
				t.Fatalf("%s: %d %s", link, w.Code, w.Body)
			}
		}
	}
	flood(plink)
	_, id, ch := g.open(alink) // proposal links spent: an action still opens
	if w := g.tap("/do", id, ch, g.p); w.Code != http.StatusOK {
		t.Fatalf("tap: %d %s", w.Code, w.Body)
	}

	g.now = g.now.Add(page.LinkWindow)
	flood(alink)
	g.open(plink) // action links spent: a proposal still opens
}

// hung is an actuator that does not answer until released.
type hung struct{ release chan struct{} }

func (h hung) Act(context.Context, string, action.Act, string) error { <-h.release; return nil }

type panicking struct{}

func (panicking) Act(context.Context, string, action.Act, string) error { panic("driver bug") }

// NET-6: a hung actuator does not hold the policy lock, which the
// channel's relocks share, past the book's timeout; the tap is reported as
// not answered, with what to do next. The bound can only be tightened, and
// a panicking actuator is a failed act, not a crash.
func TestHungActuatorReleasesLock(t *testing.T) {
	h := hung{make(chan struct{})}
	defer close(h.release)
	var mu sync.Mutex
	const bound = 50 * time.Millisecond
	g := newRigWith(t, func(c *page.Config) { c.Act, c.Lock, c.ActTimeout = h, &mu, bound })
	_, id, ch := g.open(action.Link(rp, "door", action.Unlock, ""))
	tapped := make(chan *httptest.ResponseRecorder, 1)
	go func() { tapped <- g.tap("/do", id, ch, g.p) }()
	var w *httptest.ResponseRecorder
	select {
	case w = <-tapped:
	case <-time.After(bound + 2*time.Second):
		t.Fatal("the tap is still waiting on the hung actuator")
	}
	if w.Code != http.StatusGatewayTimeout || !strings.Contains(w.Body.String(), "check the device") {
		t.Fatalf("hung: %d %s", w.Code, w.Body)
	}
	if !mu.TryLock() {
		t.Fatal("the policy lock is still held after the timeout")
	}
	mu.Unlock()

	p := newPhone(t)
	for _, d := range []time.Duration{-time.Second, action.Timeout + time.Nanosecond} {
		if _, err := action.NewBook(p.public(), &radio{}, d); err == nil {
			t.Errorf("timeout %v accepted", d)
		}
	}
	if _, err := action.NewBook(p.public(), &radio{}, action.Timeout); err != nil {
		t.Errorf("timeout %v refused: %v", action.Timeout, err)
	}

	b, err := action.NewBook(p.public(), panicking{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := b.Issue(home(), "heater", action.On, "", 0)
	if _, err := b.Redeem(home(), c.ID, p.sign(c.Msg), 1); err == nil {
		t.Fatal("a panicking actuator reported done")
	}
}

// NET-6, NET-2 alerts: a tap whose act timed out, failed or panicked may
// still have reached the device, so the page tells the owner to check the
// device, never that it did nothing, and writes one line to the
// enforcer's log naming the act and the device. A page that acts with no
// log is refused. Catches a panic after the send reported as "did not do
// it" (#4138, items 2 and 3).
func TestUnsureActIsLoggedAndSaysCheck(t *testing.T) {
	h := hung{make(chan struct{})}
	defer close(h.release)
	for name, act := range map[string]action.Actuator{"hung": h, "failing": failing{}, "panicking": panicking{}} {
		g := newRigWith(t, func(c *page.Config) { c.Act, c.ActTimeout = act, 20*time.Millisecond })
		_, id, ch := g.open(action.Link(rp, "door", action.Unlock, ""))
		w := g.tap("/do", id, ch, g.p)
		if w.Code == http.StatusOK || !strings.Contains(w.Body.String(), "may still do it; check the device") || strings.Contains(w.Body.String(), "did not do it") {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		if len(g.logs) != 1 || !strings.HasPrefix(g.logs[0], "action: unlock on door may have run: ") || strings.Contains(g.logs[0], "\n") {
			t.Errorf("%s: logged %q", name, g.logs)
		}
	}
	g := newRig(t)
	_, id, ch := g.open(action.Link(rp, "heater", action.On, ""))
	if w := g.tap("/do", id, ch, g.p); w.Code != http.StatusOK || len(g.logs) != 0 {
		t.Errorf("a done act: %d, logged %q", w.Code, g.logs)
	}
	_, err := page.New(page.Config{
		Name: rp, Owner: g.p.public(), Policy: g.e, Act: g.r, Zone: time.UTC,
		Addrs: []netip.AddrPort{netip.AddrPortFrom(ownerAddr, 443)},
		Allow: []netip.Prefix{netip.PrefixFrom(ownerAddr, 32)},
	})
	if !errors.Is(err, page.ErrConfig) {
		t.Errorf("a page that acts with no log: %v, want refused", err)
	}
}

// link is one device's ordered link, kept as the Actuator contract asks:
// it checks ctx and sends in one step under the lock that orders its
// writes. sent is what reached the device, in order.
type link struct {
	mu   sync.Mutex
	sent []string
}

func (l *link) Act(ctx context.Context, _ string, a action.Act, _ string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	l.sent = append(l.sent, string(a))
	return nil
}

func (l *link) relock() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sent = append(l.sent, "lock")
}

// NET-6: the lock relocks. An unlock that timed out never reaches the
// device after the relock the channel sends once the policy lock is free,
// however short the book's timeout.
func TestTimedOutUnlockNeverFollowsRelock(t *testing.T) {
	p := newPhone(t)
	for _, bound := range []time.Duration{time.Nanosecond, time.Microsecond} {
		timeouts := 0
		for range 2000 {
			l := &link{}
			b, err := action.NewBook(p.public(), l, bound)
			if err != nil {
				t.Fatal(err)
			}
			var policyLock sync.Mutex
			c, _ := b.Issue(home(), "door", action.Unlock, "", 0)
			policyLock.Lock()
			_, err = b.Redeem(home(), c.ID, p.sign(c.Msg), 1)
			policyLock.Unlock()
			if errors.Is(err, action.ErrTimeout) {
				timeouts++
			}
			policyLock.Lock()
			l.relock()
			policyLock.Unlock()
			time.Sleep(20 * time.Microsecond) // let a stray unlock try to land
			l.mu.Lock()
			if last := l.sent[len(l.sent)-1]; last != "lock" {
				t.Fatalf("bound %v: sent %v, the unlock landed after the relock", bound, l.sent)
			}
			l.mu.Unlock()
		}
		if timeouts == 0 {
			t.Fatalf("bound %v: no run timed out, the test proves nothing", bound)
		}
	}
}
