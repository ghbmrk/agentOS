package enrol

// REQ: NET-4, NET-2, HW-10

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/ap"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const (
	rp = "enforcer.home.arpa"
	// caseCode is a synthetic canary, never a real code.
	caseCode = "CANARY-CASE-CODE-AAAA-BBBB"
)

// authenticator is a fake ES256 passkey on rp with user verification.
type authenticator struct {
	t    *testing.T
	priv *ecdsa.PrivateKey
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
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

// sign is a tap over msg, in key.AssertionSig's encoding.
func (a *authenticator) sign(msg []byte) []byte {
	c := key.Challenge(msg)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(c[:]), "origin": "https://" + rp, "crossOrigin": false})
	h := sha256.Sum256([]byte(rp))
	ad := append(h[:], 0x01|0x04, 0, 0, 0, 0)
	cdh := sha256.Sum256(cd)
	m := sha256.Sum256(append(slices.Clone(ad), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, m[:])
	if err != nil {
		a.t.Fatal(err)
	}
	b, err := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	if err != nil {
		a.t.Fatal(err)
	}
	return b
}

type memStore struct{ b []byte }

func (m *memStore) Load() ([]byte, error) { return m.b, nil }
func (m *memStore) Save(b []byte) error   { m.b = slices.Clone(b); return nil }

// fakeAlerts records what enrolment told the owner.
type fakeAlerts struct {
	raised   []alert.Kind
	recovery bool
}

func (f *fakeAlerts) Raise(k alert.Kind, _ string) (alert.Record, error) {
	f.raised = append(f.raised, k)
	return alert.Record{}, nil
}
func (f *fakeAlerts) Recovery(p bool) { f.recovery = p }

// accessPoint is slice g's access point as the daemon wires it: the keys
// and the configuration they render.
type accessPoint struct {
	keys    ap.Keys
	layout  ap.Layout
	pushed  []ap.File
	fail    bool
	replace int
}

func (a *accessPoint) Replace() (Card, error) {
	if a.fail {
		return Card{}, errors.New("access point unreachable")
	}
	a.replace++
	if !a.keys.Enrolled() {
		k := a.keys
		if err := k.Enrol(); err != nil {
			return Card{}, err
		}
		files, err := ap.Config(policy.Document{}, a.layout, k)
		if err != nil {
			return Card{}, err
		}
		a.keys, a.pushed = k, files
	}
	c, _ := a.keys.NetworkCard(a.layout, policy.NetOwner)
	return Card{SSID: c.SSID, Shown: c.Shown, QR: c.QR}, nil
}

// opens reports whether pw opens any network the access point broadcasts.
func (a *accessPoint) opens(pw string) bool {
	for _, f := range a.pushed {
		if strings.Contains(string(f.Data), pw) {
			return true
		}
	}
	return false
}

func layout() ap.Layout {
	return ap.Layout{
		Uplink: "eth0", DeviceUplink: "eth1",
		Owner: 10, Household: 20, Guests: 30, Admin: 99,
		Addr:   netip.MustParsePrefix("10.70.0.2/24"),
		Radios: []ap.Radio{{Name: "radio0", Path: "platform/soc/18000000.wifi", Band: "2g", HTMode: "HE20", Channel: "auto", Country: "US"}},
		SSID:   ap.SSIDs{Setup: "Home setup", Owner: "Home", Household: "Home family", Guests: "Home guests", Devices: "Home things"},
		// A synthetic key, never a real one.
		EnforcerKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEnforcerSyntheticTestKeyOnly000000000000000",
	}
}

type rig struct {
	t      *testing.T
	b      *Book
	e      *policy.Engine
	es     *memStore
	bs     *memStore
	ap     *accessPoint
	alerts *fakeAlerts
	now    time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	g := &rig{t: t, es: &memStore{}, bs: &memStore{}, alerts: &fakeAlerts{}, now: time.UnixMilli(1_800_000_000_000),
		ap: &accessPoint{keys: ap.Keys{Setup: "CANARYSETUPAAAAAAAAAAAAAAA"}, layout: layout()}}
	files, err := ap.Config(policy.Document{}, g.ap.layout, g.ap.keys)
	if err != nil {
		t.Fatal(err)
	}
	g.ap.pushed = files
	if err := Provision(g.bs, caseCode, nil); err != nil {
		t.Fatal(err)
	}
	g.reopen()
	return g
}

// reopen is a restart: the book and the engine from their stores.
func (g *rig) reopen() {
	g.t.Helper()
	b, err := Open(Config{Name: rp, Store: g.bs, Network: g.ap, Alerts: g.alerts, Now: func() time.Time { return g.now }})
	if err != nil {
		g.t.Fatal(err)
	}
	e, err := b.OpenPolicy(g.es)
	if err != nil {
		g.t.Fatal(err)
	}
	g.b, g.e = b, e
}

// enrol runs Begin and Finish for a with code.
func (g *rig) enrol(a *authenticator, code string) (Result, error) {
	g.t.Helper()
	id, msg, err := g.b.Begin(code, a.Public())
	if err != nil {
		return Result{}, err
	}
	return g.b.Finish(id, a.sign(msg))
}

// home is a policy with one device on it.
func home(v uint64) policy.Document {
	return policy.Document{Version: v, Devices: []policy.Device{{ID: "tv", Network: policy.NetDevices, WiFi: "vlan101", Everyday: true, Allow: []string{"tv.example"}}}}
}

// propose is the owner's tap on next through the engine.
func (g *rig) propose(a *authenticator, next policy.Document) (policy.Outcome, error) {
	p := policy.Proposal{Doc: next, Diff: []byte(fmt.Sprintf("v%d", next.Version))}
	r, err := p.Root(a.Public())
	if err != nil {
		g.t.Fatal(err)
	}
	return g.e.Propose(p, a.sign(key.RootMsg(r)), g.now.UnixMilli())
}

// keep is a's tap keeping the policy in force.
func (g *rig) keep(a *authenticator, v uint64) error {
	p, r, err := g.b.KeepProposal(v)
	if err != nil {
		return err
	}
	return g.b.Keep(p, a.sign(key.RootMsg(r)))
}

// enrolled is a rig with owner a and home(1) in force.
func enrolled(t *testing.T) (*rig, *authenticator, string) {
	g := newRig(t)
	a := newAuthenticator(t)
	res, err := g.enrol(a, caseCode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.propose(a, home(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := g.e.Tick(g.now.UnixMilli() + policy.Wait); err != nil {
		t.Fatal(err)
	}
	if g.e.Current().Device("tv") == nil {
		t.Fatal("home(1) not in force")
	}
	return g, a, res.Recovery
}

// TestFirstPasskeyNeedsSetupSecret: in factory state only the case code
// enrols, only for a passkey that signs its own enrolment, once; the
// enrolment shows a recovery code once and the Owner network's card, and
// texts the owner. Catches enrolment by whoever reaches the setup network.
func TestFirstPasskeyNeedsSetupSecret(t *testing.T) {
	g := newRig(t)
	a, x := newAuthenticator(t), newAuthenticator(t)
	for _, code := range []string{"", "CANARY-CASE-CODE-AAAA-BBBC", "CANARYSETUPAAAAAAAAAAAAAAA"} {
		if _, _, err := g.b.Begin(code, a.Public()); !errors.Is(err, ErrCode) {
			t.Errorf("code %q: %v", code, err)
		}
	}
	// A passkey on another name is refused even with the code.
	other, _ := key.ES256("elsewhere.example", a.Public().Bytes())
	if _, _, err := g.b.Begin(caseCode, other); !errors.Is(err, ErrKey) {
		t.Errorf("other RP ID: %v", err)
	}
	// A case-code ticket begun before another passkey enrolled does not
	// finish afterwards, as a replacement no recovery code authorised.
	early, earlyMsg, err := g.b.Begin(caseCode, x.Public())
	if err != nil {
		t.Fatal(err)
	}
	// The code with a passkey that does not sign its ticket enrols nothing.
	id, msg, err := g.b.Begin(caseCode, a.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.b.Finish(id, x.sign(msg)); !errors.Is(err, ErrProof) {
		t.Errorf("tap by another passkey: %v", err)
	}
	if _, err := g.b.Finish(id, a.sign(msg)); !errors.Is(err, ErrGone) {
		t.Errorf("ticket reused after a failed tap: %v", err)
	}
	if g.b.Phase() != Factory || g.b.Owner().Valid() {
		t.Fatal("enrolled without a proof")
	}
	// Typed as printed or not, the case code enrols a.
	res, err := g.enrol(a, strings.ToLower(strings.ReplaceAll(caseCode, "-", " ")))
	if err != nil {
		t.Fatal(err)
	}
	if g.b.Phase() != Enrolled || g.b.Owner() != a.Public() || !g.b.Kept() {
		t.Fatalf("after enrolment: phase %s owner %v kept %v", g.b.Phase(), g.b.Owner(), g.b.Kept())
	}
	if len(res.Recovery) != CodeLen || res.Card.SSID != "Home" || !res.Due.IsZero() {
		t.Errorf("result %+v", res)
	}
	if !slices.Equal(g.alerts.raised, []alert.Kind{alert.Enrolment}) {
		t.Errorf("alerts %v", g.alerts.raised)
	}
	if _, err := g.b.Finish(early, x.sign(earlyMsg)); !errors.Is(err, ErrGone) {
		t.Errorf("case-code ticket finished after enrolment: %v", err)
	}
	if _, ok := g.b.Recovery(); ok || g.b.Owner() != a.Public() {
		t.Error("a case-code ticket started a replacement")
	}
	// The policy is a's now: a's tap applies a version.
	if _, err := g.propose(a, home(1)); err != nil {
		t.Errorf("owner's first proposal: %v", err)
	}
	// With a passkey in force the case code enrols nobody else.
	if _, _, err := g.b.Begin(caseCode, x.Public()); !errors.Is(err, ErrCode) {
		t.Errorf("case code after enrolment: %v", err)
	}
	// The book keeps no code, only verifiers.
	for _, c := range []string{Normal(caseCode), res.Recovery} {
		if strings.Contains(string(g.bs.b), c) {
			t.Errorf("stored state holds a code")
		}
	}
	g.reopen()
	if g.b.Owner() != a.Public() || !g.b.Kept() {
		t.Error("enrolment lost on restart")
	}
	// Guessing is capped: after MaxFailures misses even the right code waits.
	g2 := newRig(t)
	for i := 0; i < MaxFailures; i++ {
		g2.b.Begin("WRONG", a.Public())
	}
	if _, err := g2.enrol(a, caseCode); !errors.Is(err, ErrLimited) {
		t.Errorf("after %d misses: %v", MaxFailures, err)
	}
	g2.now = g2.now.Add(FailWindow)
	if _, err := g2.enrol(a, caseCode); err != nil {
		t.Errorf("after the window: %v", err)
	}
}

// TestRecoveryCodeEnrolsAfterWaitOnly: the recovery code enrols only a
// replacement passkey, only after Wait, cancelable by the passkey in
// force, with a text and the page's pending state at the start; it then
// takes the owner's place, a loosening the old passkey signed meanwhile
// does not land, and the policy waits for the new passkey to keep it.
// Catches instant takeover by a stolen code.
func TestRecoveryCodeEnrolsAfterWaitOnly(t *testing.T) {
	g, a, code := enrolled(t)
	b := newAuthenticator(t)
	g.alerts.raised = nil

	// Only a replacement: not the passkey in force, and not a reset.
	if _, _, err := g.b.Begin(code, a.Public()); !errors.Is(err, ErrPhase) {
		t.Errorf("re-enrolling the owner: %v", err)
	}
	if err := g.b.FactoryReset(code); !errors.Is(err, ErrCode) {
		t.Errorf("reset by the recovery code: %v", err)
	}
	// Two tickets begun together: the second never swaps the replacement
	// the first started.
	c := newAuthenticator(t)
	id2, msg2, err := g.b.Begin(code, c.Public())
	if err != nil {
		t.Fatal(err)
	}
	res, err := g.enrol(b, code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.b.Finish(id2, c.sign(msg2)); !errors.Is(err, ErrGone) {
		t.Errorf("second ticket swapped the replacement: %v", err)
	}
	if want := g.now.Add(Wait); !res.Due.Equal(want) || len(res.Recovery) != CodeLen || res.Recovery == code {
		t.Errorf("result %+v, want due %v", res, want)
	}
	if !slices.Equal(g.alerts.raised, []alert.Kind{alert.RecoveryCodeUsed}) || !g.alerts.recovery {
		t.Errorf("at start: alerts %v, pending %v", g.alerts.raised, g.alerts.recovery)
	}
	if due, ok := g.b.Recovery(); !ok || !due.Equal(res.Due) {
		t.Error("the page does not show the recovery pending")
	}
	// One at a time.
	if _, _, err := g.b.Begin(code, newAuthenticator(t).Public()); !errors.Is(err, ErrPhase) {
		t.Errorf("second recovery while one waits: %v", err)
	}
	// Not before the wait, across a restart too.
	g.now = g.now.Add(Wait - time.Millisecond)
	g.reopen()
	if done, err := g.b.Tick(); done || err != nil || g.b.Owner() != a.Public() {
		t.Fatalf("applied early: %v %v", done, err)
	}
	// The owner cancels it with the passkey in force (the page's tap).
	fresh, err := g.b.Cancel()
	if err != nil {
		t.Fatal(err)
	}
	g.now = g.now.Add(time.Hour)
	if done, _ := g.b.Tick(); done || g.b.Owner() != a.Public() || g.alerts.recovery {
		t.Fatal("a cancelled recovery applied")
	}
	// The code that started it is spent: it cannot start another, and
	// neither can the code the cancelled replacement was shown.
	for _, old := range []string{code, res.Recovery} {
		if _, _, err := g.b.Begin(old, newAuthenticator(t).Public()); !errors.Is(err, ErrCode) {
			t.Errorf("spent recovery code after cancel: %v", err)
		}
	}
	if len(fresh) != CodeLen || fresh == code {
		t.Fatalf("new recovery code %q", fresh)
	}
	code = fresh

	// Again, uncancelled: a's loosening signed meanwhile is dropped when b
	// takes over.
	res, err = g.enrol(b, code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.propose(a, edit(home(0), g.now.UnixMilli(), "tv", "evil.example")); err != nil {
		t.Fatal(err)
	}
	g.now = g.now.Add(Wait)
	if done, err := g.b.Tick(); !done || err != nil {
		t.Fatalf("not applied at Wait: %v", err)
	}
	if g.b.Owner() != b.Public() || g.b.Kept() || g.alerts.recovery || g.alerts.raised[len(g.alerts.raised)-1] != alert.Enrolment {
		t.Fatalf("after Wait: owner %v kept %v alerts %v", g.b.Owner(), g.b.Kept(), g.alerts.raised)
	}
	if len(g.e.Pending()) != 0 {
		t.Error("the old passkey's loosening outlived it")
	}
	// Until b keeps the policy, neither passkey loosens it.
	for _, x := range []*authenticator{a, b} {
		if _, err := g.propose(x, edit(home(0), g.now.UnixMilli()+1, "tv", "x.example")); !errors.Is(err, policy.ErrNotOwner) {
			t.Errorf("proposal before keep: %v", err)
		}
	}
	// The old recovery code is spent; the new one is the code.
	if _, _, err := g.b.Begin(code, newAuthenticator(t).Public()); !errors.Is(err, ErrCode) {
		t.Errorf("old recovery code: %v", err)
	}
	g.reopen() // a restart keeps the engine owner-less until the keep
	if _, err := g.propose(a, edit(home(0), g.now.UnixMilli()+2, "tv", "x.example")); !errors.Is(err, policy.ErrNotOwner) {
		t.Errorf("old passkey after restart: %v", err)
	}
	before := g.e.Current()
	if err := g.keep(a, uint64(g.now.UnixMilli())+3); err == nil {
		t.Error("the old passkey kept the policy")
	}
	if err := g.keep(b, uint64(g.now.UnixMilli())+4); err != nil {
		t.Fatal(err)
	}
	if !g.b.Kept() || !sameRules(before, g.e.Current()) {
		t.Fatal("keep changed the policy")
	}
	g.reopen()
	if !sameRules(before, g.e.Current()) {
		t.Fatal("the kept policy does not reopen under the new passkey")
	}
	if out, err := g.propose(b, edit(home(0), g.now.UnixMilli()+5, "tv", "y.example")); err != nil || out.Pending == "" {
		t.Errorf("new owner's loosening: %+v %v", out, err)
	}
	if _, _, err := g.b.Begin(res.Recovery, newAuthenticator(t).Public()); err != nil {
		t.Errorf("new recovery code: %v", err)
	}
}

// TestFactoryResetKeepsPolicyBlocksLoosening: the case code resets; the
// policy in force stays, a waiting loosening is cancelled, the old passkey
// approves nothing, and no loosening applies until the case code enrols a
// new passkey and it keeps the policy. Tightenings still apply. Catches a
// reset that opens the home.
func TestFactoryResetKeepsPolicyBlocksLoosening(t *testing.T) {
	g, a, code := enrolled(t)
	if _, err := g.propose(a, edit(home(0), g.now.UnixMilli(), "tv", "evil.example")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"", code, "CANARYSETUPAAAAAAAAAAAAAAA"} {
		if err := g.b.FactoryReset(c); !errors.Is(err, ErrCode) {
			t.Errorf("reset with %q: %v", c, err)
		}
	}
	before := g.e.Current()
	if err := g.b.FactoryReset(caseCode); err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		t.Helper()
		if g.b.Phase() != Reset || g.b.Owner().Valid() {
			t.Fatalf("%s: phase %s", when, g.b.Phase())
		}
		if !sameRules(before, g.e.Current()) {
			t.Fatalf("%s: the policy changed", when)
		}
		if len(g.e.Pending()) != 0 {
			t.Fatalf("%s: a loosening still waits", when)
		}
		if _, err := g.propose(a, edit(home(0), g.now.UnixMilli()+7, "tv", "x.example")); !errors.Is(err, policy.ErrNotOwner) {
			t.Errorf("%s: old passkey's loosening: %v", when, err)
		}
		if _, _, err := g.b.Begin(code, newAuthenticator(t).Public()); !errors.Is(err, ErrCode) {
			t.Errorf("%s: recovery code after reset: %v", when, err)
		}
	}
	g.now = g.now.Add(time.Hour)
	if _, err := g.e.Tick(g.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	check("after reset")
	g.reopen()
	check("after restart")
	// A tightening from the channel still applies.
	if err := g.e.Tighten(policy.Op{Kind: policy.RemoveDestination, Device: "tv", Host: "tv.example"}, g.now.UnixMilli()); err != nil {
		t.Errorf("tightening during reset: %v", err)
	}
	before = g.e.Current()

	// The case code enrols b; the Owner network stays.
	b := newAuthenticator(t)
	res, err := g.enrol(b, caseCode)
	if err != nil {
		t.Fatal(err)
	}
	if g.b.Owner() != b.Public() || g.b.Kept() || res.Card.SSID != "Home" {
		t.Fatalf("after re-enrolment: kept %v card %+v", g.b.Kept(), res.Card)
	}
	if _, err := g.propose(b, edit(home(0), g.now.UnixMilli()+8, "tv", "x.example")); !errors.Is(err, policy.ErrNotOwner) {
		t.Errorf("loosening before keep: %v", err)
	}
	if err := g.keep(b, uint64(g.now.UnixMilli())+9); err != nil {
		t.Fatal(err)
	}
	if !sameRules(before, g.e.Current()) {
		t.Fatal("re-enrolment changed the policy")
	}
	if out, err := g.propose(b, edit(home(0), g.now.UnixMilli()+10, "tv", "x.example")); err != nil || out.Pending == "" {
		t.Errorf("new owner's loosening: %+v %v", out, err)
	}

	// A stolen recovery code's ticket, begun before a reset, does not
	// start a replacement against the passkey enrolled after it.
	g2, _, code2 := enrolled(t)
	x := newAuthenticator(t)
	id, msg, err := g2.b.Begin(code2, x.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := g2.b.FactoryReset(caseCode); err != nil {
		t.Fatal(err)
	}
	if _, err := g2.enrol(newAuthenticator(t), caseCode); err != nil {
		t.Fatal(err)
	}
	if _, err := g2.b.Finish(id, x.sign(msg)); !errors.Is(err, ErrGone) {
		t.Errorf("ticket from before the reset: %v", err)
	}
	if _, ok := g2.b.Recovery(); ok {
		t.Error("a ticket from before the reset started a replacement")
	}
}

// TestSetupNetworkReplacedAtEnrolment: enrolment replaces the setup
// network before any passkey is in force, so afterwards the sticker's
// password opens nothing; if the access point cannot be told, nothing
// enrols. Catches a sticker that still works.
func TestSetupNetworkReplacedAtEnrolment(t *testing.T) {
	g := newRig(t)
	setup := g.ap.keys.Setup
	if !g.ap.opens(setup) {
		t.Fatal("fixture: the setup network is not up before enrolment")
	}
	a := newAuthenticator(t)
	g.ap.fail = true
	if _, err := g.enrol(a, caseCode); err == nil || g.b.Phase() != Factory || g.b.Owner().Valid() {
		t.Fatalf("enrolled with the setup network still up: %v", err)
	}
	g.ap.fail = false
	res, err := g.enrol(a, caseCode)
	if err != nil {
		t.Fatal(err)
	}
	if g.ap.opens(setup) {
		t.Error("the setup network's password still opens a network")
	}
	for _, f := range g.ap.pushed {
		if strings.Contains(string(f.Data), "Home setup") {
			t.Error("the setup network still broadcasts")
		}
	}
	if !g.ap.opens(g.ap.keys.Owner) || res.Card.QR == "" || !strings.Contains(res.Card.QR, g.ap.keys.Owner) {
		t.Errorf("the Owner network is not up or not shown: %+v", res.Card)
	}
	if res.Card.Shown == "" || strings.Contains(res.Card.QR, setup) {
		t.Errorf("card %+v", res.Card)
	}
}

// sameRules is equality of two documents but for their version.
func sameRules(x, y policy.Document) bool {
	x.Version, y.Version = 0, 0
	bx, _ := policy.Encode(x)
	by, _ := policy.Encode(y)
	return string(bx) == string(by)
}

// edit is d at version v with host added to device id's allow list: a
// loosening.
func edit(d policy.Document, v int64, id, host string) policy.Document {
	d.Version = uint64(v)
	for i := range d.Devices {
		if d.Devices[i].ID == id {
			d.Devices[i].Allow = append(slices.Clone(d.Devices[i].Allow), host)
		}
	}
	return d
}
