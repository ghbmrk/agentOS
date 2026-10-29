package policy

// REQ: STO-4, NET-4, NET-2

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const rp = "enforcer.home.arpa"

// authenticator is a WebAuthn ES256 credential that signs as a phone's
// passkey would, on its own RP ID, with flags the test can clear.
type authenticator struct {
	t     *testing.T
	priv  *ecdsa.PrivateKey
	rpID  string
	flags byte
}

func newAuthenticator(t *testing.T, rpID string) *authenticator {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{t: t, priv: p, rpID: rpID, flags: 0x01 | 0x04}
}

func (a *authenticator) Public() key.PublicKey {
	point, err := a.priv.PublicKey.Bytes()
	if err != nil {
		a.t.Fatal(err)
	}
	pk, err := key.ES256(a.rpID, point)
	if err != nil {
		a.t.Fatal(err)
	}
	return pk
}

func (a *authenticator) Sign(msg []byte) []byte {
	c := key.Challenge(msg)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(c[:]),
		"origin": "https://" + a.rpID, "crossOrigin": false})
	h := sha256.Sum256([]byte(a.rpID))
	ad := append(h[:], a.flags, 0, 0, 0, 0)
	cdh := sha256.Sum256(cd)
	m := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
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

// sign is the owner's tap on the page for p, as a credential owner.
func sign(t *testing.T, a *authenticator, owner key.PublicKey, p Proposal) []byte {
	t.Helper()
	r, err := p.Root(owner)
	if err != nil {
		t.Fatal(err)
	}
	return a.Sign(key.RootMsg(r))
}

type memStore struct{ b []byte }

func (m *memStore) Load() ([]byte, error) { return m.b, nil }
func (m *memStore) Save(b []byte) error   { m.b = slices.Clone(b); return nil }

// STO-4: a policy version is a KEY-1 root over the document and the
// rendered diff, signed by the owner's ES256 passkey and checked by
// broker/kernel/key. Another credential, another RP ID, no user
// verification, another diff or another document is refused, so there is
// no second rule system and no assertion that approves a diff it did not
// commit to.
func TestVersionKeyVerifiesWithKernelKeyLibrary(t *testing.T) {
	a := newAuthenticator(t, rp)
	owner := a.Public()
	p := Proposal{Doc: home(1), Diff: []byte("Allow plug, cam and lock on Devices.")}
	sig := sign(t, a, owner, p)
	k, err := Verify(owner, 0, p, sig)
	if err != nil {
		t.Fatalf("the owner's assertion: %v", err)
	}
	if k.Root.Clerk != Clerk || k.Root.Owner != owner || !owner.Verify(key.RootMsg(k.Root), k.Root.Sig) || !key.SignedBy(k, owner) {
		t.Fatal("the version is not a root the key library checks as the owner's")
	}
	if err := Check(owner, k, p); err != nil {
		t.Fatalf("re-check of a stored version: %v", err)
	}

	other := newAuthenticator(t, rp)
	agentos := newAuthenticator(t, "agentos.home.arpa")
	noUV := newAuthenticator(t, rp)
	noUV.priv, noUV.flags = a.priv, 0x01
	p2 := Proposal{Doc: p.Doc, Diff: []byte("Allow nothing new.")}
	p3 := Proposal{Doc: edit(1, func(d *Document) { dev(d, "plug").Allow = append(dev(d, "plug").Allow, "evil.example") }), Diff: p.Diff}
	refused := map[string]struct {
		sig []byte
		p   Proposal
	}{
		"another credential":   {sign(t, other, owner, p), p},
		"another RP ID":        {sign(t, agentos, owner, p), p},
		"no user verification": {sign(t, noUV, owner, p), p},
		"another diff":         {sig, p2},
		"another document":     {sig, p3},
		"no signature":         {nil, p},
		"garbage":              {[]byte("{}"), p},
	}
	for name, c := range refused {
		if _, err := Verify(owner, 0, c.p, c.sig); !errors.Is(err, ErrBadSig) {
			t.Errorf("%s: %v, want ErrBadSig", name, err)
		}
	}
	if err := Check(owner, k, p2); !errors.Is(err, ErrUnbound) {
		t.Errorf("a stored key with another diff: %v", err)
	}
	if err := Check(other.Public(), k, p); err == nil {
		t.Error("a stored key checked against another owner verified")
	}

	// The fake authenticator's Ed25519 keys are for the kernel's tests; the
	// enforcer's owner is a WebAuthn credential on its own name.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ed := key.Ed25519Signer(priv)
	r, _ := p.Root(ed.Public())
	if _, err := Verify(ed.Public(), 0, p, ed.Sign(key.RootMsg(r))); !errors.Is(err, ErrNotOwner) {
		t.Errorf("an Ed25519 owner: %v", err)
	}
}

// home is a small home. On the safety list (NET-2): a smart plug with a
// vendor cloud and a named secure command, a camera with none, and a lock
// with a visitor's standing rule. Off it (Everyday, which only the owner
// sets): a TV with a vendor cloud and a speaker paired with it, with a
// standing rule of its own.
func home(v uint64) Document {
	return Document{
		Version:      v,
		Destinations: []string{"mail.example", "models.example"},
		Devices: []Device{
			{ID: "plug", Network: NetDevices, WiFi: "vlan101", Allow: []string{"a.example", "b.example"}, VendorCloud: true, Secure: "off"},
			{ID: "cam", Network: NetDevices, WiFi: "vlan102", Allow: []string{"cam.example"}, VendorCloud: true, Class: ClassCamera, Stream: []Port{{ProtoTCP, 554}}},
			{ID: "lock", Network: NetDevices, Allow: []string{"lock.example"}, VendorCloud: true, Secure: "lock"},
			{ID: "tv", Network: NetDevices, WiFi: "vlan104", Allow: []string{"a.example", "b.example"}, VendorCloud: true, Everyday: true, Control: []Port{{ProtoTCP, 8008}}},
			{ID: "speaker", Network: NetDevices, WiFi: "vlan105", Allow: []string{"s.example"}, Everyday: true, Control: []Port{{ProtoTCP, 80}, {ProtoUDP, 1900}}},
		},
		Pairs: []Pair{{A: "plug", B: "cam"}, {A: "tv", B: "speaker"}},
		Standing: []StandingRule{
			{ID: "plumber", Device: "lock", Action: "keypad-code", FromMS: 1000, ToMS: 2000},
			{ID: "party", Device: "speaker", Action: "loud", FromMS: 1000, ToMS: 2000},
		},
		Holds: []Hold{{Device: "cam", Kind: HoldFirmware}},
	}
}

// edit is home(v) changed by f.
func edit(v uint64, f func(d *Document)) Document {
	d := home(v)
	f(&d)
	return d
}

func dev(d *Document, id string) *Device { return d.Device(id) }

func rule(d *Document, id string) *StandingRule {
	i := slices.IndexFunc(d.Standing, func(r StandingRule) bool { return r.ID == id })
	return &d.Standing[i]
}

func without[T any](s []T, drop func(T) bool) []T { return slices.DeleteFunc(slices.Clone(s), drop) }

// opened is an engine whose policy in force is home(1).
func opened(t *testing.T) (*Engine, *authenticator, *memStore) {
	t.Helper()
	a := newAuthenticator(t, rp)
	store := &memStore{}
	e, err := Open(a.Public(), store)
	if err != nil {
		t.Fatal(err)
	}
	p := Proposal{Doc: home(1), Diff: []byte("v1")}
	if _, err := e.Propose(p, sign(t, a, a.Public(), p), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Tick(Wait); err != nil {
		t.Fatal(err)
	}
	return e, a, store
}

func (a *authenticator) propose(t *testing.T, e *Engine, p Proposal, now int64) (Outcome, error) {
	t.Helper()
	return e.Propose(p, sign(t, a, a.Public(), p), now)
}

// NET-4 Tightening: only the closed-list kinds, one at a time, classify as
// a tightening. Each row runs for an off-list device, where it applies at
// once, and for a safety-list device, where it is an asserted tightening
// (Owner). Every other change to every field, any mix and any two
// tightenings is a loosening.
func TestClassifyClosedList(t *testing.T) {
	// Per-device rows: x is the device, y the other end of its pair, r its
	// standing rule. Off-list: tv, speaker, party. Safety-list: plug, cam, plumber on lock.
	type sub struct{ x, y, r, ry string }
	subjects := map[string]sub{"off-list": {"tv", "speaker", "party", "speaker"}, "safety-list": {"plug", "cam", "plumber", "lock"}}
	tight := map[string]struct {
		kind string
		f    func(d *Document, s sub)
	}{
		"remove a host":        {RemoveDestination, func(d *Document, s sub) { dev(d, s.x).Allow = []string{"b.example"} }},
		"cut the vendor cloud": {CutVendorCloud, func(d *Document, s sub) { dev(d, s.x).VendorCloud = false }},
		"remove the pair": {RemovePair, func(d *Document, s sub) {
			d.Pairs = without(d.Pairs, func(p Pair) bool { return p.A == s.x || p.B == s.x })
		}},
		"isolate the device": {IsolateDevice, func(d *Document, s sub) { dev(d, s.x).Isolated = true }},
		"remove the device": {RemoveDevice, func(d *Document, s sub) {
			d.Devices = without(d.Devices, func(v Device) bool { return v.ID == s.x })
			d.Pairs = without(d.Pairs, func(p Pair) bool { return p.A == s.x || p.B == s.x })
		}},
		"narrow the rule": {NarrowRule, func(d *Document, s sub) { rule(d, s.r).ToMS = 1500 }},
		"revoke the rule": {RevokeRule, func(d *Document, s sub) {
			d.Standing = without(d.Standing, func(r StandingRule) bool { return r.ID == s.r })
		}},
	}
	loose := map[string]func(d *Document, s sub){
		"add a host":             func(d *Document, s sub) { dev(d, s.x).Allow = append(dev(d, s.x).Allow, "x.example") },
		"swap a host":            func(d *Document, s sub) { dev(d, s.x).Allow = []string{"a.example", "x.example"} },
		"move network":           func(d *Document, s sub) { dev(d, s.x).Network = NetHousehold },
		"change Wi-Fi identity":  func(d *Document, s sub) { dev(d, s.x).WiFi = "vlan201" },
		"relabel":                func(d *Document, s sub) { dev(d, s.x).Label = LabelContained },
		"un-isolate":             func(d *Document, s sub) { dev(d, s.x).Isolated = false }, // run on an isolated base below
		"toggle the safety list": func(d *Document, s sub) { dev(d, s.x).Everyday = !dev(d, s.x).Everyday; dev(d, s.x).Secure = "" },
		"add a pair":             func(d *Document, s sub) { d.Pairs = append(d.Pairs, Pair{A: s.x, B: "lock"}) },
		"widen the rule":         func(d *Document, s sub) { rule(d, s.r).ToMS = 2500 },
		"shift the rule":         func(d *Document, s sub) { rule(d, s.r).FromMS, rule(d, s.r).ToMS = 1500, 2500 },
		"change the rule action": func(d *Document, s sub) { rule(d, s.r).Action = "other" },
		"move the rule":          func(d *Document, s sub) { rule(d, s.r).Device = s.y },
		"rename the rule":        func(d *Document, s sub) { rule(d, s.r).ID = "renamed" },
		"add a rule":             func(d *Document, s sub) { d.Standing = append(d.Standing, StandingRule{"new", s.x, "x", 1, 2}) },
		"add a hold":             func(d *Document, s sub) { d.Holds = append(d.Holds, Hold{s.x, HoldFix}) },
		"two hosts":              func(d *Document, s sub) { dev(d, s.x).Allow = nil },
		"cut and isolate":        func(d *Document, s sub) { dev(d, s.x).VendorCloud = false; dev(d, s.x).Isolated = true },
		"cut and add a host": func(d *Document, s sub) {
			dev(d, s.x).VendorCloud = false
			dev(d, s.x).Allow = append(dev(d, s.x).Allow, "x.example")
		},
		"narrow and widen": func(d *Document, s sub) {
			rule(d, s.r).ToMS = 1500
			rule(d, "party").FromMS, rule(d, "plumber").FromMS = 0, 0
		},
		"remove, keep its pair": func(d *Document, s sub) { d.Devices = without(d.Devices, func(v Device) bool { return v.ID == s.x }) },
		// Ports: naming, removing or changing a control port is not on the
		// closed list, so even a narrowing waits (ENF-a-12).
		"add a control port":    func(d *Document, s sub) { dev(d, s.x).Control = append(dev(d, s.x).Control, Port{ProtoTCP, 9}) },
		"change a control port": func(d *Document, s sub) { dev(d, s.x).Control = []Port{{ProtoUDP, 9}} },
		"remove a control port": func(d *Document, s sub) { dev(d, s.x).Control = nil }, // run on a base with a port below
	}
	for sname, s := range subjects {
		for name, c := range tight {
			got := Classify(home(1), edit(1, func(d *Document) { c.f(d, s) }))
			if !got.Tightening || got.Op.Kind != c.kind || got.Owner != (sname == "safety-list") {
				t.Errorf("%s, %s: %+v, want %s with Owner %v", sname, name, got, c.kind, sname == "safety-list")
			}
		}
		for name, f := range loose {
			base := home(1)
			switch name {
			case "un-isolate":
				dev(&base, s.x).Isolated = true
			case "remove a control port":
				dev(&base, s.x).Control = []Port{{ProtoTCP, 9}}
			}
			next := base.normal() // a copy
			f(&next, s)
			if got := Classify(base, next); got.Tightening {
				t.Errorf("%s, %s: classified as a tightening: %+v", sname, name, got)
			}
		}
	}

	// Whole-document fields and the safety list's own edges.
	for name, f := range map[string]func(d *Document){
		"version only":              func(d *Document) { d.Version = 9 },
		"add a core destination":    func(d *Document) { d.Destinations = append(d.Destinations, "x.example") },
		"remove a core destination": func(d *Document) { d.Destinations = d.Destinations[:1] },
		"add a device": func(d *Document) {
			d.Devices = append(d.Devices, Device{ID: "new", Network: NetDevices, Everyday: true})
		},
		"remove a hold":                            func(d *Document) { d.Holds = nil },
		"change a hold's kind":                     func(d *Document) { d.Holds[0].Kind = HoldFix },
		"change the drone policy":                  func(d *Document) { d.Drone = strings.Repeat("ab", 32) },
		"rename the secure command":                func(d *Document) { dev(d, "lock").Secure = "bolt" },
		"name a camera's command":                  func(d *Document) { dev(d, "cam").Secure = "off" },
		"rename a device":                          func(d *Document) { dev(d, "tv").ID = "tv2"; d.Pairs[1].A = "tv2" },
		"secure on an off-list device (malformed)": func(d *Document) { dev(d, "tv").Secure = "off" },
		"add a stream port":                        func(d *Document) { dev(d, "cam").Stream = append(dev(d, "cam").Stream, Port{ProtoUDP, 5004}) },
		"change a stream port":                     func(d *Document) { dev(d, "cam").Stream = []Port{{ProtoTCP, 8554}} },
		"remove the stream port":                   func(d *Document) { dev(d, "cam").Stream = nil },
		"class a camera a microphone":              func(d *Document) { dev(d, "cam").Class = ClassMicrophone },
		"unclass the camera":                       func(d *Document) { dev(d, "cam").Class = ""; dev(d, "cam").Stream = nil },
		"class the lock a camera (malformed)":      func(d *Document) { dev(d, "lock").Class = ClassCamera },
		"class a device a camera":                  func(d *Document) { dev(d, "lock").Class = ClassCamera; dev(d, "lock").Secure = "" },
		"no change":                                func(d *Document) {},
	} {
		if got := Classify(home(1), edit(1, f)); got.Tightening {
			t.Errorf("%s: classified as a tightening: %+v", name, got)
		}
	}

	// A device nobody classified is on the safety list, and so is a camera
	// with no named command: tightening either needs the owner.
	unknown := edit(1, func(d *Document) {
		d.Devices = append(d.Devices, Device{ID: "thing", Network: NetDevices, Allow: []string{"t.example"}})
	})
	for _, op := range []Op{{Kind: IsolateDevice, Device: "thing"}, {Kind: RemoveDestination, Device: "thing", Host: "t.example"}, {Kind: IsolateDevice, Device: "cam"}, {Kind: CutVendorCloud, Device: "cam"}} {
		next, _ := Apply(unknown, op)
		if c := Classify(unknown, next); !c.Tightening || !c.Owner {
			t.Errorf("%s %s: %+v, want an asserted tightening", op.Kind, op.Device, c)
		}
	}

	// Isolating or removing an off-list device cuts its pairs, so when it
	// is paired with a safety-list device the owner must sign, as for
	// removing that pair (Security fix-list on #3697, item 2).
	linked := edit(1, func(d *Document) { d.Pairs = append(d.Pairs, Pair{A: "lock", B: "tv"}) })
	for _, op := range []Op{{Kind: IsolateDevice, Device: "tv"}, {Kind: RemoveDevice, Device: "tv"}} {
		next, _ := Apply(linked, op)
		if c := Classify(linked, next); !c.Tightening || !c.Owner {
			t.Errorf("%s tv, paired with the lock: %+v, want an asserted tightening", op.Kind, c)
		}
	}

	// Every field has a row: adding a field to the document without one
	// fails here.
	covered := map[string][]string{
		"Document":     {"Version", "Destinations", "Devices", "Pairs", "Standing", "Holds", "Drone"},
		"Device":       {"ID", "Network", "WiFi", "Allow", "VendorCloud", "Isolated", "Everyday", "Secure", "Label", "Class", "Control", "Stream"},
		"Port":         {"Proto", "Num"},
		"Pair":         {"A", "B"},
		"StandingRule": {"ID", "Device", "Action", "FromMS", "ToMS"},
		"Hold":         {"Device", "Kind"},
	}
	for _, v := range []any{Document{}, Device{}, Port{}, Pair{}, StandingRule{}, Hold{}} {
		ty := reflect.TypeOf(v)
		var fields []string
		for i := range ty.NumField() {
			fields = append(fields, ty.Field(i).Name)
		}
		if !slices.Equal(fields, covered[ty.Name()]) {
			t.Errorf("%s has fields %v; the classify table covers %v", ty.Name(), fields, covered[ty.Name()])
		}
	}
}

// NET-4 Loosening: a signed loosening applies at exactly +10 minutes on the
// enforcer's clock, not before, never after it is cancelled, and both the
// wait and the cancel survive a restart. A cancelled assertion is spent. A
// tightening, unsigned or signed, applied while a loosening waits is kept
// when the loosening lands, and the loosening is not dropped.
func TestLooseningWaitsAndCancels(t *testing.T) {
	a := newAuthenticator(t, rp)
	owner := a.Public()
	store := &memStore{}
	e, err := Open(owner, store)
	if err != nil {
		t.Fatal(err)
	}
	const t0 = 1_000_000
	out, err := a.propose(t, e, Proposal{Doc: home(1), Diff: []byte("first policy")}, t0)
	if err != nil || out.Applied || out.Pending == "" || out.DueMS != t0+Wait {
		t.Fatalf("a loosening: %+v %v", out, err)
	}
	if got, _ := e.Tick(t0 + Wait - 1); got != nil || e.Current().Version != 0 {
		t.Fatalf("applied before the wait: %v", got)
	}
	if e, err = Open(owner, store); err != nil {
		t.Fatal(err)
	}
	if ps := e.Pending(); len(ps) != 1 || ps[0].DueMS != t0+Wait {
		t.Fatalf("pending after restart: %+v", ps)
	}
	if got, err := e.Tick(t0 + Wait); err != nil || len(got) != 1 || e.Current().Version != 1 || e.Current().Device("lock") == nil {
		t.Fatalf("not applied at +10 minutes: %v %v", got, err)
	}

	// Cancelled, then a restart: never applied, and the same assertion is
	// refused again (Security item 1, L3 item 3).
	const t1 = 5_000_000
	p2 := Proposal{Doc: edit(2, func(d *Document) { dev(d, "tv").Allow = append(dev(d, "tv").Allow, "evil.example") }), Diff: []byte("allow evil")}
	sig2 := sign(t, a, owner, p2)
	out, err = e.Propose(p2, sig2, t1)
	if err != nil || out.Pending == "" {
		t.Fatal(out, err)
	}
	if err := e.Cancel(out.Pending); err != nil {
		t.Fatal(err)
	}
	if err := e.Cancel(out.Pending); !errors.Is(err, ErrNoPending) {
		t.Errorf("a second cancel: %v", err)
	}
	if _, err := e.Propose(p2, sig2, t1+1); !errors.Is(err, ErrNotRising) {
		t.Errorf("the cancelled assertion again: %v", err)
	}
	if e, err = Open(owner, store); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Propose(p2, sig2, t1+2); !errors.Is(err, ErrNotRising) {
		t.Errorf("the cancelled assertion after a restart: %v", err)
	}
	if got, _ := e.Tick(t1 + 100*Wait); got != nil || e.Current().Version != 1 || slices.Contains(e.Current().Device("tv").Allow, "evil.example") {
		t.Fatalf("a cancelled loosening applied: %v", got)
	}

	// While v3 (add a host to the speaker) waits, the channel cuts the
	// TV's cloud and the owner signs v4, cutting the lock's cloud (an
	// asserted tightening). Both apply at once; v3 still lands, on top of
	// them (L3 item 5, UX item 1).
	p3 := Proposal{Doc: edit(3, func(d *Document) { dev(d, "speaker").Allow = append(dev(d, "speaker").Allow, "c.example") }), Diff: []byte("allow c on the speaker")}
	if _, err := a.propose(t, e, p3, t1); err != nil {
		t.Fatal(err)
	}
	if err := e.Tighten(Op{Kind: CutVendorCloud, Device: "tv"}, t1+1); err != nil {
		t.Fatal(err)
	}
	p4 := Proposal{Doc: edit(4, func(d *Document) { dev(d, "tv").VendorCloud = false; dev(d, "lock").VendorCloud = false }), Diff: []byte("cut the lock's cloud")}
	if out, err := a.propose(t, e, p4, t1+2); err != nil || !out.Applied || !out.Class.Owner {
		t.Fatalf("a signed tightening of the lock while a loosening waits: %+v %v", out, err)
	}
	if len(e.Pending()) != 1 {
		t.Fatal("a signed tightening dropped the waiting loosening")
	}
	// A second loosening while one waits is refused, and its assertion
	// is spent: after the first lands it cannot come back and undo the
	// tightenings taken since (delta Security item 1).
	p5 := Proposal{Doc: edit(5, func(d *Document) { dev(d, "speaker").Allow = append(dev(d, "speaker").Allow, "x.example") }), Diff: []byte("another loosening")}
	sig5 := sign(t, a, owner, p5)
	if _, err := e.Propose(p5, sig5, t1+3); !errors.Is(err, ErrPending) {
		t.Errorf("a second loosening while one waits: %v", err)
	}
	if e, err = Open(owner, store); err != nil {
		t.Fatal(err)
	}
	if got, err := e.Tick(t1 + Wait); err != nil || len(got) != 1 {
		t.Fatalf("the waiting loosening did not land: %v %v", got, err)
	}
	cur := e.Current()
	if cur.Version != 4 || !slices.Contains(dev(&cur, "speaker").Allow, "c.example") || dev(&cur, "tv").VendorCloud || dev(&cur, "lock").VendorCloud {
		t.Fatalf("after the loosening: %+v", cur)
	}
	if e, err = Open(owner, store); err != nil || !reflect.DeepEqual(e.Current(), cur) {
		t.Fatalf("restart changed the policy: %v", err)
	}
	if _, err := e.Propose(p5, sig5, t1+Wait+1); !errors.Is(err, ErrNotRising) {
		t.Errorf("the refused second loosening, after the first landed: %v", err)
	}

	// Every step taken while a loosening waits must carry over when it
	// lands; one that would not is refused when it is taken, so nothing
	// reported as applied is dropped later (delta Security item 2, delta
	// L3 item 2). The owner puts the TV back on the safety list and moves
	// the plumber's window to 1500-3000, both loosenings that wait.
	const t2 = 9_000_000
	p6 := Proposal{Doc: func() Document {
		d := e.Current()
		d.Version = 6
		dev(&d, "tv").Everyday = false
		dev(&d, "tv").Allow = []string{"a.example", "x.example"}
		rule(&d, "plumber").FromMS, rule(&d, "plumber").ToMS = 1500, 3000
		return d
	}(), Diff: []byte("relist the tv, swap its host, move the plumber")}
	if out, err := a.propose(t, e, p6, t2); err != nil || out.Pending == "" {
		t.Fatalf("p6: %+v %v", out, err)
	}
	// The channel: isolating the TV needs no owner now but would after
	// p6, so it is refused now; b.example is gone after p6.
	if err := e.Tighten(Op{Kind: IsolateDevice, Device: "tv"}, t2+1); !errors.Is(err, ErrNeedsOwner) {
		t.Errorf("isolating a TV that p6 relists: %v", err)
	}
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "tv", Host: "b.example"}, t2+1); !errors.Is(err, ErrPending) {
		t.Errorf("removing a host p6 drops: %v", err)
	}
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "speaker", Host: "c.example"}, t2+1); err != nil {
		t.Errorf("a step that carries over: %v", err)
	}
	// The owner narrows the plumber to 1000-1200: signed, but p6's window
	// does not contain it, so it is refused now, and its version is spent.
	p7 := Proposal{Doc: func() Document {
		d := e.Current()
		d.Version = 7
		rule(&d, "plumber").ToMS = 1200
		return d
	}(), Diff: []byte("plumber until 1200")}
	sig7 := sign(t, a, owner, p7)
	if _, err := e.Propose(p7, sig7, t2+2); !errors.Is(err, ErrPending) {
		t.Errorf("a signed narrowing p6 would undo: %v", err)
	}
	if _, err := e.Propose(p7, sig7, t2+2); !errors.Is(err, ErrNotRising) {
		t.Errorf("the refused narrowing at once again: %v", err)
	}
	// One that does carry over: cut the lock's cloud is already done, so
	// isolate the camera.
	p8 := Proposal{Doc: func() Document { d := e.Current(); d.Version = 8; dev(&d, "cam").Isolated = true; return d }(), Diff: []byte("isolate the camera")}
	if out, err := a.propose(t, e, p8, t2+3); err != nil || !out.Applied {
		t.Fatalf("a signed tightening that carries over: %+v %v", out, err)
	}
	if e, err = Open(owner, store); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Propose(p7, sig7, t2+4); !errors.Is(err, ErrNotRising) {
		t.Errorf("the refused narrowing again: %v", err)
	}
	if _, err := e.Tick(t2 + Wait); err != nil {
		t.Fatal(err)
	}
	cur = e.Current()
	if tv := dev(&cur, "tv"); tv.Everyday || tv.Isolated || !slices.Equal(tv.Allow, []string{"a.example", "x.example"}) {
		t.Errorf("tv after p6: %+v", tv)
	}
	if !dev(&cur, "cam").Isolated || slices.Contains(dev(&cur, "speaker").Allow, "c.example") || cur.Version != 8 {
		t.Errorf("a step taken during the wait did not carry over: %+v", cur)
	}
	if r := rule(&cur, "plumber"); r.FromMS != 1500 || r.ToMS != 3000 {
		t.Errorf("plumber after p6: %+v", r)
	}
	if e, err = Open(owner, store); err != nil || !reflect.DeepEqual(e.Current(), cur) {
		t.Fatalf("restart after p6: %v", err)
	}
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "tv", Host: "a.example"}, t2+Wait); !errors.Is(err, ErrNeedsOwner) {
		t.Errorf("the relisted tv tightened from the channel: %v", err)
	}
}

// NET-2 Recovery: a version at or below any version ever accepted is
// refused, a replayed assertion with it; restoring an older document takes
// a new, higher version with a fresh assertion, and is then a loosening
// that waits. The export for the core's backup restores through that path
// and holds no secret.
func TestOlderVersionRefused(t *testing.T) {
	e, a, _ := opened(t)
	owner := a.Public()
	p1 := Proposal{Doc: home(1), Diff: []byte("v1")}
	p2 := Proposal{Doc: edit(2, func(d *Document) { d.Pairs = d.Pairs[:1] }), Diff: []byte("v2: remove the tv-speaker pair")}
	if out, err := a.propose(t, e, p2, Wait); err != nil || !out.Applied {
		t.Fatal(out, err)
	}
	if _, err := e.Propose(p1, sign(t, a, owner, p1), Wait); !errors.Is(err, ErrNotRising) {
		t.Errorf("v1 freshly signed: %v", err)
	}
	same := Proposal{Doc: edit(2, func(d *Document) { d.Pairs = d.Pairs[:1]; dev(d, "cam").Isolated = true }), Diff: []byte("v2 again")}
	if _, err := a.propose(t, e, same, Wait); !errors.Is(err, ErrNotRising) {
		t.Errorf("an equal version: %v", err)
	}
	if e.Current().Version != 2 || len(e.Pending()) != 0 {
		t.Fatal("a refused version changed the engine")
	}

	restore := Proposal{Doc: home(3), Diff: []byte("restore v1: add the pair back")}
	out, err := a.propose(t, e, restore, 2*Wait)
	if err != nil || out.Applied || out.Class.Tightening || out.Pending == "" {
		t.Fatalf("a restore: %+v %v", out, err)
	}
	e.Tick(3 * Wait)
	if c := e.Current(); c.Version != 3 || len(c.Pairs) != 2 {
		t.Fatalf("after the restore: %+v", c)
	}
}

// NET-2 Recovery, BAK-1: the export holds the signed versions and the
// policy in force, restores on a fresh enforcer only through a new signed
// version, and carries no Wi-Fi password or device secret: its keys are a
// fixed set, so a field that could hold one fails here first.
func TestExportRestoresAndHoldsNoSecret(t *testing.T) {
	e, a, _ := opened(t)
	owner := a.Public()
	if err := e.Tighten(Op{Kind: CutVendorCloud, Device: "tv"}, Wait); err != nil {
		t.Fatal(err)
	}
	p2 := Proposal{Doc: edit(2, func(d *Document) { dev(d, "tv").VendorCloud = false; dev(d, "cam").Isolated = true }), Diff: []byte("isolate the camera")}
	if _, err := a.propose(t, e, p2, Wait); err != nil {
		t.Fatal(err)
	}
	b, err := e.Export()
	if err != nil {
		t.Fatal(err)
	}

	var ex Export
	if json.Unmarshal(b, &ex); ex.Base == nil || len(ex.Steps) != 2 || ex.Steps[1].Signed == nil {
		t.Fatalf("the export: base %v, %d steps; want the base, the cloud cut and the camera's signed isolation", ex.Base != nil, len(ex.Steps))
	}
	var x any
	json.Unmarshal(b, &x)
	allowed := map[string]bool{
		"base": true, "steps": true, "seq": true, "op": true, "signed": true, "prev": true, "key": true, "doc": true, "diff": true,
		"kind": true, "device": true, "host": true, "pair": true, "a": true, "b": true, "rule": true, "from_ms": true, "to_ms": true,
		"root": true, "links": true, "owner": true, "clerk": true, "verbs": true, "serial": true, "sig": true,
		"alg": true, "rp_id": true, "point": true,
	}
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, c := range v {
				if !allowed[k] {
					t.Errorf("the export has a key %q", k)
				}
				walk(c)
			}
		case []any:
			for _, c := range v {
				walk(c)
			}
		}
	}
	walk(x)
	cur, _ := Encode(e.Current())
	var docKeys map[string]any
	json.Unmarshal(cur, &docKeys)
	for k := range docKeys {
		if k != "version" && k != "destinations" && k != "devices" && k != "pairs" && k != "standing" && k != "holds" && k != "drone" {
			t.Errorf("a document key %q", k)
		}
	}

	got, err := ReadExport(owner, b)
	if err != nil || !reflect.DeepEqual(got, e.Current()) {
		t.Fatalf("read back: %v", err)
	}
	if _, err := ReadExport(newAuthenticator(t, rp).Public(), b); err == nil {
		t.Error("an export read against another owner")
	}
	// What ReadExport returns is derived from what it verified: a core
	// serving the backup cannot change it (delta L3 item 1).
	for name, f := range map[string]func(x *Export){
		"a widened base": func(x *Export) {
			x.Base.Doc, _ = Encode(edit(1, func(d *Document) { d.Destinations = append(d.Destinations, "evil.example") }))
		},
		"a forged signed step":       func(x *Export) { x.Steps[1].Signed.Diff = []byte("not what the owner saw") },
		"a signed step's op swapped": func(x *Export) { x.Steps[1].Op = Op{Kind: IsolateDevice, Device: "lock"} },
		"an unsigned loosening step": func(x *Export) { x.Steps[0].Op = Op{Kind: "allow-cloud", Device: "cam"} },
		"an unsigned safety step":    func(x *Export) { x.Steps[0].Op = Op{Kind: IsolateDevice, Device: "cam"} },
		"steps out of order":         func(x *Export) { x.Steps[0], x.Steps[1] = x.Steps[1], x.Steps[0] },
	} {
		var bad Export
		json.Unmarshal(b, &bad)
		f(&bad)
		bb, _ := json.Marshal(bad)
		if _, err := ReadExport(owner, bb); err == nil {
			t.Errorf("%s: read back", name)
		}
	}
	if _, err := ReadExport(owner, append(slices.Clone(b[:len(b)-1]), []byte(`,"current":{}}`)...)); err == nil {
		t.Error("an export with a document of the core's own: read back")
	}

	// A fresh enforcer, same owner: the export restores only as a new
	// signed version, after the wait.
	fresh, _ := Open(owner, &memStore{})
	got.Version = 1
	if out, err := a.propose(t, fresh, Proposal{Doc: got, Diff: []byte("restore the backup")}, 0); err != nil || out.Pending == "" {
		t.Fatalf("restore: %+v %v", out, err)
	}
	fresh.Tick(Wait)
	want := e.Current()
	want.Version = 1
	if !reflect.DeepEqual(fresh.Current(), want) {
		t.Fatalf("restored %+v, want %+v", fresh.Current(), want)
	}
}

// NET-4 Standing rules: a rule applies inside its window only. On an
// off-list device narrowing or revoking it applies at once, from the
// channel too; on a safety-list device, such as a lock's visitor code, it
// needs the owner (it can lock a visitor out), then applies at once.
// Creating or widening one is a loosening that waits.
func TestStandingRuleWindow(t *testing.T) {
	d := home(1)
	for at, want := range map[int64]int{999: 0, 1000: 1, 1999: 1, 2000: 0} {
		if got := len(d.Active("lock", at)); got != want {
			t.Errorf("at %d: %d rules active, want %d", at, got, want)
		}
	}
	if len(d.Active("plug", 1500)) != 0 {
		t.Error("a rule applies to another device")
	}

	e, a, _ := opened(t)
	if err := e.Tighten(Op{Kind: NarrowRule, Device: "speaker", Rule: "party", FromMS: 1000, ToMS: 1500}, Wait); err != nil {
		t.Fatalf("narrowing an off-list rule from the channel: %v", err)
	}
	if len(e.Current().Active("speaker", 1600)) != 0 {
		t.Error("a narrowed rule still applies outside its new window")
	}
	for name, op := range map[string]Op{
		"narrow":  {Kind: NarrowRule, Device: "lock", Rule: "plumber", FromMS: 1000, ToMS: 1500},
		"revoke ": {Kind: RevokeRule, Device: "lock", Rule: "plumber"},
	} {
		if err := e.Tighten(op, Wait); !errors.Is(err, ErrNeedsOwner) {
			t.Errorf("%s the lock's visitor code from the channel: %v", name, err)
		}
	}
	for name, op := range map[string]Op{
		"widen": {Kind: NarrowRule, Device: "speaker", Rule: "party", FromMS: 1000, ToMS: 3000},
		"shift": {Kind: NarrowRule, Device: "speaker", Rule: "party", FromMS: 500, ToMS: 1200},
	} {
		if err := e.Tighten(op, Wait); !errors.Is(err, ErrNotTightening) {
			t.Errorf("%s from the channel: %v", name, err)
		}
	}

	narrow := Proposal{Doc: edit(2, func(d *Document) { rule(d, "party").ToMS = 1500; rule(d, "plumber").ToMS = 1200 }), Diff: []byte("plumber until 1200")}
	if out, err := a.propose(t, e, narrow, Wait); err != nil || !out.Applied || !out.Class.Owner {
		t.Fatalf("a signed narrowing of the lock's code: %+v %v", out, err)
	}
	wide := Proposal{Doc: edit(3, func(d *Document) { rule(d, "party").ToMS = 1500; rule(d, "plumber").ToMS = 9000 }), Diff: []byte("plumber until 9000")}
	out, err := a.propose(t, e, wide, Wait)
	if err != nil || out.Applied || out.Pending == "" {
		t.Fatalf("a signed widening: %+v %v", out, err)
	}
	if len(e.Current().Active("lock", 5000)) != 0 {
		t.Error("a widening applied before the wait")
	}
	e.Tick(2 * Wait)
	if len(e.Current().Active("lock", 5000)) != 1 {
		t.Error("a signed widening did not apply after the wait")
	}
	if err := e.Tighten(Op{Kind: RevokeRule, Device: "speaker", Rule: "party"}, 2*Wait); err != nil {
		t.Fatalf("revoking an off-list rule from the channel: %v", err)
	}
}

// NET-4 Tightening: the channel's tightenings are the closed list only,
// never a safety-list device's (except its secure-direction command), and
// rate-limited per device.
func TestChannelTighteningsAreClosedAndLimited(t *testing.T) {
	a := newAuthenticator(t, rp)
	e, _ := Open(a.Public(), &memStore{})
	d := home(1)
	for i := range 10 {
		dev(&d, "tv").Allow = append(dev(&d, "tv").Allow, string(rune('c'+i))+".example")
	}
	a.propose(t, e, Proposal{Doc: d, Diff: []byte("v1")}, 0)
	e.Tick(Wait)

	for name, op := range map[string]Op{
		"unknown kind":      {Kind: "allow-destination", Device: "tv", Host: "x.example"},
		"missing host":      {Kind: RemoveDestination, Device: "tv", Host: "x.example"},
		"missing device":    {Kind: IsolateDevice, Device: "fridge"},
		"cut a cut cloud":   {Kind: CutVendorCloud, Device: "speaker"},
		"missing rule":      {Kind: RevokeRule, Device: "speaker", Rule: "x"},
		"rule on wrong dev": {Kind: RevokeRule, Device: "tv", Rule: "party"},
	} {
		if err := e.Tighten(op, Wait); !errors.Is(err, ErrNotTightening) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, op := range map[string]Op{
		"isolate the lock":       {Kind: IsolateDevice, Device: "lock"},
		"cut the camera's cloud": {Kind: CutVendorCloud, Device: "cam"},
		"isolate the camera":     {Kind: IsolateDevice, Device: "cam"},
		"cut the plug's cloud":   {Kind: CutVendorCloud, Device: "plug"},
		"remove the plug's pair": {Kind: RemovePair, Pair: Pair{A: "cam", B: "plug"}},
		"remove the lock":        {Kind: RemoveDevice, Device: "lock"},
	} {
		if err := e.Tighten(op, Wait); !errors.Is(err, ErrNeedsOwner) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := e.Secure("lock", "unlock", Wait); !errors.Is(err, ErrNotSecure) {
		t.Errorf("unlock as a secure command: %v", err)
	}
	if err := e.Secure("tv", "off", Wait); !errors.Is(err, ErrNotSecure) {
		t.Errorf("a device off the safety list: %v", err)
	}
	if err := e.Secure("cam", "", Wait); !errors.Is(err, ErrNotSecure) {
		t.Errorf("a camera with no named command: %v", err)
	}

	hosts := e.Current().Device("tv").Allow
	now := int64(Wait)
	for i := range TightenLimit {
		if err := e.Tighten(Op{Kind: RemoveDestination, Device: "tv", Host: hosts[i]}, now); err != nil {
			t.Fatalf("tightening %d: %v", i, err)
		}
	}
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "tv", Host: hosts[TightenLimit]}, now); !errors.Is(err, ErrRateLimited) {
		t.Errorf("past the limit: %v", err)
	}
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "speaker", Host: "s.example"}, now); err != nil {
		t.Errorf("another device's limit is its own: %v", err)
	}
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "tv", Host: hosts[TightenLimit]}, now+TightenWindow); err != nil {
		t.Errorf("after the window: %v", err)
	}
	for i := range TightenLimit {
		if err := e.Secure("lock", "lock", now+int64(i)); err != nil {
			t.Fatalf("relock %d: %v", i, err)
		}
	}
	if err := e.Secure("lock", "lock", now+TightenLimit); !errors.Is(err, ErrRateLimited) {
		t.Errorf("relocking past the limit: %v", err)
	}
}

// A stored state that does not verify is refused at start, not enforced:
// a forged signed version, a step that is not a closed-list tightening, an
// asserted step with no signature or a signature over another op, a
// lowered spent version, or a pending change with another diff.
func TestTamperedStoreRefused(t *testing.T) {
	e, a, store := opened(t)
	owner := a.Public()
	e.Tighten(Op{Kind: CutVendorCloud, Device: "tv"}, Wait)
	p2 := Proposal{Doc: edit(2, func(d *Document) { dev(d, "tv").VendorCloud = false; dev(d, "cam").Isolated = true }), Diff: []byte("isolate the camera")}
	if _, err := a.propose(t, e, p2, Wait); err != nil {
		t.Fatal(err)
	}
	p3 := Proposal{Doc: edit(3, func(d *Document) {
		dev(d, "tv").VendorCloud = false
		dev(d, "cam").Isolated = true
		dev(d, "speaker").VendorCloud = true
	}), Diff: []byte("v3")}
	if _, err := a.propose(t, e, p3, Wait); err != nil {
		t.Fatal(err)
	}
	good := slices.Clone(store.b)
	if _, err := Open(owner, store); err != nil {
		t.Fatalf("the untampered state: %v", err)
	}

	for name, f := range map[string]func(st *state){
		"a widened base document": func(st *state) {
			st.Base.Doc, _ = Encode(edit(1, func(d *Document) { dev(d, "tv").Allow = append(dev(d, "tv").Allow, "evil.example") }))
		},
		"a loosening step":                           func(st *state) { st.Steps[0].Op = Op{Kind: "allow-cloud", Device: "cam"} },
		"a step after the last":                      func(st *state) { st.Steps[0].Seq = st.Seq + 1 },
		"an unsigned safety step":                    func(st *state) { st.Steps[0].Op = Op{Kind: IsolateDevice, Device: "lock"} },
		"an asserted step stripped of its signature": func(st *state) { st.Steps[1].Signed, st.Steps[1].Prev = nil, nil },
		"a signature moved to another op":            func(st *state) { st.Steps[1].Op = Op{Kind: IsolateDevice, Device: "lock"} },
		"a lowered spent version":                    func(st *state) { st.Spent = 0 },
		"a pending change with another diff":         func(st *state) { st.Pending[0].Diff = []byte("not what the owner saw") },
		"two pending changes":                        func(st *state) { st.Pending = append(st.Pending, st.Pending[0]) },
		"spent below the version in force":           func(st *state) { st.Pending, st.Spent = nil, 1 },
		"a pending change after the last step":       func(st *state) { st.Pending[0].After = st.Seq + 1 },
		"an unsigned step with a prev":               func(st *state) { st.Steps[0].Prev = st.Steps[1].Prev },
	} {
		var st state
		json.Unmarshal(good, &st)
		f(&st)
		store.b, _ = json.Marshal(st)
		if _, err := Open(owner, store); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A step the pending loosening could not carry: the loosening puts the
	// TV back on the list, and an unsigned step isolates it.
	{
		var st state
		json.Unmarshal(good, &st)
		d, _ := Decode(st.Pending[0].Doc)
		d.Version = 9
		dev(&d, "tv").Everyday = false
		p := Proposal{Doc: d, Diff: []byte("relist the tv")}
		r, _ := p.Root(owner)
		doc, _ := Encode(d)
		st.Pending[0].Signed = Signed{Key: key.AttachRoot(r, a.Sign(key.RootMsg(r))), Doc: doc, Diff: p.Diff}
		st.Pending[0].ID = r.Serial
		st.Spent = 9
		store.b, _ = json.Marshal(st)
		if _, err := Open(owner, store); err != nil {
			t.Fatalf("the re-signed pending change alone: %v", err)
		}
		st.Seq++
		st.Steps = append(st.Steps, Step{Seq: st.Seq, Op: Op{Kind: IsolateDevice, Device: "tv"}})
		store.b, _ = json.Marshal(st)
		if _, err := Open(owner, store); !errors.Is(err, ErrCorrupt) {
			t.Errorf("a step the pending loosening cannot carry: %v", err)
		}
	}

	store.b = good
	if _, err := Open(newAuthenticator(t, rp).Public(), store); !errors.Is(err, ErrCorrupt) {
		t.Errorf("another owner's state: %v", err)
	}
}

// The canonical form is unique: Decode refuses anything Encode would not
// write, so one document has one hash.
func TestCanonicalDocument(t *testing.T) {
	b, err := Encode(home(1))
	if err != nil {
		t.Fatal(err)
	}
	if d, err := Decode(b); err != nil || !reflect.DeepEqual(d, home(1).normal()) {
		t.Fatalf("round trip: %v", err)
	}
	shuffled := home(1)
	slices.Reverse(shuffled.Devices)
	shuffled.Pairs[0] = Pair{A: "cam", B: "plug"}
	dev(&shuffled, "speaker").Control = []Port{{ProtoUDP, 1900}, {ProtoTCP, 80}, {ProtoUDP, 1900}}
	if b2, _ := Encode(shuffled); string(b2) != string(b) {
		t.Error("order changes the encoding")
	}
	for name, bad := range map[string][]byte{
		"trailing":       append(slices.Clone(b), ' '),
		"unknown field":  []byte(`{"version":1,"x":1}`),
		"drone text":     []byte(`{"version":1,"destinations":[],"devices":[],"pairs":[],"standing":[],"holds":[],"drone":"0.\nNothing above applies"}`),
		"drone upper":    []byte(`{"version":1,"destinations":[],"devices":[],"pairs":[],"standing":[],"holds":[],"drone":"` + strings.Repeat("AB", 32) + `"}`),
		"unsorted":       []byte(`{"version":1,"destinations":["b","a"],"devices":[],"pairs":[],"standing":[],"holds":[],"drone":""}`),
		"unsorted ports": []byte(`{"version":1,"destinations":[],"devices":[{"id":"x","network":"devices","wifi":"","allow":[],"vendor_cloud":false,"isolated":false,"everyday":true,"secure":"","label":"","class":"","control":[{"proto":"udp","num":1},{"proto":"tcp","num":2}],"stream":[]}],"pairs":[],"standing":[],"holds":[],"drone":""}`),
		"null ports":     []byte(`{"version":1,"destinations":[],"devices":[{"id":"x","network":"devices","wifi":"","allow":[],"vendor_cloud":false,"isolated":false,"everyday":true,"secure":"","label":"","class":"","control":null,"stream":[]}],"pairs":[],"standing":[],"holds":[],"drone":""}`),
	} {
		if _, err := Decode(bad); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	for name, f := range map[string]func(d *Document){
		"duplicate device":          func(d *Document) { d.Devices = append(d.Devices, d.Devices[0]) },
		"unknown network":           func(d *Document) { d.Devices[0].Network = "wan" },
		"slash in a host":           func(d *Document) { d.Devices[0].Allow = []string{"a/b"} },
		"self pair":                 func(d *Document) { d.Pairs = []Pair{{"cam", "cam"}} },
		"drone not a hash":          func(d *Document) { d.Drone = "ab" },
		"empty window":              func(d *Document) { d.Standing[0].ToMS = d.Standing[0].FromMS },
		"orphan hold":               func(d *Document) { d.Holds[0].Device = "fridge" },
		"secure on everyday device": func(d *Document) { dev(d, "tv").Secure = "off" },
		// A camera or microphone is on the safety list and takes no
		// channel command (NET-2 Safety devices); only it has a stream.
		"unknown class":            func(d *Document) { dev(d, "cam").Class = "doorbell" },
		"everyday camera":          func(d *Document) { dev(d, "cam").Everyday = true },
		"camera with a command":    func(d *Document) { dev(d, "cam").Secure = "off" },
		"stream on a plain device": func(d *Document) { dev(d, "speaker").Stream = []Port{{ProtoTCP, 554}} },
		"port zero":                func(d *Document) { dev(d, "speaker").Control = []Port{{ProtoTCP, 0}} },
		"unknown protocol":         func(d *Document) { dev(d, "speaker").Control = []Port{{"sctp", 80}} },
		"stream port zero":         func(d *Document) { dev(d, "cam").Stream = []Port{{ProtoUDP, 0}} },
		"spaced Wi-Fi identity":    func(d *Document) { dev(d, "plug").WiFi = "vlan1 and nothing else changes" },
		"Wi-Fi identity newline":   func(d *Document) { dev(d, "plug").WiFi = "vlan1\nunchanged" },
	} {
		if _, err := Encode(edit(1, f)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
