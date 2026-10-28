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

// home is a small home: a plug with a vendor cloud, a camera paired with
// it, and a lock on the safety list with a visitor's standing rule.
func home(v uint64) Document {
	return Document{
		Version:      v,
		Destinations: []string{"mail.example", "models.example"},
		Devices: []Device{
			{ID: "plug", Network: NetDevices, WiFi: "vlan101", Allow: []string{"a.example", "b.example"}, VendorCloud: true},
			{ID: "cam", Network: NetDevices, WiFi: "vlan102", Allow: []string{"cam.example"}},
			{ID: "lock", Network: NetDevices, Allow: []string{"lock.example"}, VendorCloud: true, Secure: "lock"},
		},
		Pairs:    []Pair{{A: "plug", B: "cam"}},
		Standing: []StandingRule{{ID: "plumber", Device: "lock", Action: "keypad-code", FromMS: 1000, ToMS: 2000}},
		Holds:    []Hold{{Device: "cam", Kind: HoldFirmware}},
	}
}

// edit is home(v) changed by f.
func edit(v uint64, f func(d *Document)) Document {
	d := home(v)
	f(&d)
	return d
}

func dev(d *Document, id string) *Device { return d.Device(id) }

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

// NET-4 Tightening: only the closed-list kinds, one at a time, classify as
// a tightening. Every other change to every field of the document, any mix
// and any pair of tightenings is a loosening.
func TestClassifyClosedList(t *testing.T) {
	type want struct {
		kind  string // "" = loosening
		owner bool
	}
	cases := map[string]struct {
		f func(d *Document)
		w want
	}{
		// The closed list.
		"remove a host from one device": {func(d *Document) { dev(d, "plug").Allow = []string{"b.example"} }, want{RemoveDestination, false}},
		"cut one vendor cloud":          {func(d *Document) { dev(d, "plug").VendorCloud = false }, want{CutVendorCloud, false}},
		"remove one pair":               {func(d *Document) { d.Pairs = nil }, want{RemovePair, false}},
		"isolate one device":            {func(d *Document) { dev(d, "cam").Isolated = true }, want{IsolateDevice, false}},
		"remove one device":             {func(d *Document) { d.Devices = slices.Delete(d.Devices, 1, 2); d.Pairs = nil; d.Holds = nil }, want{RemoveDevice, false}},
		"remove a device with its pair": {func(d *Document) { d.Devices = slices.Delete(d.Devices, 0, 1); d.Pairs = nil }, want{RemoveDevice, false}},
		"narrow a standing rule":        {func(d *Document) { d.Standing[0].ToMS = 1500 }, want{NarrowRule, false}},
		"revoke a standing rule":        {func(d *Document) { d.Standing = nil }, want{RevokeRule, false}},
		// The closed list on a safety-list device needs the owner.
		"cut the lock's vendor cloud": {func(d *Document) { dev(d, "lock").VendorCloud = false }, want{CutVendorCloud, true}},
		"isolate the lock":            {func(d *Document) { dev(d, "lock").Isolated = true }, want{IsolateDevice, true}},
		"remove the lock's host":      {func(d *Document) { dev(d, "lock").Allow = nil }, want{RemoveDestination, true}},
		"remove the lock":             {func(d *Document) { d.Devices = d.Devices[:2]; d.Standing = nil }, want{RemoveDevice, true}},

		// Every field, the other way or sideways: loosenings.
		"version only":              {func(d *Document) { d.Version = 9 }, want{}},
		"add a core destination":    {func(d *Document) { d.Destinations = append(d.Destinations, "x.example") }, want{}},
		"remove a core destination": {func(d *Document) { d.Destinations = d.Destinations[:1] }, want{}},
		"add a device":              {func(d *Document) { d.Devices = append(d.Devices, Device{ID: "tv", Network: NetDevices}) }, want{}},
		"move a device's network":   {func(d *Document) { dev(d, "plug").Network = NetHousehold }, want{}},
		"change a Wi-Fi identity":   {func(d *Document) { dev(d, "plug").WiFi = "vlan201" }, want{}},
		"clear a Wi-Fi identity":    {func(d *Document) { dev(d, "plug").WiFi = "" }, want{}},
		"add a host to a device":    {func(d *Document) { dev(d, "cam").Allow = append(dev(d, "cam").Allow, "x.example") }, want{}},
		"swap a device's host":      {func(d *Document) { dev(d, "cam").Allow = []string{"x.example"} }, want{}},
		"allow a vendor cloud":      {func(d *Document) { dev(d, "cam").VendorCloud = true }, want{}},
		"take the lock off safety":  {func(d *Document) { dev(d, "lock").Secure = "" }, want{}},
		"rename the secure command": {func(d *Document) { dev(d, "lock").Secure = "unlock" }, want{}},
		"put the plug on safety":    {func(d *Document) { dev(d, "plug").Secure = "off" }, want{}},
		"add a pair":                {func(d *Document) { d.Pairs = append(d.Pairs, Pair{A: "lock", B: "cam"}) }, want{}},
		"add a standing rule":       {func(d *Document) { d.Standing = append(d.Standing, StandingRule{"x", "lock", "keypad-code", 1, 2}) }, want{}},
		"widen a standing rule":     {func(d *Document) { d.Standing[0].ToMS = 2500 }, want{}},
		"shift a standing rule":     {func(d *Document) { d.Standing[0].FromMS, d.Standing[0].ToMS = 1500, 2500 }, want{}},
		"change a rule's action":    {func(d *Document) { d.Standing[0].Action = "unlock" }, want{}},
		"move a rule to a device":   {func(d *Document) { d.Standing[0].Device = "cam" }, want{}},
		"rename a rule":             {func(d *Document) { d.Standing[0].ID = "electrician" }, want{}},
		"add a hold":                {func(d *Document) { d.Holds = append(d.Holds, Hold{"plug", HoldFix}) }, want{}},
		"remove a hold":             {func(d *Document) { d.Holds = nil }, want{}},
		"change a hold's kind":      {func(d *Document) { d.Holds[0].Kind = HoldFix }, want{}},
		"change the drone policy":   {func(d *Document) { d.Drone = "ab" }, want{}},
		"rename a device":           {func(d *Document) { dev(d, "plug").ID = "plug2"; d.Pairs[0].A = "plug2" }, want{}},

		// Mixes, doubles and broken documents.
		"tighten and loosen":                         {func(d *Document) { dev(d, "plug").Allow = []string{"b.example", "x.example"} }, want{}},
		"two tightenings":                            {func(d *Document) { dev(d, "plug").Allow = nil }, want{}},
		"tighten two kinds":                          {func(d *Document) { dev(d, "plug").VendorCloud = false; d.Pairs = nil }, want{}},
		"isolate and narrow":                         {func(d *Document) { dev(d, "cam").Isolated = true; d.Standing[0].ToMS = 1500 }, want{}},
		"remove a device, keep its pair (malformed)": {func(d *Document) { d.Devices = d.Devices[1:] }, want{}},
		"no change":                                  {func(d *Document) {}, want{}},
	}
	for name, c := range cases {
		got := Classify(home(1), edit(1, c.f))
		if got.Tightening != (c.w.kind != "") || got.Op.Kind != c.w.kind || got.Owner != c.w.owner {
			t.Errorf("%s: %+v, want %+v", name, got, c.w)
		}
	}
	if c := Classify(edit(1, func(d *Document) { dev(d, "cam").Isolated = true }), home(1)); c.Tightening {
		t.Error("un-isolating a device classified as a tightening")
	}
	if c := Classify(edit(1, func(d *Document) { dev(d, "cam").Isolated = true }), edit(1, func(d *Document) { dev(d, "cam").Isolated = true })); c.Tightening {
		t.Error("no change classified as a tightening")
	}

	// The table above names every field: adding a field to the document
	// without a case here fails.
	covered := map[string][]string{
		"Document":     {"Version", "Destinations", "Devices", "Pairs", "Standing", "Holds", "Drone"},
		"Device":       {"ID", "Network", "WiFi", "Allow", "VendorCloud", "Isolated", "Secure"},
		"Pair":         {"A", "B"},
		"StandingRule": {"ID", "Device", "Action", "FromMS", "ToMS"},
		"Hold":         {"Device", "Kind"},
	}
	for _, v := range []any{Document{}, Device{}, Pair{}, StandingRule{}, Hold{}} {
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
// wait and the cancel survive a restart.
func TestLooseningWaitsAndCancels(t *testing.T) {
	a := newAuthenticator(t, rp)
	owner := a.Public()
	store := &memStore{}
	e, err := Open(owner, store)
	if err != nil {
		t.Fatal(err)
	}
	const t0 = 1_000_000
	p1 := Proposal{Doc: home(1), Diff: []byte("first policy")}
	out, err := e.Propose(p1, sign(t, a, owner, p1), t0)
	if err != nil || out.Applied || out.Pending == "" || out.DueMS != t0+Wait {
		t.Fatalf("a loosening: %+v %v", out, err)
	}
	if got, _ := e.Tick(t0 + Wait - 1); got != nil || e.Current().Version != 0 {
		t.Fatalf("applied before the wait: %v", got)
	}

	// Restart inside the wait: the pending change and its deadline survive.
	if e, err = Open(owner, store); err != nil {
		t.Fatal(err)
	}
	if ps := e.Pending(); len(ps) != 1 || ps[0].DueMS != t0+Wait {
		t.Fatalf("pending after restart: %+v", ps)
	}
	if got, err := e.Tick(t0 + Wait); err != nil || len(got) != 1 || e.Current().Version != 1 || e.Current().Device("lock") == nil {
		t.Fatalf("not applied at +10 minutes: %v %v", got, err)
	}

	// A second loosening, cancelled, then a restart: never applied.
	const t1 = 5_000_000
	p2 := Proposal{Doc: edit(2, func(d *Document) { dev(d, "cam").VendorCloud = true }), Diff: []byte("allow cam's cloud")}
	out, err = e.Propose(p2, sign(t, a, owner, p2), t1)
	if err != nil || out.Pending == "" {
		t.Fatal(out, err)
	}
	if err := e.Cancel(out.Pending); err != nil {
		t.Fatal(err)
	}
	if err := e.Cancel(out.Pending); !errors.Is(err, ErrNoPending) {
		t.Errorf("a second cancel: %v", err)
	}
	if e, err = Open(owner, store); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.Tick(t1 + 100*Wait); got != nil || e.Current().Version != 1 || dev(ptr(e.Current()), "cam").VendorCloud {
		t.Fatalf("a cancelled loosening applied: %v", got)
	}

	// A tightening applied while a loosening waits is not undone by it.
	p3 := Proposal{Doc: edit(3, func(d *Document) { dev(d, "cam").VendorCloud = true }), Diff: []byte("allow cam's cloud")}
	if _, err := e.Propose(p3, sign(t, a, owner, p3), t1); err != nil {
		t.Fatal(err)
	}
	if err := e.Tighten(Op{Kind: CutVendorCloud, Device: "plug"}, t1+1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Tick(t1 + Wait); err != nil {
		t.Fatal(err)
	}
	cur := e.Current()
	if cur.Version != 3 || !dev(&cur, "cam").VendorCloud || dev(&cur, "plug").VendorCloud {
		t.Fatalf("after the loosening: %+v", cur)
	}
	if e, err = Open(owner, store); err != nil || !reflect.DeepEqual(e.Current(), cur) {
		t.Fatalf("restart changed the policy: %v", err)
	}

	// A signed tightening applies at once.
	p4 := Proposal{Doc: edit(4, func(d *Document) {
		dev(d, "cam").VendorCloud = true
		dev(d, "plug").VendorCloud = false
		dev(d, "lock").Isolated = true
	}), Diff: []byte("isolate the lock")}
	if out, err := e.Propose(p4, sign(t, a, owner, p4), t1+Wait); err != nil || !out.Applied || !out.Class.Owner || e.Current().Version != 4 {
		t.Fatalf("a signed tightening of the lock: %+v %v", out, err)
	}
}

func ptr(d Document) *Document { return &d }

// NET-2 Recovery: a version at or below the one in force or pending is
// refused, a replayed assertion with it; restoring an older document takes
// a new, higher version with a fresh assertion, and is then a loosening
// that waits.
func TestOlderVersionRefused(t *testing.T) {
	a := newAuthenticator(t, rp)
	owner := a.Public()
	store := &memStore{}
	e, _ := Open(owner, store)
	p1 := Proposal{Doc: home(1), Diff: []byte("v1")}
	sig1 := sign(t, a, owner, p1)
	if _, err := e.Propose(p1, sig1, 0); err != nil {
		t.Fatal(err)
	}
	e.Tick(Wait)
	p2 := Proposal{Doc: edit(2, func(d *Document) { d.Pairs = nil }), Diff: []byte("v2: remove the pair")}
	if out, err := e.Propose(p2, sign(t, a, owner, p2), Wait); err != nil || !out.Applied {
		t.Fatal(out, err)
	}
	if _, err := e.Propose(p1, sig1, Wait); !errors.Is(err, ErrNotRising) {
		t.Errorf("v1 replayed: %v", err)
	}
	p1b := Proposal{Doc: home(1), Diff: []byte("v1 again")}
	if _, err := e.Propose(p1b, sign(t, a, owner, p1b), Wait); !errors.Is(err, ErrNotRising) {
		t.Errorf("v1 freshly signed: %v", err)
	}
	same := Proposal{Doc: edit(2, func(d *Document) { d.Pairs = nil; dev(d, "cam").VendorCloud = true }), Diff: []byte("v2 again")}
	if _, err := e.Propose(same, sign(t, a, owner, same), Wait); !errors.Is(err, ErrNotRising) {
		t.Errorf("an equal version: %v", err)
	}
	if e.Current().Version != 2 || len(e.Pending()) != 0 {
		t.Fatal("a refused version changed the engine")
	}

	// Restore v1's document as v3: a fresh tap, a loosening, the wait.
	restore := Proposal{Doc: home(3), Diff: []byte("restore v1: add the pair back")}
	out, err := e.Propose(restore, sign(t, a, owner, restore), 2*Wait)
	if err != nil || out.Applied || out.Class.Tightening || out.Pending == "" {
		t.Fatalf("a restore: %+v %v", out, err)
	}
	// While v3 waits, v3 again is refused too.
	again := Proposal{Doc: edit(3, func(d *Document) {}), Diff: []byte("other")}
	if _, err := e.Propose(again, sign(t, a, owner, again), 2*Wait); !errors.Is(err, ErrNotRising) {
		t.Errorf("a version equal to a pending one: %v", err)
	}
	e.Tick(3 * Wait)
	if c := e.Current(); c.Version != 3 || len(c.Pairs) != 1 {
		t.Fatalf("after the restore: %+v", c)
	}

	// A loosening still waiting when the owner signs a later version is
	// superseded by it: it never applies over the later one.
	p4 := Proposal{Doc: edit(4, func(d *Document) { dev(d, "cam").VendorCloud = true }), Diff: []byte("v4: allow cam's cloud")}
	if _, err := e.Propose(p4, sign(t, a, owner, p4), 3*Wait); err != nil {
		t.Fatal(err)
	}
	p5 := Proposal{Doc: edit(5, func(d *Document) { d.Pairs = nil }), Diff: []byte("v5: remove the pair")}
	if out, err := e.Propose(p5, sign(t, a, owner, p5), 3*Wait); err != nil || !out.Applied {
		t.Fatal(out, err)
	}
	e.Tick(5 * Wait)
	if c := e.Current(); c.Version != 5 || dev(&c, "cam").VendorCloud || len(e.Pending()) != 0 {
		t.Fatalf("a superseded loosening applied: %+v", c)
	}
}

// NET-4 Standing rules: a visitor's keypad code applies inside its window
// only. Narrowing or revoking it applies at once, from the channel too;
// creating or widening it is a loosening that waits.
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

	a := newAuthenticator(t, rp)
	owner := a.Public()
	e, _ := Open(owner, &memStore{})
	p := Proposal{Doc: d, Diff: []byte("v1")}
	e.Propose(p, sign(t, a, owner, p), 0)
	e.Tick(Wait)

	if err := e.Tighten(Op{Kind: NarrowRule, Device: "lock", Rule: "plumber", FromMS: 1000, ToMS: 1500}, Wait); err != nil {
		t.Fatalf("narrowing from the channel: %v", err)
	}
	if len(e.Current().Active("lock", 1600)) != 0 {
		t.Error("a narrowed rule still applies outside its new window")
	}
	if err := e.Tighten(Op{Kind: NarrowRule, Device: "lock", Rule: "plumber", FromMS: 1000, ToMS: 3000}, Wait); !errors.Is(err, ErrNotTightening) {
		t.Errorf("widening from the channel: %v", err)
	}
	if err := e.Tighten(Op{Kind: NarrowRule, Device: "lock", Rule: "plumber", FromMS: 500, ToMS: 1200}, Wait); !errors.Is(err, ErrNotTightening) {
		t.Errorf("shifting from the channel: %v", err)
	}

	wide := Proposal{Doc: edit(2, func(d *Document) { d.Standing[0].ToMS = 9000 }), Diff: []byte("plumber until 9000")}
	out, err := e.Propose(wide, sign(t, a, owner, wide), Wait)
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
	if err := e.Tighten(Op{Kind: RevokeRule, Device: "lock", Rule: "plumber"}, 2*Wait); err != nil || len(e.Current().Standing) != 0 {
		t.Fatalf("revoking from the channel: %v", err)
	}
}

// NET-4 Tightening: the channel's tightenings are the closed list only,
// never a safety-list device's (except its secure-direction command), and
// rate-limited per device.
func TestChannelTighteningsAreClosedAndLimited(t *testing.T) {
	a := newAuthenticator(t, rp)
	owner := a.Public()
	e, _ := Open(owner, &memStore{})
	d := home(1)
	for i := range 10 {
		d.Devices[0].Allow = append(d.Devices[0].Allow, string(rune('c'+i))+".example")
	}
	p := Proposal{Doc: d, Diff: []byte("v1")}
	e.Propose(p, sign(t, a, owner, p), 0)
	e.Tick(Wait)

	for name, op := range map[string]Op{
		"unknown kind":      {Kind: "allow-destination", Device: "plug", Host: "x.example"},
		"missing host":      {Kind: RemoveDestination, Device: "plug", Host: "x.example"},
		"missing device":    {Kind: IsolateDevice, Device: "tv"},
		"cut a cut cloud":   {Kind: CutVendorCloud, Device: "cam"},
		"missing rule":      {Kind: RevokeRule, Device: "lock", Rule: "x"},
		"rule on wrong dev": {Kind: RevokeRule, Device: "cam", Rule: "plumber"},
	} {
		if err := e.Tighten(op, Wait); !errors.Is(err, ErrNotTightening) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, op := range map[string]Op{
		"isolate the lock":   {Kind: IsolateDevice, Device: "lock"},
		"cut the lock cloud": {Kind: CutVendorCloud, Device: "lock"},
		"remove the lock":    {Kind: RemoveDevice, Device: "lock"},
	} {
		if err := e.Tighten(op, Wait); !errors.Is(err, ErrNeedsOwner) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := e.Secure("lock", "unlock", Wait); !errors.Is(err, ErrNotSecure) {
		t.Errorf("unlock as a secure command: %v", err)
	}
	if err := e.Secure("plug", "off", Wait); !errors.Is(err, ErrNotSecure) {
		t.Errorf("a device off the safety list: %v", err)
	}

	hosts := e.Current().Device("plug").Allow
	now := int64(Wait)
	for i := range TightenLimit {
		if err := e.Tighten(Op{Kind: RemoveDestination, Device: "plug", Host: hosts[i]}, now); err != nil {
			t.Fatalf("tightening %d: %v", i, err)
		}
	}
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "plug", Host: hosts[TightenLimit]}, now); !errors.Is(err, ErrRateLimited) {
		t.Errorf("past the limit: %v", err)
	}
	if err := e.Tighten(Op{Kind: IsolateDevice, Device: "cam"}, now); err != nil {
		t.Errorf("another device's limit is its own: %v", err)
	}
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "plug", Host: hosts[TightenLimit]}, now+TightenWindow); err != nil {
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
// a forged signed version, or a step that is not a closed-list tightening.
func TestTamperedStoreRefused(t *testing.T) {
	a := newAuthenticator(t, rp)
	owner := a.Public()
	store := &memStore{}
	e, _ := Open(owner, store)
	p := Proposal{Doc: home(1), Diff: []byte("v1")}
	e.Propose(p, sign(t, a, owner, p), 0)
	e.Tick(Wait)
	e.Tighten(Op{Kind: CutVendorCloud, Device: "plug"}, Wait)
	good := slices.Clone(store.b)

	var st state
	json.Unmarshal(good, &st)
	wider := edit(1, func(d *Document) { dev(d, "plug").Allow = append(dev(d, "plug").Allow, "evil.example") })
	st.Base.Doc, _ = Encode(wider)
	store.b, _ = json.Marshal(st)
	if _, err := Open(owner, store); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a widened stored document: %v", err)
	}

	json.Unmarshal(good, &st)
	st.Steps[0].Op = Op{Kind: "allow-cloud", Device: "cam"}
	store.b, _ = json.Marshal(st)
	if _, err := Open(owner, store); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a loosening step: %v", err)
	}

	json.Unmarshal(good, &st)
	st.Steps[0].Seq = st.Seq + 1
	store.b, _ = json.Marshal(st)
	if _, err := Open(owner, store); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a step from after the last one: %v", err)
	}

	p2 := Proposal{Doc: edit(2, func(d *Document) { dev(d, "cam").VendorCloud = true }), Diff: []byte("v2")}
	store.b = good
	e, _ = Open(owner, store)
	if _, err := e.Propose(p2, sign(t, a, owner, p2), Wait); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(store.b, &st)
	st.Pending[0].Diff = []byte("something the owner did not see")
	store.b, _ = json.Marshal(st)
	if _, err := Open(owner, store); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a pending change with another diff: %v", err)
	}
	json.Unmarshal(good, &st)

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
	shuffled.Pairs[0] = Pair{A: "plug", B: "cam"}
	if b2, _ := Encode(shuffled); string(b2) != string(b) {
		t.Error("order changes the encoding")
	}
	for name, bad := range map[string][]byte{
		"trailing":      append(slices.Clone(b), ' '),
		"unknown field": []byte(`{"version":1,"x":1}`),
		"unsorted":      []byte(`{"version":1,"destinations":["b","a"],"devices":[],"pairs":[],"standing":[],"holds":[],"drone":""}`),
	} {
		if _, err := Decode(bad); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	for name, f := range map[string]func(d *Document){
		"duplicate device": func(d *Document) { d.Devices = append(d.Devices, d.Devices[0]) },
		"unknown network":  func(d *Document) { d.Devices[0].Network = "wan" },
		"slash in a host":  func(d *Document) { d.Devices[0].Allow = []string{"a/b"} },
		"self pair":        func(d *Document) { d.Pairs = []Pair{{"cam", "cam"}} },
		"empty window":     func(d *Document) { d.Standing[0].ToMS = d.Standing[0].FromMS },
		"orphan hold":      func(d *Document) { d.Holds[0].Device = "tv" },
	} {
		if _, err := Encode(edit(1, f)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
