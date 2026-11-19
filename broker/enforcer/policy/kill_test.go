package policy

// REQ: STO-4, NET-4, NET-6

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// openWith is an engine whose policy in force is d, signed by a.
func openWith(t *testing.T, d Document) (*Engine, *authenticator, *memStore) {
	t.Helper()
	a := newAuthenticator(t, rp)
	store := &memStore{}
	e, err := Open(a.Public(), store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.propose(t, e, Proposal{Doc: d, Diff: []byte("v")}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Tick(Wait); err != nil {
		t.Fatal(err)
	}
	return e, a, store
}

// Usual hours are [From, To): From is usual, To is not; and valid reads
// each bound inclusively.
func TestHoursBoundaries(t *testing.T) {
	h := Hours{From: 7, To: 22}
	for hour, want := range map[int]bool{6: false, 7: true, 21: true, 22: false} {
		if h.Usual(hour) != want {
			t.Errorf("%v.Usual(%d) = %v", h, hour, !want)
		}
	}
	for _, c := range []struct {
		h    Hours
		want bool
	}{
		{Hours{23, 1}, true}, {Hours{0, 1}, true}, {Hours{5, 24}, true},
		{Hours{24, 1}, false}, {Hours{5, 0}, false}, {Hours{5, 25}, false}, {Hours{0, 24}, false}, {Hours{5, 5}, false},
	} {
		if c.h.valid() != c.want {
			t.Errorf("%v.valid() = %v", c.h, !c.want)
		}
	}
}

// Decode's refusals keep their own reasons: unknown fields and trailing
// data are malformed, a document that fails check says why.
func TestDecodeRefusalReasons(t *testing.T) {
	b, err := Encode(home(1))
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string][]byte{
		"unknown field": append([]byte(`{"zz":1,`), b[1:]...),
		"trailing data": append(append([]byte{}, b...), []byte(" {}")...),
		"not json":      []byte("{"),
	} {
		if _, err := Decode(in); err == nil || err.Error() != ErrMalformed.Error() {
			t.Errorf("%s: %v, want %v alone", name, err, ErrMalformed)
		}
	}
	bad := bytes.Replace(b, []byte(`"id":"tv"`), []byte(`"id":"t v"`), 1)
	if _, err := Decode(bad); err == nil || !strings.Contains(err.Error(), `device id "t v"`) {
		t.Errorf("a document that fails check: %v", err)
	}
	if _, err := Hash(edit(1, func(d *Document) { d.Destinations = []string{"a b"} })); err == nil {
		t.Error("Hash of a document that fails check")
	}
}

// normal writes empty maps as absent, copies the usual hours, and sorts and
// deduplicates pairs, holds and ports.
func TestNormalForm(t *testing.T) {
	d := home(1)
	d.Caps, d.Basis = map[string]uint64{}, map[string]string{}
	h := Hours{From: 6, To: 23}
	dev(&d, "lock").UsualHours = &h
	d.Pairs = []Pair{{A: "tv", B: "speaker"}, {A: "cam", B: "plug"}, {A: "speaker", B: "tv"}}
	d.Holds = []Hold{{Device: "lock", Kind: HoldFix}, {Device: "cam", Kind: HoldFirmware}, {Device: "lock", Kind: HoldFix}}
	n := d.normal()
	if n.Caps != nil || n.Basis != nil {
		t.Errorf("empty maps kept: %v %v", n.Caps, n.Basis)
	}
	n.Device("lock").UsualHours.From = 9
	if h.From != 6 {
		t.Error("normal's usual hours alias the input's")
	}
	if want := []Pair{{A: "cam", B: "plug"}, {A: "speaker", B: "tv"}}; !reflect.DeepEqual(n.Pairs, want) {
		t.Errorf("pairs %v, want %v", n.Pairs, want)
	}
	if want := []Hold{{Device: "cam", Kind: HoldFirmware}, {Device: "lock", Kind: HoldFix}}; !reflect.DeepEqual(n.Holds, want) {
		t.Errorf("holds %v, want %v", n.Holds, want)
	}
	got := ports([]Port{{ProtoUDP, 1}, {ProtoTCP, 80}, {ProtoTCP, 22}, {ProtoUDP, 1}})
	if want := []Port{{ProtoTCP, 22}, {ProtoTCP, 80}, {ProtoUDP, 1}}; !reflect.DeepEqual(got, want) {
		t.Errorf("ports %v, want %v", got, want)
	}
}

// An mDNS key holds each label's length, so labels split differently are
// different names.
func TestMDNSKeyLengths(t *testing.T) {
	if MDNSKey([]string{"ab", "c"}) == MDNSKey([]string{"a", "bc"}) {
		t.Error("two names with labels split differently share a key")
	}
}

// check refuses each malformed field it reads.
func TestCheckRefusals(t *testing.T) {
	for name, f := range map[string]func(*Document){
		"label":            func(d *Document) { dev(d, "plug").Label = "weird" },
		"class":            func(d *Document) { dev(d, "plug").Class = "toaster" },
		"secure, everyday": func(d *Document) { dev(d, "tv").Secure = "off" },
		"destination":      func(d *Document) { d.Destinations = append(d.Destinations, "a b") },
		"rule twice":       func(d *Document) { d.Standing = append(d.Standing, d.Standing[0]) },
		"drone not hex":    func(d *Document) { d.Drone = strings.Repeat("z", 64) },
	} {
		if _, err := Encode(edit(1, f)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Encode(edit(1, func(d *Document) { d.Drone = strings.Repeat("ab", 32) })); err != nil {
		t.Errorf("a drone hash refused: %v", err)
	}
}

// Classify reads a change from or to a document that fails check as a
// loosening, even when the change would remove what fails.
func TestClassifyInvalidIsLoosening(t *testing.T) {
	o := edit(1, func(d *Document) { dev(d, "tv").Label = "weird" })
	n := edit(1, func(d *Document) {
		d.Devices = without(d.Devices, func(x Device) bool { return x.ID == "tv" })
		d.Pairs = without(d.Pairs, func(p Pair) bool { return p.A == "tv" || p.B == "tv" })
	})
	if c := Classify(o, n); c.Tightening {
		t.Errorf("a change from a malformed document classified %+v", c)
	}
}

// Apply refuses an op that changes nothing or names nothing, reads a pair
// either way round, and narrows a rule only inside its window.
func TestApplyRefusesNoChange(t *testing.T) {
	d := edit(1, func(d *Document) { dev(d, "speaker").Isolated = true })
	for name, op := range map[string]Op{
		"cut no cloud":     {Kind: CutVendorCloud, Device: "speaker"},
		"isolate isolated": {Kind: IsolateDevice, Device: "speaker"},
		"remove no device": {Kind: RemoveDevice, Device: "nobody"},
		"remove no pair":   {Kind: RemovePair, Pair: Pair{A: "plug", B: "tv"}},
		"no such kind":     {Kind: "widen", Device: "tv"},
		"narrow to empty":  {Kind: NarrowRule, Device: "lock", Rule: "plumber", FromMS: 1500, ToMS: 1500},
	} {
		if _, ok := Apply(d, op); ok {
			t.Errorf("%s applied", name)
		}
	}
	got, ok := Apply(d, Op{Kind: RemovePair, Pair: Pair{A: "speaker", B: "tv"}})
	if !ok || len(got.Pairs) != 1 {
		t.Errorf("a pair named the other way round: %v %v", ok, got.Pairs)
	}
	for _, w := range [][2]int64{{1000, 1999}, {1001, 2000}} {
		if _, ok := Apply(d, Op{Kind: NarrowRule, Device: "lock", Rule: "plumber", FromMS: w[0], ToMS: w[1]}); !ok {
			t.Errorf("narrowing to %v refused", w)
		}
	}
}

// Isolating an off-list device paired with a safety-list one needs the
// owner, whichever end of the pair it is.
func TestIsolatePairedNeedsOwner(t *testing.T) {
	for _, other := range []string{"cam", "zcam"} {
		o := edit(1, func(d *Document) {
			c := *dev(d, "cam")
			c.ID = "zcam"
			d.Devices = append(d.Devices, c)
			d.Pairs = append(d.Pairs, Pair{A: "tv", B: other})
		})
		n := o.normal()
		n.Device("tv").Isolated = true
		if c := Classify(o, n); !c.Tightening || !c.Owner {
			t.Errorf("isolating tv paired with %s: %+v", other, c)
		}
	}
}

// A hold on a device with no risk to name is not one the screen must name.
func TestRiskHoldsSkipsNoRisk(t *testing.T) {
	next := edit(1, func(d *Document) { d.Holds = append(d.Holds, Hold{Device: "plug", Kind: HoldFix}) })
	if h := RiskHolds(home(1), next); len(h) != 0 {
		t.Errorf("risk holds %v", h)
	}
}

// Serial, Root, Verify and Check refuse a document that fails check with
// check's own error, and Check refuses a key with anything beyond the
// owner's root or another assertion.
func TestVersionRefusals(t *testing.T) {
	a := newAuthenticator(t, rp)
	owner := a.Public()
	bad := Proposal{Doc: edit(1, func(d *Document) { d.Destinations = []string{"a b"} }), Diff: []byte("x")}
	if _, err := bad.Serial(); !errors.Is(err, ErrMalformed) {
		t.Errorf("Serial: %v", err)
	}
	if _, err := bad.Root(owner); !errors.Is(err, ErrMalformed) {
		t.Errorf("Root: %v", err)
	}
	if _, err := Verify(owner, 0, bad, []byte("sig")); !errors.Is(err, ErrMalformed) {
		t.Errorf("Verify: %v", err)
	}
	p := Proposal{Doc: home(1), Diff: []byte("one")}
	k, err := Verify(owner, 0, p, sign(t, a, owner, p))
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(owner, k, bad); !errors.Is(err, ErrMalformed) {
		t.Errorf("Check of a bad document: %v", err)
	}
	linked := k
	linked.Links = append(linked.Links, key.Link{})
	if err := Check(owner, linked, p); !errors.Is(err, ErrNotOwner) {
		t.Errorf("a key with a link: %v", err)
	}
	p2 := Proposal{Doc: home(1), Diff: []byte("two")}
	k2, err := Verify(owner, 0, p2, sign(t, a, owner, p2))
	if err != nil {
		t.Fatal(err)
	}
	swapped := k
	swapped.Root.Sig = k2.Root.Sig
	if err := Check(owner, swapped, p); !errors.Is(err, ErrBadSig) {
		t.Errorf("a key with another proposal's assertion: %v", err)
	}
}

type failStore struct{ err error }

func (f failStore) Load() ([]byte, error) { return nil, f.err }
func (f failStore) Save([]byte) error     { return f.err }

// Open refuses a store it cannot read and a state with a field it does not
// know.
func TestOpenRefusesUnreadable(t *testing.T) {
	a := newAuthenticator(t, rp)
	boom := errors.New("disk gone")
	if _, err := Open(a.Public(), failStore{boom}); !errors.Is(err, boom) {
		t.Errorf("a store that fails: %v", err)
	}
	e, a, store := opened(t)
	_ = e
	extra := &memStore{b: append([]byte(`{"zz":1,`), store.b[1:]...)}
	if _, err := Open(a.Public(), extra); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a state with an unknown field: %v", err)
	}
}

// Rekey takes only an ES256 passkey, even on a factory engine, refuses a
// malformed document with check's error, and the new passkey signs from
// then on.
func TestRekeyOwnerAndDocument(t *testing.T) {
	a := newAuthenticator(t, rp)
	e, err := Open(a.Public(), &memStore{})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ed := key.Ed25519(pub)
	if err := e.Rekey(ed, Proposal{}, nil); !errors.Is(err, ErrNotOwner) {
		t.Errorf("a factory engine rekeyed to Ed25519: %v", err)
	}

	e, a, _ = opened(t)
	b := newAuthenticator(t, rp)
	bad := Proposal{Doc: edit(2, func(d *Document) { d.Destinations = []string{"a b"} }), Diff: []byte("x")}
	if err := e.Rekey(b.Public(), bad, []byte("sig")); !errors.Is(err, ErrMalformed) {
		t.Errorf("a malformed rekey: %v", err)
	}
	same := e.Current()
	same.Version = 2
	p := Proposal{Doc: same, Diff: []byte("new passkey")}
	if err := e.Rekey(b.Public(), p, sign(t, b, b.Public(), p)); err != nil {
		t.Fatal(err)
	}
	next := Proposal{Doc: edit(3, func(d *Document) { d.Destinations = append(d.Destinations, "x.example") }), Diff: []byte("v3")}
	if _, err := b.propose(t, e, next, 0); err != nil {
		t.Errorf("the new passkey's proposal: %v", err)
	}
	_ = a
}

// Removing a pair counts against both its devices' tightening limit.
func TestRemovePairCountsBothDevices(t *testing.T) {
	e, _, _ := openWith(t, edit(1, func(d *Document) {
		dev(d, "tv").Allow = []string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example"}
	}))
	for _, h := range []string{"a", "b", "c", "d", "e", "f"} {
		if err := e.Tighten(Op{Kind: RemoveDestination, Device: "tv", Host: h + ".example"}, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Tighten(Op{Kind: RemovePair, Pair: Pair{A: "speaker", B: "tv"}}, 0); !errors.Is(err, ErrRateLimited) {
		t.Errorf("a pair of a device past its limit: %v", err)
	}
}

// ReadExport refuses a base or a signed step that does not verify, with
// the reason it failed, and two steps out of order.
func TestReadExportRefusals(t *testing.T) {
	e, a, _ := opened(t)
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "tv", Host: "a.example"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := e.Tighten(Op{Kind: RemoveDestination, Device: "tv", Host: "b.example"}, 0); err != nil {
		t.Fatal(err)
	}
	next := e.Current()
	next.Version = 2
	next.Device("plug").Allow = []string{"b.example"}
	if _, err := a.propose(t, e, Proposal{Doc: next, Diff: []byte("v2")}, 0); err != nil {
		t.Fatal(err)
	}
	b, err := e.Export()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadExport(a.Public(), b); err != nil {
		t.Fatalf("the export itself: %v", err)
	}
	read := func(f func(x *Export)) error {
		var x Export
		if err := json.Unmarshal(b, &x); err != nil {
			t.Fatal(err)
		}
		f(&x)
		out, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ReadExport(a.Public(), out)
		return err
	}
	for name, c := range map[string]struct {
		f    func(x *Export)
		want error
	}{
		"base not canonical": {func(x *Export) { x.Base.Doc = append([]byte(" "), x.Base.Doc...) }, ErrMalformed},
		"base by another":    {func(x *Export) { x.Base.Key.Root.Sig = x.Steps[2].Signed.Key.Root.Sig }, ErrBadSig},
		"step's assertion":   {func(x *Export) { x.Steps[2].Signed.Key.Root.Sig = x.Base.Key.Root.Sig }, ErrBadSig},
		"step's prev":        {func(x *Export) { x.Steps[2].Prev = append([]byte(" "), x.Steps[2].Prev...) }, ErrMalformed},
		"steps out of order": {func(x *Export) { x.Steps[1].Seq = x.Steps[0].Seq }, ErrCorrupt},
	} {
		err := read(c.f)
		if err == nil || !strings.Contains(err.Error(), c.want.Error()) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}
