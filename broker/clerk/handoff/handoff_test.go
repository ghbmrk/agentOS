package handoff

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/pageca"
)

// REQ: STO-2, CLK-1, KEY-4

func gen(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	p := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	return p.Public().(ed25519.PublicKey), p
}

// es256 is a hardware key's credential on rpID.
func es256(t *testing.T, rpID string) key.PublicKey {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := p.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := key.ES256(rpID, point)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

var (
	ownerPub, _ = gen(1)
	_, headPriv = gen(3)
	sparePub, _ = gen(4)
	anchors     = []key.PublicKey{key.Ed25519(ownerPub), key.Ed25519(sparePub)}
)

func testKeys() KernelKeys {
	return KernelKeys{Log: [32]byte{9}, Head: headPriv, Counter: testCounter(), Anchors: anchors, Slot: SlotTPM}
}

func testCounter() Counter {
	return Counter{SRK: bytes.Repeat([]byte{5}, 34), Handle: 0x01801234, Name: bytes.Repeat([]byte{6}, 34), Auth: []byte("0123456789abcdef0123456789abcdef")}
}

// pipeWith is a pipe's read end holding b, its writer closed.
func pipeWith(t *testing.T, b []byte) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return r
}

// STO-2a-e: the kernel gets its keys from the unlock step's pipe, whole.
// #3138: an ES256 hardware key crosses as itself, not misread as Ed25519.
func TestTheHandoffCarriesTheKernelsKeys(t *testing.T) {
	hw := es256(t, "box.example")
	keys := testKeys()
	keys.Anchors = []key.PublicKey{anchors[0], hw, anchors[1]}
	b, err := keys.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ReadKeys(pipeWith(t, b))
	if err != nil {
		t.Fatal(err)
	}
	want := testCounter()
	if k.Log != [32]byte{9} || !k.Head.Equal(headPriv) || len(k.Anchors) != 3 || k.Anchors[0] != anchors[0] || k.Anchors[1] != hw || k.Anchors[2] != anchors[1] ||
		!bytes.Equal(k.Counter.SRK, want.SRK) || k.Counter.Handle != want.Handle || !bytes.Equal(k.Counter.Name, want.Name) || !bytes.Equal(k.Counter.Auth, want.Auth) {
		t.Fatalf("keys did not survive the hand-off: %+v", k)
	}
	auth := k.Counter.Auth
	k.Wipe()
	if k.Head != nil || k.Log != ([32]byte{}) || k.Counter.Auth != nil || !bytes.Equal(auth, make([]byte, len(auth))) {
		t.Fatal("Wipe left keys")
	}
}

// A hand-off that is short, long, of another version, or not on a pipe is
// refused whole: no key of it is used.
func TestADamagedHandoffIsRefused(t *testing.T) {
	good, err := testKeys().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	extra := append(bytes.Clone(good), 0)
	retag := bytes.Clone(good)
	retag[len(handoffTag)-2] = '1' // a v1 hand-off, which carried no counter
	v2 := bytes.Clone(good)
	v2[len(handoffTag)-2] = '2' // a v2 hand-off, whose anchors were bare Ed25519 keys
	v3 := bytes.Clone(good)
	v3[len(handoffTag)-2] = '3' // a v3 hand-off, which carried no recipient
	v4 := bytes.Clone(good)
	v4[len(handoffTag)-2] = '4' // a v4 hand-off, which carried no page authority
	v5 := bytes.Clone(good)
	v5[len(handoffTag)-2] = '5'                          // a v5 hand-off, which carried no link key, first edge or slot
	count := len(good) - 2*(2+ed25519.PublicKeySize) - 1 // the anchors' count
	miscount := bytes.Clone(good)
	miscount[count] = 3
	zeroLen := bytes.Clone(good)
	zeroLen[count+1], zeroLen[count+2] = 0, 0
	pastEnd := bytes.Clone(good)
	binary.BigEndian.PutUint16(pastEnd[len(good)-2-ed25519.PublicKeySize:], ed25519.PublicKeySize+1)
	hw := es256(t, "box.example")
	dup := testKeys()
	dup.Anchors = []key.PublicKey{hw}
	dupB, err := dup.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	e := hw.Encode()
	dupB[len(dupB)-3-len(e)] = 2
	dupB = binary.BigEndian.AppendUint16(dupB, uint16(len(e)))
	dupB = append(dupB, e...)
	ragged := append(bytes.Clone(good[:len(good)-ed25519.PublicKeySize-2]), 0, 31)
	ragged = append(ragged, ownerPub[:31]...) // an entry that decodes to no key
	o := len(handoffTag) + 64                 // the SRK name's length
	srkLong := bytes.Clone(good)
	srkLong[o] = maxName + 1
	srkNone := bytes.Clone(good)
	srkNone[o] = 0
	authLen := o + 1 + 34 + 4 + 1 + 34 // the auth value's length
	authShort := bytes.Clone(good)
	authShort[authLen]--
	for name, b := range map[string][]byte{
		"empty": nil, "short": good[:len(good)-1], "trailing": extra, "tag": retag, "v2": v2, "v3": v3, "v4": v4, "v5": v5, "count": miscount,
		"zero-length entry": zeroLen, "past the end": pastEnd, "duplicate es256": dupB, "no key": ragged,
		"srk long": srkLong, "srk none": srkNone, "auth miscounted": authShort, "no counter": good[:o],
		"huge": bytes.Repeat([]byte{1}, maxHandoff+1),
	} {
		if _, err := ReadKeys(pipeWith(t, b)); !errors.Is(err, ErrHandoff) {
			t.Errorf("%s: got %v, want ErrHandoff", name, err)
		}
	}
	// A file on the drive never stands in for the unlock step.
	p := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(p, good, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeys(f); !errors.Is(err, ErrHandoff) {
		t.Fatalf("regular file: got %v, want ErrHandoff", err)
	}
}

// D-146: the owner's anchors are 1 to MaxAnchors distinct keys, and
// MaxAnchors ES256 keys on the longest RP ID fit the hand-off.
func TestAnchorsAreBounded(t *testing.T) {
	rp := strings.Repeat("a", 253)
	var hw []key.PublicKey
	for range MaxAnchors + 1 {
		hw = append(hw, es256(t, rp))
	}
	k := testKeys()
	k.Anchors = hw[:MaxAnchors]
	k.Recipient = testRecipient(t)
	b, err := k.Marshal()
	if err != nil || len(b) > maxHandoff {
		t.Fatalf("%d ES256 keys: %d bytes of %d, %v", MaxAnchors, len(b), maxHandoff, err)
	}
	if got, err := ReadKeys(pipeWith(t, b)); err != nil || len(got.Anchors) != MaxAnchors || got.Anchors[MaxAnchors-1] != hw[MaxAnchors-1] {
		t.Fatalf("%d ES256 keys: read %v", MaxAnchors, err)
	}
	k.Anchors = hw
	if _, err := k.Marshal(); !errors.Is(err, ErrHandoff) {
		t.Fatalf("%d keys: got %v, want ErrHandoff", MaxAnchors+1, err)
	}
	if _, err := EncodeAnchors(hw); !errors.Is(err, ErrHandoff) {
		t.Fatalf("%d keys encoded: got %v, want ErrHandoff", MaxAnchors+1, err)
	}
	// One more entry on the wire is refused by count, past maxHandoff too.
	over := testKeys()
	over.Anchors = hw[:1]
	ob, err := over.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	e := hw[0].Encode()
	ob[len(ob)-3-len(e)] = MaxAnchors + 1
	for _, a := range hw[1:] {
		ob = binary.BigEndian.AppendUint16(ob, uint16(len(a.Encode())))
		ob = append(ob, a.Encode()...)
	}
	if _, err := parseKeys(ob); !errors.Is(err, ErrHandoff) {
		t.Fatalf("%d keys on the wire: got %v, want ErrHandoff", MaxAnchors+1, err)
	}
	if _, err := parseAnchors(ob[len(ob)-(MaxAnchors+1)*(2+len(e)):], MaxAnchors+1); !errors.Is(err, ErrHandoff) {
		t.Fatalf("%d anchors: got %v, want ErrHandoff", MaxAnchors+1, err)
	}
}

// #3138: a box enrolled before ES256 anchors keeps them: an entry of bare
// 32-byte keys reads as Ed25519 keys. Damaged ones are refused.
func TestAnOldAnchorsEntryStillReads(t *testing.T) {
	one := []byte(ownerPub)
	if a, err := ParseAnchors(append(bytes.Clone(one), sparePub...)); err != nil || len(a) != 2 || a[0] != anchors[0] || a[1] != anchors[1] {
		t.Fatalf("two keys: %v %v", a, err)
	}
	many := bytes.Repeat(make([]byte, ed25519.PublicKeySize), MaxAnchors+1)
	for i := 0; i <= MaxAnchors; i++ {
		many[i*ed25519.PublicKeySize] = byte(i)
	}
	for name, b := range map[string][]byte{
		"none": nil, "ragged": one[:31], "dup": append(bytes.Clone(one), one...), "many": many,
	} {
		if _, err := ParseAnchors(b); !errors.Is(err, ErrHandoff) {
			t.Errorf("%s: got %v, want ErrHandoff", name, err)
		}
	}
}

// #3138: the tagged entry round-trips keys of both algorithms; a tag of
// another version, or a damaged entry, is refused.
func TestEncodeAnchorsRoundTrips(t *testing.T) {
	want := []key.PublicKey{anchors[0], es256(t, "box.example"), anchors[1]}
	b, err := EncodeAnchors(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAnchors(b)
	if err != nil || len(got) != len(want) {
		t.Fatalf("round trip: %v %v", got, err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("anchor %d: got %v, want %v", i, got[i], want[i])
		}
	}
	v2 := bytes.Clone(b)
	v2[len(anchorsTag)-2] = '2'
	zero := append([]byte(anchorsTag), 0)
	for name, bad := range map[string][]byte{
		"v2": v2, "tag only": []byte(anchorsTag), "count zero": zero, "short": b[:len(b)-1], "trailing": append(bytes.Clone(b), 0),
		"miscount": append(append([]byte(anchorsTag), 2), b[len(anchorsTag)+1:]...),
	} {
		if _, err := ParseAnchors(bad); !errors.Is(err, ErrHandoff) {
			t.Errorf("%s: got %v, want ErrHandoff", name, err)
		}
	}
	for name, a := range map[string][]key.PublicKey{
		"none": nil, "zero key": {{}}, "dup": {want[1], want[1]},
	} {
		if _, err := EncodeAnchors(a); !errors.Is(err, ErrHandoff) {
			t.Errorf("encode %s: got %v, want ErrHandoff", name, err)
		}
	}
}

// #2905 open point 2: a store with no anchors yet hands over none, and the
// kernel starts setup-only. A count of none with keys after it is refused.
func TestNoAnchorsStartsSetupOnly(t *testing.T) {
	b, err := (KernelKeys{Head: headPriv, Counter: testCounter(), Slot: SlotTPM}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k, err := parseKeys(b)
	if err != nil || len(k.Anchors) != 0 || !k.Head.Equal(headPriv) {
		t.Fatalf("no anchors: %v %v", k.Anchors, err)
	}
	if _, err := parseKeys(append(append(b, 0, 32), ownerPub...)); !errors.Is(err, ErrHandoff) {
		t.Fatalf("a key after a count of none: got %v, want ErrHandoff", err)
	}
}

// LOG-2, STO-1: a hand-off without the log anchor's whole counter is never
// written, so no kernel starts on an anchor it cannot advance.
func TestTheCounterIsWhole(t *testing.T) {
	for name, mut := range map[string]func(*Counter){
		"no srk": func(c *Counter) { c.SRK = nil }, "no handle": func(c *Counter) { c.Handle = 0 },
		"no name": func(c *Counter) { c.Name = nil }, "no auth": func(c *Counter) { c.Auth = nil },
		"long name": func(c *Counter) { c.Name = make([]byte, maxName+1) },
	} {
		k := testKeys()
		mut(&k.Counter)
		if _, err := k.Marshal(); !errors.Is(err, ErrHandoff) {
			t.Errorf("%s: got %v, want ErrHandoff", name, err)
		}
	}
}

// testRecipient is a recipient in its wire form: an X25519 public key and an
// ML-KEM-768 encapsulation key.
func testRecipient(t *testing.T) []byte {
	t.Helper()
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	return append(x.PublicKey().Bytes(), dk.EncapsulationKey().Bytes()...)
}

// REQ: BAK-1
// MIG-4-recovery-e1: the backup recipient crosses whole, and none crosses
// as none. A recipient of the wrong size, or whose ML-KEM key does not
// parse, is refused at both ends, so no read is sized by the wire.
func TestKernelKeysCarryTheRecipient(t *testing.T) {
	rcp := testRecipient(t)
	keys := testKeys()
	keys.Recipient = rcp
	b, err := keys.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ReadKeys(pipeWith(t, b))
	if err != nil || !bytes.Equal(k.Recipient, rcp) || len(k.Anchors) != len(anchors) || k.Counter.Handle != testCounter().Handle {
		t.Fatalf("recipient did not survive the hand-off: %x %v", k.Recipient, err)
	}
	none, err := testKeys().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if k, err := ReadKeys(pipeWith(t, none)); err != nil || k.Recipient != nil {
		t.Fatalf("no recipient: %x %v", k.Recipient, err)
	}

	// The recipient's length sits after the counter's auth value.
	o := len(handoffTag) + 64 + 1 + 34 + 4 + 1 + 34 + 1 + 32
	if binary.BigEndian.Uint16(b[o:]) != RecipientLen {
		t.Fatalf("recipient length not at %d", o)
	}
	badEK := bytes.Clone(rcp)
	for i := recipientXLen; i < recipientXLen+384; i++ {
		badEK[i] = 0xff // coefficients past the ML-KEM modulus
	}
	wire := func(n int, r []byte) []byte {
		w := bytes.Clone(b[:o])
		w = binary.BigEndian.AppendUint16(w, uint16(n))
		w = append(w, r...)
		return append(w, b[o+2+RecipientLen:]...)
	}
	for name, w := range map[string][]byte{
		"long":       wire(RecipientLen+1, append(bytes.Clone(rcp), 0)),
		"short":      wire(RecipientLen-1, rcp[:RecipientLen-1]),
		"huge":       wire(0xffff, rcp),
		"bad ek":     wire(RecipientLen, badEK),
		"truncated":  b[:o+2+100],
		"no length":  b[:o+1],
		"no anchors": b[:o+2+RecipientLen],
	} {
		if _, err := ReadKeys(pipeWith(t, w)); !errors.Is(err, ErrHandoff) {
			t.Errorf("wire %s: got %v, want ErrHandoff", name, err)
		}
	}
	for name, r := range map[string][]byte{"long": append(bytes.Clone(rcp), 0), "short": rcp[:RecipientLen-1], "bad ek": badEK} {
		k := testKeys()
		k.Recipient = r
		if _, err := k.Marshal(); !errors.Is(err, ErrHandoff) {
			t.Errorf("marshal %s: got %v, want ErrHandoff", name, err)
		}
	}

	// The store entry: tagged, and only a whole recipient reads.
	x, ek, err := SplitRecipient(rcp)
	if err != nil {
		t.Fatal(err)
	}
	v, err := EncodeRecipient(x, ek)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseRecipient(v); err != nil || !bytes.Equal(got, rcp) {
		t.Fatalf("entry round trip: %x %v", got, err)
	}
	if _, err := EncodeRecipient(x, badEK[recipientXLen:]); !errors.Is(err, ErrHandoff) {
		t.Fatalf("encode bad ek: got %v", err)
	}
	for name, e := range map[string][]byte{
		"untagged": rcp, "short": v[:len(v)-1], "long": append(bytes.Clone(v), 0),
		"v2": append([]byte("agentos-backup-recipient/v2\n"), rcp...),
	} {
		if _, err := ParseRecipient(e); !errors.Is(err, ErrHandoff) {
			t.Errorf("entry %s: got %v, want ErrHandoff", name, err)
		}
	}
}

// testPageCA is a page authority's sealed form.
func testPageCA(t *testing.T) []byte {
	t.Helper()
	a, err := pageca.New(pageca.DefaultName, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := pageca.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// REQ: CH-9, BAK-1
// MIG-4-recovery-f1: the page authority crosses whole beside the
// recipient, and none crosses as none. One that is oversized or does not
// open as an authority is refused at both ends and as a store entry.
func TestKernelKeysCarryThePageCA(t *testing.T) {
	ca := testPageCA(t)
	keys := testKeys()
	keys.Recipient, keys.PageCA = testRecipient(t), ca
	b, err := keys.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ReadKeys(pipeWith(t, b))
	if err != nil || !bytes.Equal(k.PageCA, ca) || !bytes.Equal(k.Recipient, keys.Recipient) || len(k.Anchors) != len(anchors) {
		t.Fatalf("the page authority did not survive the hand-off: %v", err)
	}
	if a, err := pageca.Unmarshal(k.PageCA); err != nil || a.Name() != pageca.DefaultName {
		t.Fatalf("the handed authority does not open: %v", err)
	}
	k.Wipe()
	if k.PageCA != nil {
		t.Fatal("Wipe left the page authority")
	}
	if k, err := ReadKeys(pipeWith(t, get(t, testKeys().Marshal))); err != nil || k.PageCA != nil {
		t.Fatalf("no authority: %x %v", k.PageCA, err)
	}

	// The authority's length sits after the recipient.
	o := len(handoffTag) + 64 + 1 + 34 + 4 + 1 + 34 + 1 + 32 + 2 + RecipientLen
	if int(binary.BigEndian.Uint16(b[o:])) != len(ca) {
		t.Fatalf("authority length not at %d", o)
	}
	wire := func(n int, r []byte) []byte {
		w := bytes.Clone(b[:o])
		w = binary.BigEndian.AppendUint16(w, uint16(n))
		w = append(w, r...)
		return append(w, b[o+2+len(ca):]...)
	}
	bad := bytes.Clone(ca)
	bad[len(bad)/2] ^= 1
	big := append(bytes.Clone(ca), bytes.Repeat([]byte{' '}, pageca.MaxSealed)...)
	for name, w := range map[string][]byte{
		"long":       wire(len(ca)+1, append(bytes.Clone(ca), ' ')),
		"short":      wire(len(ca)-1, ca[:len(ca)-1]),
		"huge":       wire(0xffff, ca),
		"garbage":    wire(len(ca), bad),
		"oversized":  wire(len(big), big),
		"truncated":  b[:o+2+100],
		"no length":  b[:o+1],
		"no anchors": b[:o+2+len(ca)],
	} {
		if _, err := ReadKeys(pipeWith(t, w)); !errors.Is(err, ErrHandoff) {
			t.Errorf("wire %s: got %v, want ErrHandoff", name, err)
		}
	}
	other, err := pageca.New("other.internal", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string][]byte{"garbage": bad, "oversized": big, "not json": []byte("cert"), "no key": []byte(`{"cert":null,"key":null}`)} {
		k := testKeys()
		k.PageCA = v
		if _, err := k.Marshal(); !errors.Is(err, ErrHandoff) {
			t.Errorf("marshal %s: got %v, want ErrHandoff", name, err)
		}
		if _, err := ParsePageCA(v); !errors.Is(err, ErrHandoff) {
			t.Errorf("entry %s: got %v, want ErrHandoff", name, err)
		}
	}
	// The entry is the authority's sealed form as is, for any page name it
	// admits; the kernel serves only the name its certificate names.
	if got, err := ParsePageCA(get(t, func() ([]byte, error) { return pageca.Marshal(other) })); err != nil || len(got) == 0 {
		t.Fatalf("another name's authority: %v", err)
	}
	if got, err := ParsePageCA(ca); err != nil || !bytes.Equal(got, ca) || &got[0] == &ca[0] {
		t.Fatalf("the entry does not read as a copy: %v", err)
	}
}

func get(t *testing.T, f func() ([]byte, error)) []byte {
	t.Helper()
	b, err := f()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// REQ: HW-15, REC-2, BAK-1
// EDGE-link-core-b: the link key, the first edge key and the slot cross
// whole, after the page authority, and a store with neither key hands
// none. Each is size-bounded: a wrong length, a field running past the end,
// or a slot that is empty, long or not printable is refused at both ends.
// Revert mutants: `optional` taking any length (the "edge 31" wire passes);
// `validSlot` dropped from Marshal (the empty-slot marshal passes).
func TestKernelKeysCarryTheLinkKeys(t *testing.T) {
	_, link := gen(7)
	edge, _ := gen(8)
	keys := testKeys()
	keys.PageCA, keys.LinkKey, keys.FirstEdge, keys.Slot = testPageCA(t), link, edge, SlotPassphrase
	b, err := keys.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ReadKeys(pipeWith(t, b))
	if err != nil || !k.LinkKey.Equal(link) || !k.FirstEdge.Equal(edge) || k.Slot != SlotPassphrase || !bytes.Equal(k.PageCA, keys.PageCA) || len(k.Anchors) != len(anchors) {
		t.Fatalf("the link keys did not survive the hand-off: %v", err)
	}
	k.Wipe()
	if k.LinkKey != nil {
		t.Fatal("Wipe left the link key")
	}
	if k, err := ReadKeys(pipeWith(t, get(t, testKeys().Marshal))); err != nil || k.LinkKey != nil || k.FirstEdge != nil || k.Slot != SlotTPM {
		t.Fatalf("no link keys: %v", err)
	}

	// The link key's length sits after the page authority.
	o := len(handoffTag) + 64 + 1 + 34 + 4 + 1 + 34 + 1 + 32 + 2 + 2 + len(keys.PageCA)
	if b[o] != ed25519.SeedSize || !bytes.Equal(b[o+1:o+33], link.Seed()) {
		t.Fatalf("link key not at %d", o)
	}
	e := o + 1 + 32
	s := e + 1 + 32
	splice := func(at, skip int, with ...byte) []byte {
		w := bytes.Clone(b[:at])
		w = append(w, with...)
		return append(w, b[at+skip:]...)
	}
	for name, w := range map[string][]byte{
		"link 31":     splice(o, 1+32, append([]byte{31}, link.Seed()[:31]...)...),
		"link 33":     splice(o, 1+32, append([]byte{33}, append(link.Seed(), 0)...)...),
		"edge 31":     splice(e, 1+32, append([]byte{31}, edge[:31]...)...),
		"edge 64":     splice(e, 1, 64),
		"slot empty":  splice(s, 1+len(SlotPassphrase), 0),
		"slot space":  splice(s, 1+len(SlotPassphrase), 3, 't', ' ', 'm'),
		"slot long":   splice(s, 1+len(SlotPassphrase), append([]byte{MaxSlot + 1}, bytes.Repeat([]byte{'a'}, MaxSlot+1)...)...),
		"slot past":   splice(s, 1, 0xff),
		"no slot":     b[:s],
		"no edge":     b[:e],
		"no link key": b[:o],
	} {
		if _, err := ReadKeys(pipeWith(t, w)); !errors.Is(err, ErrHandoff) {
			t.Errorf("wire %s: got %v, want ErrHandoff", name, err)
		}
	}
	for name, mod := range map[string]func(*KernelKeys){
		"short link key": func(k *KernelKeys) { k.LinkKey = link[:32] },
		"short edge":     func(k *KernelKeys) { k.FirstEdge = edge[:31] },
		"empty slot":     func(k *KernelKeys) { k.Slot = "" },
		"long slot":      func(k *KernelKeys) { k.Slot = strings.Repeat("a", MaxSlot+1) },
		"control slot":   func(k *KernelKeys) { k.Slot = "tpm\n" },
	} {
		k := testKeys()
		mod(&k)
		if _, err := k.Marshal(); !errors.Is(err, ErrHandoff) {
			t.Errorf("marshal %s: got %v, want ErrHandoff", name, err)
		}
	}
	for _, v := range [][]byte{nil, make([]byte, 31), make([]byte, 33), make([]byte, 64)} {
		if _, err := ParseLinkKey(v); !errors.Is(err, ErrHandoff) {
			t.Errorf("link key entry of %d bytes read", len(v))
		}
		if _, err := ParseFirstEdge(v); !errors.Is(err, ErrHandoff) && len(v) != 32 {
			t.Errorf("first edge entry of %d bytes read", len(v))
		}
	}
	if got, err := ParseLinkKey(link.Seed()); err != nil || !got.Equal(link) {
		t.Fatalf("link key entry: %v", err)
	}
	if got, err := ParseFirstEdge(edge); err != nil || !got.Equal(edge) || &got[0] == &edge[0] {
		t.Fatalf("first edge entry is not a copy: %v", err)
	}
}

// REQ: REC-4, BAK-1
// MIG-4-recovery-r1 (#3391): an approval round-trips under the head key
// and binds its route, old, next and expiry; one under another head key,
// edited in any byte, cut, padded, past its time or out of shape refuses.
func TestApprovalRoundTripAndBounds(t *testing.T) {
	pub, priv := gen(3)
	otherPub, otherPriv := gen(4)
	old, next := strings.Repeat("0a", 16), strings.Repeat("1b", 16)
	card := Approval{Route: RouteCard, Old: old, Next: next, Expires: 5000}
	for _, a := range []Approval{card, {Route: RouteCard, Next: next, Expires: 5000}, {Route: RouteLost, Old: old, Expires: 5000}, {Route: RouteLost, Expires: 1}} {
		b, err := SignApproval(priv, a)
		if err != nil {
			t.Fatalf("%+v: %v", a, err)
		}
		if len(b) > MaxApproval {
			t.Fatalf("%+v: %d bytes, over MaxApproval", a, len(b))
		}
		if got, err := VerifyApproval(pub, b, a.Expires-1); err != nil || got != a {
			t.Fatalf("%+v: verified %+v, %v", a, got, err)
		}
		if _, err := VerifyApproval(pub, b, a.Expires); !errors.Is(err, ErrApprovalExpired) {
			t.Fatalf("%+v at its expiry: %v", a, err)
		}
		if _, err := VerifyApproval(otherPub, b, 0); !errors.Is(err, ErrApproval) {
			t.Fatalf("%+v under another head key: %v", a, err)
		}
	}
	b, err := SignApproval(priv, card)
	if err != nil {
		t.Fatal(err)
	}
	for i := range b {
		e := bytes.Clone(b)
		e[i] ^= 1
		if got, err := VerifyApproval(pub, e, 0); err == nil {
			t.Fatalf("byte %d edited: verified %+v", i, got)
		}
	}
	for name, e := range map[string][]byte{
		"empty":   nil,
		"cut":     b[:len(b)-1],
		"no sig":  b[:len(b)-ed25519.SignatureSize],
		"padded":  append(bytes.Clone(b), 0),
		"long":    bytes.Repeat([]byte{'a'}, MaxApproval+1),
		"tagless": b[len(approvalTag):],
	} {
		if _, err := VerifyApproval(pub, e, 0); !errors.Is(err, ErrApproval) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A body re-signed by the right key but out of shape still refuses:
	// the parser, not only the signature, holds the form.
	resign := func(body []byte) []byte { return append(bytes.Clone(body), ed25519.Sign(priv, body)...) }
	body := card.body()
	for name, e := range map[string][]byte{
		"version 2":   append(append([]byte(approvalTag), 2), body[len(approvalTag)+1:]...),
		"route c":     append(append([]byte(approvalTag), approvalV, 'c'), body[len(approvalTag)+2:]...),
		"old overrun": append(append([]byte(approvalTag), approvalV, 'a', 200), body[len(approvalTag)+3:]...),
		"trailing":    append(bytes.Clone(body), 0),
	} {
		if _, err := VerifyApproval(pub, resign(e), 0); !errors.Is(err, ErrApproval) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, a := range map[string]Approval{
		"card, no next":    {Route: RouteCard, Old: old},
		"card, next = old": {Route: RouteCard, Old: old, Next: old},
		"lost, a next":     {Route: RouteLost, Old: old, Next: next},
		"no route":         {Old: old, Next: next},
		"upper hex":        {Route: RouteCard, Old: strings.ToUpper(old), Next: next},
		"short id":         {Route: RouteCard, Old: old[:30], Next: next},
	} {
		if _, err := SignApproval(priv, a); !errors.Is(err, ErrApproval) {
			t.Fatalf("%s signed: %v", name, err)
		}
		if _, err := VerifyApproval(pub, resign(a.bodyUnchecked()), 0); !errors.Is(err, ErrApproval) {
			t.Fatalf("%s verified: %v", name, err)
		}
	}
	if _, err := SignApproval(otherPriv[:10], card); !errors.Is(err, ErrApproval) {
		t.Fatalf("a short head key: %v", err)
	}
}

// bodyUnchecked is body for any route byte, "" written as a zero byte.
func (a Approval) bodyUnchecked() []byte {
	if a.Route == "" {
		a.Route = "\x00"
	}
	return a.body()
}
