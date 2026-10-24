package handoff

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// REQ: STO-2, CLK-1

func gen(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	p := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	return p.Public().(ed25519.PublicKey), p
}

var (
	ownerPub, _ = gen(1)
	_, headPriv = gen(3)
	sparePub, _ = gen(4)
	anchors     = []ed25519.PublicKey{ownerPub, sparePub}
)

func testKeys() KernelKeys {
	return KernelKeys{Log: [32]byte{9}, Head: headPriv, Counter: testCounter(), Anchors: anchors}
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
func TestTheHandoffCarriesTheKernelsKeys(t *testing.T) {
	b, err := testKeys().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ReadKeys(pipeWith(t, b))
	if err != nil {
		t.Fatal(err)
	}
	want := testCounter()
	if k.Log != [32]byte{9} || !k.Head.Equal(headPriv) || len(k.Anchors) != 2 || !k.Anchors[0].Equal(ownerPub) || !k.Anchors[1].Equal(sparePub) ||
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
	miscount := bytes.Clone(good)
	miscount[len(good)-2*ed25519.PublicKeySize-1] = 3
	o := len(handoffTag) + 64 // the SRK name's length
	srkLong := bytes.Clone(good)
	srkLong[o] = maxName + 1
	srkNone := bytes.Clone(good)
	srkNone[o] = 0
	authLen := o + 1 + 34 + 4 + 1 + 34 // the auth value's length
	authShort := bytes.Clone(good)
	authShort[authLen]--
	for name, b := range map[string][]byte{
		"empty": nil, "short": good[:len(good)-1], "long": extra, "tag": retag, "count": miscount,
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

// D-146: the owner's anchors are 1 to MaxAnchors distinct keys.
func TestAnchorsAreBounded(t *testing.T) {
	one := []byte(ownerPub)
	if a, err := ParseAnchors(one); err != nil || len(a) != 1 {
		t.Fatalf("one key: %v %v", a, err)
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

// #2905 open point 2: a store with no anchors yet hands over none, and the
// kernel starts setup-only. A count of none with keys after it is refused.
func TestNoAnchorsStartsSetupOnly(t *testing.T) {
	b, err := (KernelKeys{Head: headPriv, Counter: testCounter()}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k, err := parseKeys(b)
	if err != nil || len(k.Anchors) != 0 || !k.Head.Equal(headPriv) {
		t.Fatalf("no anchors: %v %v", k.Anchors, err)
	}
	if _, err := parseKeys(append(b, ownerPub...)); !errors.Is(err, ErrHandoff) {
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
