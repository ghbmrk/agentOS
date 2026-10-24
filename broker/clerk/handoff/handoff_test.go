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
	return KernelKeys{Log: [32]byte{9}, Head: headPriv, Anchors: anchors}
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
	if k.Log != [32]byte{9} || !k.Head.Equal(headPriv) || len(k.Anchors) != 2 || !k.Anchors[0].Equal(ownerPub) || !k.Anchors[1].Equal(sparePub) {
		t.Fatalf("keys did not survive the hand-off: %+v", k)
	}
	k.Wipe()
	if k.Head != nil || k.Log != ([32]byte{}) {
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
	retag[len(handoffTag)-2] = '2'
	miscount := bytes.Clone(good)
	miscount[len(handoffTag)+64] = 3
	for name, b := range map[string][]byte{
		"empty": nil, "short": good[:len(good)-1], "long": extra, "tag": retag, "count": miscount,
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
	if _, err := (KernelKeys{Head: headPriv}).Marshal(); !errors.Is(err, ErrHandoff) {
		t.Fatalf("no anchors: got %v", err)
	}
}
