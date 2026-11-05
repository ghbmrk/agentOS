package handoff

// REQ: CLK-1

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret"
	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
)

// The hand-off prints no key: not the log key, the head key, the clerk
// root key, the counter's auth value, the page authority, the link key, a
// new recovery card or the checker's code seed, in sixteen verbs (%w and %p
// included), bare and in holders with unexported pointer, value and
// interface fields (CLK-1, DECOY-b-8, #4759). Each sits in a Secret, a
// pointer to a pointer that fmt prints as an address at any depth; a holder
// of the same key in a plain field shows it, so the check can see one.
// Catches a boot error or debug line in the unlock step or the kernel main
// that formats the hand-off and puts the keys in an unsealed log.
func TestKernelKeysPrintNoKey(t *testing.T) {
	var logKey, root, linkSeed [32]byte
	for i := range logKey {
		logKey[i], root[i], linkSeed[i] = byte(0x91+i), byte(0x51+i), byte(0x31+i)
	}
	link := ed25519.NewKeyFromSeed(linkSeed[:])
	auth := []byte("auth-value-canary-0123456789")
	card := bytes.Repeat([]byte{0x6b, 0x4c}, MadeCardLen/2)
	ca := testPageCA(t)
	seed := []byte("code-seed-canary-0123")
	c := testCounter()
	c.Auth = secret.Hide(bytes.Clone(auth))
	k := KernelKeys{
		Log: secret.Hide(logKey), Head: secret.Hide(headPriv), ClerkRoot: secret.Hide(root), Counter: c, Anchors: anchors,
		PageCA: secret.Hide(bytes.Clone(ca)), LinkKey: secret.Hide(link), Slot: SlotTPM, NewRecovery: secret.Hide(bytes.Clone(card)),
	}
	if _, err := k.Marshal(); err != nil {
		t.Fatal(err)
	}
	s := CodeSeed{Seed: secret.Hide(bytes.Clone(seed)), Step: 9}
	secrets := [][]byte{logKey[:], headPriv.Seed(), root[:], auth, ca[len(ca)-40:], link.Seed(), card, seed}
	secrettest.NoKey(t, secrets, append(append(secrettest.Holders(k), secrettest.Holders(c)...), secrettest.Holders(s)...)...)
}

// The hand-off and the code seed read back what they hold, a copy shares
// it, and Wipe empties every copy (STO-2a-e).
func TestHandoffWipesEveryCopy(t *testing.T) {
	var empty secret.Secret[[]byte]
	if empty.Get() != nil || len(*empty.Ref()) != 0 {
		t.Fatal("the zero Secret holds something")
	}
	k := testKeys()
	k.NewRecovery = secret.Hide(bytes.Repeat([]byte{7}, MadeCardLen))
	cp := k
	if cp.Log.Get() != k.Log.Get() || !bytes.Equal(cp.Head.Get(), headPriv) {
		t.Fatal("a copy reads other keys")
	}
	head := k.Head.Get()
	k.Wipe()
	if cp.Log.Get() != ([32]byte{}) || cp.Head.Get() != nil || cp.Counter.Auth.Get() != nil || cp.NewRecovery.Get() != nil {
		t.Error("a copy keeps a key after Wipe")
	}
	if !bytes.Equal(head, make([]byte, len(head))) {
		t.Error("Wipe left the head key's bytes")
	}
	s := CodeSeed{Seed: secret.Hide([]byte{1, 2, 3})}
	b := s.Seed.Get()
	s.Wipe()
	if s.Seed.Get() != nil || !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Error("CodeSeed.Wipe left the seed")
	}
}

// The least hand-off reads: no recipient, authority, link key, first edge
// key, card or anchors, and a 1-byte slot, so ten bytes follow the counter.
// One byte fewer, or a zero counter handle, is refused (STO-2a-e).
func TestTheLeastHandoffReads(t *testing.T) {
	b, err := KernelKeys{Head: secret.Hide(headPriv), Counter: testCounter(), Slot: "x"}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if k, err := parseKeys(b); err != nil || k.Slot != "x" || len(k.Anchors) != 0 {
		t.Fatalf("the least hand-off: %v", err)
	}
	if _, err := parseKeys(b[:len(b)-1]); !errors.Is(err, ErrHandoff) {
		t.Errorf("a byte short: %v", err)
	}
	h := len(handoffTag) + 32 + ed25519.SeedSize + 32 + 1 + len(testCounter().SRK)
	zero := bytes.Clone(b)
	clear(zero[h : h+4])
	if _, err := parseKeys(zero); !errors.Is(err, ErrHandoff) {
		t.Errorf("a zero handle: %v", err)
	}
}
