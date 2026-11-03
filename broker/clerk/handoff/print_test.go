package handoff

// REQ: CLK-1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
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
	c.Auth = Hide(bytes.Clone(auth))
	k := KernelKeys{
		Log: Hide(logKey), Head: Hide(headPriv), ClerkRoot: Hide(root), Counter: c, Anchors: anchors,
		PageCA: Hide(bytes.Clone(ca)), LinkKey: Hide(link), Slot: SlotTPM, NewRecovery: Hide(bytes.Clone(card)),
	}
	if _, err := k.Marshal(); err != nil {
		t.Fatal(err)
	}
	s := CodeSeed{Seed: Hide(bytes.Clone(seed)), Step: 9}
	secrets := [][]byte{logKey[:], headPriv.Seed(), root[:], auth, ca[len(ca)-40:], link.Seed(), card, seed}
	type holder struct {
		k  *KernelKeys
		kv KernelKeys
		c  Counter
		s  CodeSeed
		v  any
	}
	hd := holder{&k, k, c, s, k}
	if keyShown(secrets, k, &k, c, &c, s, &s, hd, &hd) {
		t.Error("the hand-off, its counter or the code seed prints a key")
	}
	type plain struct{ k []byte }
	for _, p := range secrets {
		if !keyShown([][]byte{p}, &holder{v: &plain{p}}) {
			t.Errorf("no print showed %x in a plain field: the check cannot see it", p[:4])
		}
	}
}

// A Secret reads back what it holds, a copy shares it, and Wipe empties
// every copy (STO-2a-e).
func TestSecretHoldsAndWipes(t *testing.T) {
	var empty Secret[[]byte]
	if empty.Get() != nil || len(*empty.Ref()) != 0 {
		t.Fatal("the zero Secret holds something")
	}
	k := testKeys()
	k.NewRecovery = Hide(bytes.Repeat([]byte{7}, MadeCardLen))
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
	s := CodeSeed{Seed: Hide([]byte{1, 2, 3})}
	b := s.Seed.Get()
	s.Wipe()
	if s.Seed.Get() != nil || !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Error("CodeSeed.Wipe left the seed")
	}
}

// keyShown formats each of vs in sixteen verbs and reports whether any
// output holds a secret: raw, as hex, as decimal bytes, JSON-escaped or in
// the verb's own form of the bytes.
func keyShown(secrets [][]byte, vs ...any) bool {
	shown := false
	for _, v := range vs {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%t", "%e", "%c", "%U", "%o", "%b", "%w", "%p"} {
			out := strings.ToLower(fmt.Sprintf(verb, v))
			for _, s := range secrets {
				j, _ := json.Marshal(string(s))
				for _, f := range []string{string(s), hex.EncodeToString(s), strings.Trim(fmt.Sprint(s), "[]"), strings.Trim(string(j), `"`), strings.Trim(fmt.Sprintf(verb, s), "[]")} {
					shown = shown || len(f) >= 10 && strings.Contains(out, strings.ToLower(f))
				}
			}
		}
	}
	return shown
}
