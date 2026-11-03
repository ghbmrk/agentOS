package secret_test

// REQ: CLK-1

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret"
	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
)

// A Secret prints no key in any verb or holder, a plain field holding the
// same bytes does (secrettest.NoKey checks that first), and DeepEqual still
// compares through it (DECOY-b-8, the #4719 rule).
func TestSecretPrintsNoKey(t *testing.T) {
	arr := [32]byte{}
	for i := range arr {
		arr[i] = byte(0xa1 + i)
	}
	sl := []byte("slice-secret-canary-0123456789")
	a, b := secret.Hide(arr), secret.Hide(bytes.Clone(sl))
	secrettest.NoKey(t, [][]byte{arr[:], sl}, append(secrettest.Holders(a), secrettest.Holders(b)...)...)
	if !reflect.DeepEqual(b, secret.Hide(bytes.Clone(sl))) || reflect.DeepEqual(b, secret.Hide([]byte("other"))) {
		t.Error("DeepEqual does not compare through a Secret")
	}
}

// A Secret reads back what it holds, a copy shares it, and Drop clears the
// bytes and empties every copy (STO-2a-e); the zero Secret holds none.
func TestSecretHoldsAndDrops(t *testing.T) {
	var empty secret.Secret[[]byte]
	if empty.Get() != nil || len(*empty.Ref()) != 0 {
		t.Fatal("the zero Secret holds something")
	}
	*empty.Ref() = []byte{1}
	if empty.Get() != nil {
		t.Fatal("the zero Secret's Ref is shared")
	}
	secret.Drop(empty)
	k := secret.Hide([]byte{1, 2, 3})
	cp := k
	b := k.Get()
	if !bytes.Equal(cp.Get(), []byte{1, 2, 3}) || &(*cp.Ref())[0] != &b[0] {
		t.Fatal("a copy reads another key")
	}
	secret.Drop(k)
	if cp.Get() != nil || !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Error("Drop left the key in a copy or its bytes")
	}
}
