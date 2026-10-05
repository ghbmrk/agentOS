package update

// REQ: CHG-3

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func keys(t *testing.T, n int) (Root, []ed25519.PrivateKey) {
	root := Root{Keys: map[string]ed25519.PublicKey{}, Threshold: 2}
	var priv []ed25519.PrivateKey
	for i := 0; i < n; i++ {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		root.Keys[string(rune('a'+i))] = pub
		priv = append(priv, pk)
	}
	return root, priv
}

var meta = []byte(`{"version":"1.2","security":true,"images":{"host-image/release":"` + Digest([]byte("img")) + `"}}`)

func TestThreshold(t *testing.T) {
	root, pk := keys(t, 3)
	one := []Signature{{"a", ed25519.Sign(pk[0], meta)}}
	if _, err := Verify(root, meta, one, 1); err == nil {
		t.Fatal("one signature of two")
	}
	dup := append(one, Signature{"a", ed25519.Sign(pk[0], meta)})
	if _, err := Verify(root, meta, dup, 1); err == nil {
		t.Fatal("the same key twice")
	}
	stranger := append(one, Signature{"z", ed25519.Sign(pk[1], meta)})
	if _, err := Verify(root, meta, stranger, 1); err == nil {
		t.Fatal("a key outside the root")
	}
	two := append(one, Signature{"b", ed25519.Sign(pk[1], meta)})
	v, err := Verify(root, meta, two, 1)
	if err != nil || !v.OK() || !v.Security() || v.Version() != "1.2" {
		t.Fatal(v, err)
	}
	if v, _ := Verify(root, meta, two, 0); v.Security() {
		t.Fatal("security without an attestation")
	}
	tampered := append([]byte(nil), meta...)
	tampered[13] = '3'
	if _, err := Verify(root, tampered, two, 1); err == nil {
		t.Fatal("tampered metadata")
	}
	if (Verified{}).OK() {
		t.Fatal("zero value")
	}
}

func TestOnlyImages(t *testing.T) {
	root, pk := keys(t, 2)
	for _, m := range []string{
		`{"version":"1","images":{"config/x":"` + Digest(nil) + `"}}`,
		`{"version":"1","images":{"host-image/../grants/x":"` + Digest(nil) + `"}}`,
		`{"version":"1","images":{"host-image/a":"zz"}}`,
		`{"version":"1","images":{"host-image/a":"` + Digest(nil) + `"},"grants":["x"]}`,
	} {
		b := []byte(m)
		sigs := []Signature{{"a", ed25519.Sign(pk[0], b)}, {"b", ed25519.Sign(pk[1], b)}}
		if _, err := Verify(root, b, sigs, 1); err == nil {
			t.Fatalf("accepted %s", m)
		}
	}
}
