package pageca

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"testing"
)

// REQ: CH-9

// MIG-4-recovery-f1: the sealed form round-trips into the same authority
// for the name its certificate admits, and is the only form that reads:
// another key, a certificate that is not self-signed, a padded or
// reordered form, or an oversized one is refused.
func TestSealedFormRoundTrips(t *testing.T) {
	a := newAuthority(t)
	b, err := Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(b)
	if err != nil || got.Name() != DefaultName || got.Fingerprint() != a.Fingerprint() || !got.key.Equal(a.key) {
		t.Fatalf("round trip: %v", err)
	}
	other := newAuthority(t)
	ok, _ := x509.MarshalPKCS8PrivateKey(other.key)
	swapped, _ := json.Marshal(sealed{Cert: a.cert.Raw, Key: new(&ok)})
	reordered := []byte(`{"key":` + string(mustJSON(t, ok)) + `,"cert":` + string(mustJSON(t, a.cert.Raw)) + `}`)
	resigned := bytes.Clone(a.cert.Raw)
	resigned[len(resigned)-1] ^= 1
	own := get(x509.MarshalPKCS8PrivateKey(a.key))
	unsigned, _ := json.Marshal(sealed{Cert: resigned, Key: new(&own)})
	keyless := []byte(`{"cert":` + string(mustJSON(t, a.cert.Raw)) + `,"key":null}`)
	for name, v := range map[string][]byte{
		"another key": swapped, "reordered": reordered, "padded": append(bytes.Clone(b), '\n'),
		"not self-signed": unsigned, "no key": keyless, "oversized": append(bytes.Clone(b), bytes.Repeat([]byte{' '}, MaxSealed)...),
		"extra field": []byte(`{"cert":null,"key":null,"x":1}`), "empty": nil,
	} {
		if _, err := Unmarshal(v); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func get[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// Unmarshal wipes the PKCS#8 key it decoded once the authority holds it
// (STO-2a-e): the bytes handed to the key parser read as zeros afterwards.
func TestUnmarshalWipesTheKey(t *testing.T) {
	b, err := Marshal(newAuthority(t))
	if err != nil {
		t.Fatal(err)
	}
	var seen []byte
	t.Cleanup(func() { parseKey = x509.ParsePKCS8PrivateKey })
	parseKey = func(k []byte) (any, error) {
		seen = k
		return x509.ParsePKCS8PrivateKey(k)
	}
	if _, err := Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 || !bytes.Equal(seen, make([]byte, len(seen))) {
		t.Fatalf("Unmarshal left the key's %d bytes unwiped", len(seen))
	}
}
