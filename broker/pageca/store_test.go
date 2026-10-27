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
	swapped, _ := json.Marshal(sealed{Cert: a.cert.Raw, Key: ok})
	reordered := []byte(`{"key":` + string(mustJSON(t, ok)) + `,"cert":` + string(mustJSON(t, a.cert.Raw)) + `}`)
	resigned := bytes.Clone(a.cert.Raw)
	resigned[len(resigned)-1] ^= 1
	unsigned, _ := json.Marshal(sealed{Cert: resigned, Key: get(x509.MarshalPKCS8PrivateKey(a.key))})
	for name, v := range map[string][]byte{
		"another key": swapped, "reordered": reordered, "padded": append(bytes.Clone(b), '\n'),
		"not self-signed": unsigned, "oversized": append(bytes.Clone(b), bytes.Repeat([]byte{' '}, MaxSealed)...),
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
