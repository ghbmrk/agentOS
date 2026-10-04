package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// REQ: CRED-1, ARC-1

// canary returns a synthetic API-key-shaped value that exists only for this
// test run. No real credential ever appears in this repository.
func canary(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return []byte("sk-canary-" + hex.EncodeToString(b))
}

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTripAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	key, val := testKey(t), canary(t)
	v, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put("openai", KindAPIKey, val); err != nil {
		t.Fatal(err)
	}
	v.Close()

	v2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	s, ok := v2.Secret("openai")
	if !ok || s.Reveal() != string(val) {
		t.Fatalf("secret not restored")
	}
	if got := v2.List(); len(got) != 1 || got[0] != (Entry{Name: "openai", Kind: KindAPIKey}) {
		t.Fatalf("List = %v", got)
	}
	if err := v2.Delete("openai"); err != nil {
		t.Fatal(err)
	}
	if _, ok := v2.Secret("openai"); ok {
		t.Fatal("deleted secret still present")
	}
}

// The vault file holds no value in any common encoding, and is owner-only.
func TestFileIsEncryptedAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	val := canary(t)
	v, err := Create(path, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put("openai", KindAPIKey, val); err != nil {
		t.Fatal(err)
	}
	v.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range [][]byte{
		val,
		[]byte(base64.StdEncoding.EncodeToString(val)),
		[]byte(hex.EncodeToString(val)),
		[]byte("openai"), // names are sealed too
	} {
		if bytes.Contains(raw, form) {
			t.Fatalf("vault file contains %q in clear", form)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("vault file mode %v, want 0600", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("stray files next to the vault: %v", entries)
	}
}

func TestWrongKeyAndTamperingAreRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	key := testKey(t)
	v, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put("openai", KindAPIKey, canary(t)); err != nil {
		t.Fatal(err)
	}
	v.Close()
	if _, err := Open(path, testKey(t)); err == nil {
		t.Fatal("opened with the wrong key")
	}
	raw, _ := os.ReadFile(path)
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, key); err == nil {
		t.Fatal("opened a tampered vault")
	}
	if _, err := Create(path, key); err == nil {
		t.Fatal("Create overwrote an existing vault")
	}
	if _, err := Create(filepath.Join(t.TempDir(), "v"), key[:16]); err == nil {
		t.Fatal("accepted a short key")
	}
}

// A Secret printed, logged, or serialized by mistake shows a placeholder.
func TestSecretNeverFormatsItsValue(t *testing.T) {
	v, err := Create(filepath.Join(t.TempDir(), "vault"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	val := canary(t)
	if err := v.Put("openai", KindAPIKey, val); err != nil {
		t.Fatal(err)
	}
	s, _ := v.Secret("openai")
	js, _ := json.Marshal(struct{ S Secret }{s})
	txt, _ := s.MarshalText()
	outs := []string{
		fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s %q %x %X", s, s, s, s, s, s, s),
		fmt.Sprintf("%v", []Secret{s}), fmt.Sprintf("%+v", struct{ S Secret }{s}),
		string(js), string(txt), s.String(), s.GoString(),
	}
	for _, o := range outs {
		if bytes.Contains([]byte(o), val) || bytes.Contains([]byte(o), []byte(hex.EncodeToString(val))) {
			t.Fatalf("formatted secret leaks value: %s", o)
		}
	}
}

func TestPutValidates(t *testing.T) {
	v, err := Create(filepath.Join(t.TempDir(), "vault"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Put("", KindAPIKey, canary(t)); err == nil {
		t.Error("accepted empty name")
	}
	if err := v.Put("x", KindAPIKey, []byte("short")); err == nil {
		t.Error("accepted a value too short to redact safely")
	}
	if err := v.Put("x", "", canary(t)); err == nil {
		t.Error("accepted empty kind")
	}
}
