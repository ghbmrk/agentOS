package pageca

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
)

// REQ: CH-9, HW-1

func sealer(t *testing.T, b byte) Sealer {
	t.Helper()
	s, err := clerk.NewAESSealer(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStoreSealsAndReopensSameFingerprint(t *testing.T) {
	st := Store{Dir: t.TempDir(), Sealer: sealer(t, 1)}
	a, err := OpenOrCreate(st, DefaultName, built, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(st.Dir, File)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	// No plaintext key or certificate on disk.
	if bytes.Contains(raw, a.cert.Raw[:64]) || bytes.Contains(raw, a.key.D.Bytes()) {
		t.Error("the file holds the authority in the clear")
	}
	for _, claimed := range []bool{false, true} {
		b, err := OpenOrCreate(st, DefaultName, built, claimed, nil)
		if err != nil {
			t.Fatal(err)
		}
		if b.Fingerprint() != a.Fingerprint() {
			t.Error("reopened with a new fingerprint")
		}
		_, pub := p256(t)
		if _, err := b.Issue(pub, built, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Another sealer, or another page name, does not open it.
	if _, err := (Store{Dir: st.Dir, Sealer: sealer(t, 2)}).Open(DefaultName); err == nil {
		t.Error("another sealer opened it")
	}
	if _, err := st.Open("other.internal"); err == nil {
		t.Error("another name opened it")
	}
	if _, err := (Store{Dir: st.Dir}).Open(DefaultName); err == nil {
		t.Error("no sealer opened it")
	}
}

func TestStoreRefusesALinkedFile(t *testing.T) {
	dir := t.TempDir()
	st := Store{Dir: dir, Sealer: sealer(t, 1)}
	elsewhere := t.TempDir()
	a, err := OpenOrCreate(Store{Dir: elsewhere, Sealer: st.Sealer}, DefaultName, built, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(elsewhere, File), filepath.Join(dir, File)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Open(DefaultName); err == nil || errors.Is(err, ErrMissing) {
		t.Fatalf("a linked file: %v", err)
	}
	// A fresh box with a planted link makes no new authority over it.
	if _, err := OpenOrCreate(st, DefaultName, built, false, nil); err == nil {
		t.Fatal("made or opened an authority through a link")
	}
	if fi, err := os.Lstat(filepath.Join(dir, File)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the link was replaced")
	}
	// A file open to other uids is refused too.
	os.Remove(filepath.Join(dir, File))
	if err := st.Save(a); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(dir, File), 0o644)
	if _, err := st.Open(DefaultName); err == nil {
		t.Error("a file open to others opened")
	}
	// So is a directory others may write.
	os.Chmod(filepath.Join(dir, File), 0o600)
	if _, err := st.Open(DefaultName); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o777)
	defer os.Chmod(dir, 0o700)
	if _, err := st.Open(DefaultName); err == nil {
		t.Error("a directory others may write opened")
	}
}

func TestNeverRegeneratesOnAClaimedBox(t *testing.T) {
	st := Store{Dir: t.TempDir(), Sealer: sealer(t, 1)}
	if _, err := OpenOrCreate(st, DefaultName, built, true, nil); !errors.Is(err, ErrRestore) {
		t.Fatalf("claimed, no file: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(st.Dir, File)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a claimed box wrote an authority")
	}
	if _, err := OpenOrCreate(st, DefaultName, built, false, nil); err != nil {
		t.Fatal(err)
	}
	// Claimed, and the file no longer opens: never a new one.
	before, _ := os.ReadFile(filepath.Join(st.Dir, File))
	other := Store{Dir: st.Dir, Sealer: sealer(t, 9)}
	if _, err := OpenOrCreate(other, DefaultName, built, true, nil); !errors.Is(err, ErrRestore) {
		t.Fatalf("claimed, unopenable: %v", err)
	}
	// Fresh, and the file does not open: an error, not a new one.
	if _, err := OpenOrCreate(other, DefaultName, built, false, nil); err == nil {
		t.Fatal("a fresh box replaced an unopenable authority")
	}
	if after, _ := os.ReadFile(filepath.Join(st.Dir, File)); !bytes.Equal(before, after) {
		t.Error("the file changed")
	}
}

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
