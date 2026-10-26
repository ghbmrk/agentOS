package pageca

import (
	"bytes"
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
