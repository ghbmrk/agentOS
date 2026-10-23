package seal

// REQ: STO-2, A8

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

func rewrite(t *testing.T, path string, edit func(f *file)) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := parse(b)
	if err != nil {
		t.Fatal(err)
	}
	edit(f)
	if b, err = json.Marshal(f); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Someone with the drive but not the store key can write a well-formed slot
// for this store's ID that wraps a key of their own under a factor they
// know. The store then refuses to open, for them and for the owner, rather
// than open a store they chose; dropping a slot is refused the same way.
func TestSlotsChangedWithoutTheKeyAreRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store")
	mine, theirs := Recovery{Key: make([]byte, RecoveryLen)}, Recovery{Key: make([]byte, RecoveryLen)}
	mine.Key[0], theirs.Key[0] = 1, 2
	s, err := Create(path, mine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddSlot(Recovery{Key: make([]byte, RecoveryLen)}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	orig, _ := os.ReadFile(path)

	rewrite(t, path, func(f *file) {
		forged, err := makeSlot(f.ID, make([]byte, keyLen), theirs)
		if err != nil {
			t.Fatal(err)
		}
		f.Slots = append(f.Slots, forged)
	})
	for name, r := range map[string]Recovery{"theirs": theirs, "mine": mine} {
		if _, err := Unlock(path, r); !errors.Is(err, ErrTampered) {
			t.Errorf("a forged slot, unlocked with %s: got %v, want ErrTampered", name, err)
		}
	}

	os.WriteFile(path, orig, 0o600)
	rewrite(t, path, func(f *file) { f.Slots = slices.Delete(f.Slots, 1, 2) })
	if _, err := Unlock(path, mine); !errors.Is(err, ErrTampered) {
		t.Errorf("a dropped slot: got %v, want ErrTampered", err)
	}
}

// A wrap moved into another store does not open there: the store's ID is in
// every wrap's associated data.
func TestAWrapIsBoundToItsStore(t *testing.T) {
	dir := t.TempDir()
	r := Recovery{Key: make([]byte, RecoveryLen)}
	a, err := Create(filepath.Join(dir, "a"), r)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	b, err := Create(filepath.Join(dir, "b"), Recovery{Key: append([]byte{9}, make([]byte, RecoveryLen-1)...)})
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	ab, _ := os.ReadFile(filepath.Join(dir, "a"))
	fa, _ := parse(ab)
	rewrite(t, filepath.Join(dir, "b"), func(f *file) { f.Slots = append(f.Slots, fa.Slots[0]) })
	if _, err := Unlock(filepath.Join(dir, "b"), r); !errors.Is(err, ErrWrongFactor) {
		t.Fatalf("a wrap from another store: got %v, want ErrWrongFactor", err)
	}
}

// A tpm slot planted first in the file that unseals to a key of the wrong
// length (SealTo needs only the box's public policy key and the SRK's
// public area) makes Unlock return an error, not panic.
func TestAPlantedShortTPMKeyIsAnError(t *testing.T) {
	sw := swtpm.Start(t)
	sw.Reboot()
	sw.Measure(9, "initrd-A")
	key, err := tpmseal.NewPolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := tpmseal.SignCurrent(sw.TPM(), key, []uint{9})
	if err != nil {
		t.Fatal(err)
	}
	f := TPM{TPM: sw.TPM(), PolicyKey: &key.PublicKey, Policies: []tpmseal.Policy{p}}
	path := filepath.Join(t.TempDir(), "store")
	s, err := Create(path, f)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := s.Anchor()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	rewrite(t, path, func(fl *file) {
		planted := fl.Slots[0]
		planted.ID = "00000000000000ff"
		if planted.Sealed, err = tpmseal.SealTo(planted.Sealed.SRKPublic, []byte("short"), &key.PublicKey, ""); err != nil {
			t.Fatal(err)
		}
		fl.Slots = append([]slot{planted}, fl.Slots...)
	})
	_, err = Unlock(path, TPM{TPM: sw.TPM(), PolicyKey: &key.PublicKey, Anchor: anchor})
	if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrTampered) {
		t.Fatalf("a planted short tpm key: got %v, want the store refused", err)
	}
}
