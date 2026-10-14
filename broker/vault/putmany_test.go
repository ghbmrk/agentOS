package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/durable"
)

// REQ: CRED-7

// ROTATE-card-atomic (#1440): values that cover one another in redaction
// are stored together. PutMany writes them in one save, so the vault, in
// memory and on the drive, holds every old value or every new one, never
// a mix.

func putManyVault(t *testing.T) (*Vault, string, []byte) {
	t.Helper()
	path, key := filepath.Join(t.TempDir(), "vault"), testKey(t)
	v, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v, path, key
}

func items(t *testing.T, names ...string) ([]Item, map[string][]byte) {
	t.Helper()
	var its []Item
	vals := map[string][]byte{}
	for _, n := range names {
		c := canary(t)
		its = append(its, Item{Name: n, Kind: "card_part", Value: c})
		vals[n] = c
	}
	return its, vals
}

// holds checks that v has exactly want's values under their names, and that
// its redactor covers each of them.
func holds(t *testing.T, v *Vault, want map[string][]byte) {
	t.Helper()
	r, err := v.Redactor()
	if err != nil {
		t.Fatal(err)
	}
	for n, val := range want {
		s, ok := v.Secret(n)
		if !ok || s.Reveal() != string(val) {
			t.Fatalf("%s: not the expected value", n)
		}
		if bytes.Contains(r.Redact(append([]byte("out "), val...)), val) {
			t.Fatalf("%s: value not redacted", n)
		}
	}
}

func TestPutManyWritesOnce(t *testing.T) {
	v, path, key := putManyVault(t)
	writes := 0
	writeFile = func(p string, raw []byte, perm os.FileMode) error {
		writes++
		return durable.WriteFile(p, raw, perm)
	}
	t.Cleanup(func() { writeFile = durable.WriteFile })
	its, vals := items(t, "card", "card-wifi", "card-setup")
	if err := v.PutMany(its); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("%d saves, want 1", writes)
	}
	holds(t, v, vals)
	v2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	holds(t, v2, vals)
}

// A failed save puts every entry back, replaced and new alike, and the
// drive keeps the file before.
func TestPutManyFailedSaveRestoresAll(t *testing.T) {
	v, path, key := putManyVault(t)
	old, oldVals := items(t, "card", "card-wifi")
	if err := v.PutMany(old); err != nil {
		t.Fatal(err)
	}
	next, _ := items(t, "card", "card-wifi", "card-setup")
	writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	t.Cleanup(func() { writeFile = durable.WriteFile })
	if err := v.PutMany(next); err == nil {
		t.Fatal("no failure")
	}
	writeFile = durable.WriteFile
	holds(t, v, oldVals)
	if _, ok := v.Secret("card-setup"); ok {
		t.Fatal("new entry kept after a failed save")
	}
	v2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	holds(t, v2, oldVals)
	if len(v2.List()) != 2 {
		t.Fatalf("on the drive: %v", v2.List())
	}
}

// A save that fails after the new file landed (a failed directory sync)
// leaves the drive with every new value: one file, one write.
func TestPutManySaveFailsAfterRenameIsWhole(t *testing.T) {
	v, path, key := putManyVault(t)
	old, _ := items(t, "card", "card-wifi")
	if err := v.PutMany(old); err != nil {
		t.Fatal(err)
	}
	next, nextVals := items(t, "card", "card-wifi")
	writeFile = func(p string, raw []byte, perm os.FileMode) error {
		if err := durable.WriteFile(p, raw, perm); err != nil {
			return err
		}
		return errors.New("dir sync failed")
	}
	t.Cleanup(func() { writeFile = durable.WriteFile })
	if err := v.PutMany(next); err == nil {
		t.Fatal("no failure")
	}
	writeFile = durable.WriteFile
	v2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	holds(t, v2, nextVals)
}

// One bad item stores nothing.
func TestPutManyRefusesBeforeWriting(t *testing.T) {
	v, _, _ := putManyVault(t)
	good, _ := items(t, "a", "b")
	for name, bad := range map[string]Item{
		"short":     {Name: "c", Kind: "k", Value: []byte("x")},
		"no name":   {Kind: "k", Value: canary(t)},
		"no kind":   {Name: "c", Value: canary(t)},
		"duplicate": {Name: "a", Kind: "k", Value: canary(t)},
	} {
		if err := v.PutMany(append(append([]Item(nil), good...), bad)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if len(v.List()) != 0 {
			t.Fatalf("%s: stored %v", name, v.List())
		}
	}
	v.Close()
	if err := v.PutMany(good); !errors.Is(err, ErrClosed) {
		t.Fatalf("after Close: %v", err)
	}
}
