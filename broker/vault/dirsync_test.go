package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/ghbmrk/agentos/broker/durable"
)

// REQ: CRED-7, REC-4, OP-4

// VAULT-dirsync-published (#1472): a vault write whose directory sync
// fails has still put the new file in place. The vault treats it as
// published: memory keeps what the drive now holds, the old values are
// wiped, the owner is warned that a power cut could still lose the
// change, and no later save writes the old values back.

// dirSyncFails makes every write of path land and then report a failed
// directory sync, as durable.WriteFile does. It returns how many writes
// landed that way.
func dirSyncFails(t *testing.T, path string) *int {
	t.Helper()
	n := new(int)
	writeFile = func(p string, raw []byte, perm os.FileMode) error {
		if err := durable.WriteFile(p, raw, perm); err != nil || p != path {
			return err
		}
		*n++
		return fmt.Errorf("%w: %w", durable.ErrDirSync, errors.New("input/output error"))
	}
	t.Cleanup(func() { writeFile = durable.WriteFile })
	return n
}

// warnings collects what v tells the owner.
func warnings(v *Vault) *[]string {
	var got []string
	v.OnWarn(func(s string) { got = append(got, s) })
	return &got
}

func reopened(t *testing.T, path string, key []byte) *Vault {
	t.Helper()
	v, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

func TestPutManyDirSyncFailureIsPublished(t *testing.T) {
	v, path, key := putManyVault(t)
	old, _ := items(t, "card", "card-wifi")
	if err := v.PutMany(old); err != nil {
		t.Fatal(err)
	}
	warned := warnings(v)
	next, nextVals := items(t, "card", "card-wifi", "card-setup")
	landed := dirSyncFails(t, path)
	if err := v.PutMany(next); err != nil {
		t.Fatalf("PutMany after the file landed: %v", err)
	}
	writeFile = durable.WriteFile
	if *landed != 1 {
		t.Fatalf("%d writes, want 1", *landed)
	}
	if len(*warned) != 1 {
		t.Fatalf("warnings: %q, want one", *warned)
	}
	holds(t, v, nextVals)
	holds(t, reopened(t, path, key), nextVals)

	// An unrelated save writes what memory holds, which is the new card.
	mustPut(t, v, "openai", "sk-canary-unrelated-01")
	got := reopened(t, path, key)
	holds(t, got, nextVals)
	if len(got.List()) != 4 {
		t.Fatalf("on the drive after an unrelated save: %v", got.List())
	}
}

func TestPutDirSyncFailureIsPublished(t *testing.T) {
	v, path, key := putManyVault(t)
	mustPut(t, v, "openai", "sk-canary-old-value-01")
	warned := warnings(v)
	dirSyncFails(t, path)
	if err := v.Put("openai", KindAPIKey, []byte("sk-canary-new-value-02")); err != nil {
		t.Fatalf("Put after the file landed: %v", err)
	}
	writeFile = durable.WriteFile
	if len(*warned) != 1 {
		t.Fatalf("warnings: %q, want one", *warned)
	}
	want := map[string][]byte{"openai": []byte("sk-canary-new-value-02")}
	holds(t, v, want)
	r, _ := v.Redactor()
	if out := r.Redact([]byte("sk-canary-old-value-01")); bytes.Contains(out, []byte(Placeholder)) {
		t.Fatal("redactor still matches the replaced value")
	}
	mustPut(t, v, "anthropic", "sk-canary-unrelated-02")
	holds(t, reopened(t, path, key), want)
}

func TestDeleteDirSyncFailureIsPublished(t *testing.T) {
	v, path, key := putManyVault(t)
	mustPut(t, v, "openai", "sk-canary-revoked-0001")
	warned := warnings(v)
	dirSyncFails(t, path)
	if err := v.Delete("openai"); err != nil {
		t.Fatalf("Delete after the file landed: %v", err)
	}
	writeFile = durable.WriteFile
	if len(*warned) != 1 {
		t.Fatalf("warnings: %q, want one", *warned)
	}
	if _, ok := v.Secret("openai"); ok {
		t.Fatal("deleted entry still in memory")
	}
	if _, ok := reopened(t, path, key).Secret("openai"); ok {
		t.Fatal("deleted entry on the drive")
	}
	// The unrelated save must not bring the revoked value back.
	mustPut(t, v, "anthropic", "sk-canary-unrelated-03")
	if _, ok := reopened(t, path, key).Secret("openai"); ok {
		t.Fatal("an unrelated save wrote the deleted entry back")
	}
}

// A write that fails before the rename still changes nothing, in memory or
// on the drive.
func TestDeleteFailedSaveRestores(t *testing.T) {
	v, path, key := putManyVault(t)
	mustPut(t, v, "openai", "sk-canary-kept-value-1")
	writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	t.Cleanup(func() { writeFile = durable.WriteFile })
	if err := v.Delete("openai"); err == nil {
		t.Fatal("no failure")
	}
	writeFile = durable.WriteFile
	want := map[string][]byte{"openai": []byte("sk-canary-kept-value-1")}
	holds(t, v, want)
	holds(t, reopened(t, path, key), want)
}

// With a counter bound, the landed file carries the counter's next value
// and memory adopts it, but the counter is left: the file is one ahead,
// which the next write or bind finishes. Had the counter advanced, a power
// cut that undid the rename would leave the file before it, which would
// then read as an old copy and refuse to open.
func TestDirSyncFailureWithCounter(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	mustPut(t, v, "openai", "sk-canary-before-sync1")
	ref := hex.EncodeToString(v.id)
	before, count := d.copy(), pc.counters[ref]
	warned := warnings(v)
	dirSyncFails(t, d.path)
	if err := v.Put("openai", KindAPIKey, []byte("sk-canary-landed-syn2")); err != nil {
		t.Fatalf("Put after the file landed: %v", err)
	}
	writeFile = durable.WriteFile
	if len(*warned) != 1 {
		t.Fatalf("warnings: %q, want one", *warned)
	}
	if got := v.Anchors()[0].Count; got != count+1 {
		t.Fatalf("anchor in memory at %d, want %d", got, count+1)
	}
	if got := pc.counters[ref]; got != count {
		t.Fatalf("counter advanced to %d after an unsynced write", got)
	}
	landed := d.copy()

	// The power cut undid the rename: the file before still binds.
	d.putBack(before)
	w := d.open()
	if err := w.Bind(pc); err != nil {
		t.Fatalf("file before an unsynced write: %v", err)
	}
	w.Close()

	// It did not: the landed file binds, and the next write goes on from it.
	d.putBack(landed)
	mustPut(t, v, "anthropic", "sk-canary-after-sync03")
	v.Close()
	w = d.open()
	defer w.Close()
	if err := w.Bind(pc); err != nil {
		t.Fatalf("after the next write: %v", err)
	}
	if s, ok := w.Secret("openai"); !ok || s.Reveal() != "sk-canary-landed-syn2" {
		t.Fatal("the landed value was lost")
	}
	d.putBack(before)
	x := d.open()
	defer x.Close()
	if err := x.Bind(pc); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("file before two writes: %v, want ErrRolledBack", err)
	}
}

// Anchoring writes the vault file before the counter exists; a write that
// lands with a failed directory sync anchors all the same.
func TestAnchorDirSyncFailureIsPublished(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	dirSyncFails(t, d.path)
	if err := v.Anchor(pc); err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	writeFile = durable.WriteFile
	if a := v.Anchors(); len(a) != 1 || a[0].Pending {
		t.Fatalf("anchors in memory: %+v", a)
	}
	v.Close()
	w := d.open()
	defer w.Close()
	if err := w.Bind(pc); err != nil {
		t.Fatalf("Bind after an unsynced anchor: %v", err)
	}
}

// A rebase whose vault write lands with a failed directory sync keeps the
// new ID in memory, so a later save does not write the old one back.
func TestRebaseDirSyncFailureIsPublished(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	rec := recoveryish{bytes.Repeat([]byte{9}, KeySize)}
	if err := v.AddSlot(rec, func(s Slot) bool { return s.Kind == SlotRecovery }); err != nil {
		t.Fatal(err)
	}
	oldID := append([]byte(nil), v.id...)
	dirSyncFails(t, vp)
	if _, err := v.Rebase(rec); err != nil {
		t.Fatalf("Rebase: %v", err)
	}
	writeFile = durable.WriteFile
	if bytes.Equal(v.id, oldID) {
		t.Fatal("old ID kept in memory")
	}
	newID := append([]byte(nil), v.id...)
	mustPut(t, v, "anthropic", "sk-canary-after-rebase")
	v.Close()
	w, err := OpenSealed(vp, kp, rec)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if !bytes.Equal(w.id, newID) {
		t.Fatal("drive holds another ID than memory had")
	}
}
