package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
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
	replaced := [][]byte{v.entries["card"].Value, v.entries["card-wifi"].Value}
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
	for _, b := range replaced {
		if strings.Trim(string(b), "\x00") != "" {
			t.Fatal("a replaced value was not wiped")
		}
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
	warned := warnings(v)
	landed := dirSyncFails(t, d.path)
	if err := v.Anchor(pc); err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	writeFile = durable.WriteFile
	if len(*warned) != *landed || *landed != 2 {
		t.Fatalf("%d landed writes, warnings %q: want two of each", *landed, *warned)
	}
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
	warned := warnings(v)
	landed := dirSyncFails(t, vp)
	if _, err := v.Rebase(rec); err != nil {
		t.Fatalf("Rebase: %v", err)
	}
	writeFile = durable.WriteFile
	if *landed == 0 || len(*warned) != *landed {
		t.Fatalf("%d landed writes, warnings %q: want one each", *landed, *warned)
	}
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

// Trusting a PC again after its counter went rewrites the anchor as
// pending before making a new counter; that write landing with a failed
// directory sync re-anchors all the same.
func TestReanchorDirSyncFailureIsPublished(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	v.Close()
	pc.counters = map[string]uint64{} // NV_UndefineSpace
	v = d.open()
	defer v.Close()
	if err := v.Bind(pc); !errors.Is(err, ErrCounterMissing) {
		t.Fatalf("anchored PC without its counter: %v", err)
	}
	warned := warnings(v)
	landed := dirSyncFails(t, d.path)
	if err := v.Anchor(pc); err != nil {
		t.Fatalf("re-trust: %v", err)
	}
	writeFile = durable.WriteFile
	if len(*warned) != *landed || *landed != 2 {
		t.Fatalf("%d landed writes, warnings %q: want two of each", *landed, *warned)
	}
	if a := v.Anchors(); len(a) != 1 || a[0].Pending || len(pc.counters) != 1 {
		t.Fatalf("anchors in memory: %+v, counters %v", a, pc.counters)
	}
	w := d.open()
	defer w.Close()
	if err := w.Bind(pc); err != nil {
		t.Fatalf("Bind after an unsynced re-anchor: %v", err)
	}
}

// When no counter can be made, Anchor takes its pending anchor back out;
// that write landing with a failed directory sync takes it out of memory
// too, so no later save writes the pending anchor back.
func TestFailedAnchorDirSyncFailureIsPublished(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	defer v.Close()
	warned := warnings(v)
	landed := dirSyncFails(t, d.path)
	pc.broken = true
	if err := v.Anchor(pc); err == nil {
		t.Fatal("Anchor succeeded with a silent TPM")
	}
	pc.broken = false
	writeFile = durable.WriteFile
	if len(*warned) != *landed || *landed != 2 {
		t.Fatalf("%d landed writes, warnings %q: want two of each", *landed, *warned)
	}
	if a := v.Anchors(); len(a) != 0 {
		t.Fatalf("pending anchor kept in memory: %+v", a)
	}
	mustPut(t, v, "openai", "sk-canary-after-failed1")
	w := d.open()
	defer w.Close()
	if a := w.Anchors(); len(a) != 0 {
		t.Fatalf("a later save wrote the pending anchor back: %+v", a)
	}
}

// syncFails makes the catch-up's directory sync fail, as if the last
// write's name were still not durable.
func syncFails(t *testing.T) {
	t.Helper()
	syncDir = func(string) error { return fmt.Errorf("%w: %w", durable.ErrDirSync, errors.New("input/output error")) }
	t.Cleanup(func() { syncDir = durable.SyncDir })
}

// #1472 B1: after a write lands unsynced, the next write must not move the
// counter past the file before it until the landed file's name is durable.
// Before the fix, the next write's catch-up raised the counter (say 101 to
// 102) and then failed or was cut off; a power cut that undid the unsynced
// rename left the file at 101 behind a counter at 102: ErrRolledBack.
func TestCatchUpWaitsForTheLandedFile(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	defer v.Close()
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	mustPut(t, v, "openai", "sk-canary-before-sync1")
	ref := hex.EncodeToString(v.id)
	before, count := d.copy(), pc.counters[ref]
	dirSyncFails(t, d.path)
	if err := v.Put("openai", KindAPIKey, []byte("sk-canary-landed-syn2")); err != nil {
		t.Fatalf("Put after the file landed: %v", err)
	}
	writeFile = durable.WriteFile

	// The directory still has not synced: the next write refuses to
	// catch up, and nothing changes.
	syncFails(t)
	if err := v.Put("anthropic", KindAPIKey, []byte("sk-canary-next-write3")); err == nil {
		t.Fatal("next write caught up over an unsynced file")
	}
	if got := pc.counters[ref]; got != count {
		t.Fatalf("counter at %d after a refused catch-up, want %d", got, count)
	}
	if _, ok := v.Secret("anthropic"); ok {
		t.Fatal("refused write kept in memory")
	}
	landed := d.copy()

	// A bind of the landed file binds without catching up.
	w := d.open()
	if err := w.Bind(pc); err != nil {
		t.Fatalf("landed file with the sync still failing: %v", err)
	}
	w.Close()
	if got := pc.counters[ref]; got != count {
		t.Fatalf("bind caught up over an unsynced file: counter at %d", got)
	}

	// The power cut undid the rename: the file before still binds.
	d.putBack(before)
	w = d.open()
	if err := w.Bind(pc); err != nil {
		t.Fatalf("file before an unsynced write: %v", err)
	}
	w.Close()

	// Once the directory syncs, the catch-up goes ahead.
	syncDir = durable.SyncDir
	d.putBack(landed)
	w = d.open()
	defer w.Close()
	if err := w.Bind(pc); err != nil {
		t.Fatal(err)
	}
	if got := pc.counters[ref]; got != count+1 {
		t.Fatalf("counter at %d after a synced catch-up, want %d", got, count+1)
	}
	d.putBack(before)
	x := d.open()
	defer x.Close()
	if err := x.Bind(pc); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("file before a synced catch-up: %v, want ErrRolledBack", err)
	}
}

// REQ: HW-8
// Sync reports a failed directory sync of the vault file's name (#1558); a
// Sync that returned nil would let a caller change the TPM on a name a power
// cut could undo.
func TestSyncReportsAFailedDirectorySync(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	defer v.Close()
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	mustPut(t, v, "openai", "sk-canary-before-sync1")
	if err := v.Sync(); err != nil {
		t.Fatalf("Sync with a working directory sync: %v", err)
	}
	syncFails(t)
	if err := v.Sync(); !errors.Is(err, durable.ErrDirSync) {
		t.Fatalf("Sync with a failing directory sync: %v", err)
	}
}
