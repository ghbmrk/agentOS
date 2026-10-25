package vm

// REQ: LOG-4

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
)

// failStartAfterSave makes id's next start fail after its meta.json is on
// disk, as a save whose directory sync fails does: the cleanup then has a
// loadable record to remove.
func failStartAfterSave(t *testing.T, e *env, id string) {
	t.Helper()
	real := writeFile
	path := filepath.Join(e.cfg.StateDir, "machines", id, "meta.json")
	writeFile = func(p string, b []byte, perm os.FileMode) error {
		if p != path {
			return real(p, b, perm)
		}
		writeFile = real
		if err := real(p, b, perm); err != nil {
			return err
		}
		return errors.New("synthetic: directory sync failed")
	}
	t.Cleanup(func() { writeFile = real })
}

// removePartway makes the next removal of a directory of id remove its
// layer and then fail, leaving its meta.json behind.
func removePartway(t *testing.T, id string) {
	t.Helper()
	real := removeAll
	removeAll = func(p string) error {
		b := filepath.Base(p)
		if b != id && !strings.HasPrefix(b, retiredPrefix+id+"-") {
			return real(p)
		}
		removeAll = real
		if err := real(filepath.Join(p, "disk")); err != nil {
			return err
		}
		return errors.New("synthetic: removal failed part-way")
	}
	t.Cleanup(func() { removeAll = real })
}

// erase takes away everything of a subject the machine plane holds: its
// machines destroyed, then every snapshot of its lineage, as #2823's
// erase does through Destroy and ForgetSince.
func erase(t *testing.T, e *env, lineage string, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := e.m.Destroy(bg, id); err != nil && !errors.Is(err, ErrUnknown) {
			t.Fatalf("erase: destroy %s: %v", id, err)
		}
	}
	must(t, e.m.ForgetSince(bg, lineage, time.Time{}))
}

// reopen is an upgrade: a new broker over the same state.
func (e *env) reopen() {
	e.t.Helper()
	e.rt = newFake()
	e.cfg.Runtime = e.rt
	e.open()
}

// onDisk lists what of lineage or ids is left in the state directory:
// any directory named for one of ids or retired, and any meta.json that
// names lineage.
func onDisk(t *testing.T, e *env, lineage string, ids ...string) []string {
	t.Helper()
	var left []string
	for _, sub := range []string{"machines", "snapshots"} {
		ents, err := os.ReadDir(filepath.Join(e.cfg.StateDir, sub))
		must(t, err)
		for _, d := range ents {
			name := d.Name()
			if strings.HasPrefix(name, retiredPrefix) {
				left = append(left, sub+"/"+name)
				continue
			}
			for _, id := range ids {
				if name == id {
					left = append(left, sub+"/"+name)
				}
			}
			var rec struct{ ID, Lineage string }
			if readJSON(filepath.Join(e.cfg.StateDir, sub, name, "meta.json"), &rec) == nil && rec.Lineage == lineage {
				left = append(left, sub+"/"+name+"/meta.json")
			}
		}
	}
	return left
}

// otherSubject is another subject's machine, with a snapshot, that every
// sequence below must leave alone.
func otherSubject(t *testing.T, e *env) Snapshot {
	t.Helper()
	e.create("other", admission.Accepted, 100)
	e.guestWrite("other", "notes", "keep")
	s, err := e.m.Step(bg, "other")
	must(t, err)
	return s
}

func checkOther(t *testing.T, e *env, s Snapshot) {
	t.Helper()
	if _, err := e.m.Get("other"); err != nil {
		t.Errorf("other subject's machine: %v", err)
	}
	if _, err := e.m.Snapshot(s.ID); err != nil {
		t.Errorf("other subject's snapshot %s: %v", s.ID, err)
	}
	if got := e.guestRead("other", "notes"); got != "keep" {
		t.Errorf("other subject's file: %q", got)
	}
}

// LOG-4 (#3125): a failed start or fork whose cleanup fails part-way
// leaves no directory nobody owns. After the subject is erased and the
// store reopened, none of its machines, snapshots or meta.json is loaded,
// listed or left on disk; another subject is untouched (test 3); and the
// same sequence with cleanup succeeding leaves nothing and needs no sweep
// (test 2).
func TestLOG4FailedStartCleanupThenEraseLeavesNothingAfterReopen(t *testing.T) {
	type start struct {
		name string
		// run makes the subject and fails a start of id, returning the
		// subject's lineage and machines.
		run func(t *testing.T, e *env, id string) (string, []string, error)
	}
	starts := []start{
		{"cold start", func(t *testing.T, e *env, id string) (string, []string, error) {
			_, err := e.m.Create(bg, id, Spec{Image: "base", Class: admission.Accepted, MemMB: 100})
			return "", []string{id}, err
		}},
		{"fork", func(t *testing.T, e *env, id string) (string, []string, error) {
			e.create("subj", admission.Accepted, 100)
			e.guestWrite("subj", "secret", "forget me")
			if _, err := e.m.Step(bg, "subj"); err != nil {
				t.Fatal(err)
			}
			src, err := e.m.Get("subj")
			must(t, err)
			_, err = e.m.Fork(bg, "subj", []string{id})
			return src.Lineage, []string{"subj", id}, err
		}},
	}
	for _, st := range starts {
		for _, partway := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/partway=%v", st.name, partway), func(t *testing.T) {
				e := newEnv(t, 8000)
				other := otherSubject(t, e)
				const id = "subj-f"
				failStartAfterSave(t, e, id)
				if partway {
					removePartway(t, id)
				}
				lineage, ids, err := st.run(t, e, id)
				if err == nil {
					t.Fatal("the start did not fail")
				}
				if _, gerr := e.m.Get(id); gerr == nil {
					// Kept: an erase finds and retires it.
					if lineage == "" {
						m, _ := e.m.Get(id)
						lineage = m.Lineage
					}
				}
				if !partway {
					// Test 2: nothing is left to sweep.
					if left := onDisk(t, e, "\x00", id); len(left) != 0 {
						t.Errorf("a clean failure left %v", left)
					}
				}
				if lineage != "" {
					erase(t, e, lineage, ids...)
				}
				e.reopen()
				for _, m := range e.m.Machines() {
					for _, sid := range ids {
						if m == sid {
							t.Errorf("machine %s loaded after the erase", m)
						}
					}
				}
				for _, sid := range ids {
					if s := e.m.Snapshots(sid); len(s) != 0 {
						t.Errorf("snapshots of %s listed after the erase: %v", sid, ids2(s))
					}
				}
				if left := onDisk(t, e, lineage, ids...); len(left) != 0 {
					t.Errorf("left on disk after the erase and reopen: %v", left)
				}
				checkOther(t, e, other)
			})
		}
	}
}

func ids2(s []Snapshot) []string {
	var out []string
	for _, x := range s {
		out = append(out, x.ID)
	}
	return out
}

// LOG-4: when even the retirement fails (the rename), the machine is not
// released: its record and admission stay, so an erase finds it, and the
// start's error says so.
func TestLOG4UnretiredFailedStartKeepsItsRecord(t *testing.T) {
	e := newEnv(t, 8000)
	const id = "subj"
	failStartAfterSave(t, e, id)
	real := renameDir
	renameDir = func(from, to string) error {
		if filepath.Base(from) == id {
			renameDir = real
			return errors.New("synthetic: rename refused")
		}
		return real(from, to)
	}
	t.Cleanup(func() { renameDir = real })
	_, err := e.m.Create(bg, id, Spec{Image: "base", Class: admission.Accepted, MemMB: 100})
	if err == nil || !strings.Contains(err.Error(), "rename refused") {
		t.Fatalf("create: %v", err)
	}
	mc, gerr := e.m.Get(id)
	if gerr != nil {
		t.Fatalf("the unretired machine was released: %v", gerr)
	}
	erase(t, e, mc.Lineage, id)
	e.reopen()
	if _, err := e.m.Get(id); err == nil {
		t.Error("erased machine loaded after reopen")
	}
	if left := onDisk(t, e, mc.Lineage, id); len(left) != 0 {
		t.Errorf("left on disk: %v", left)
	}
}

// LOG-4 / CAP-3: a prune whose meta.json removal fails keeps the
// snapshot's record, so it stays listed and an erase still finds it;
// it never drops the record and leaves a meta.json the next load
// republishes.
func TestLOG4PruneUnlinkFailureKeepsTheRecord(t *testing.T) {
	e := pruneEnv(t)
	e.create("m", admission.Accepted, 100)
	old, err := e.m.Step(bg, "m")
	must(t, err)
	for i := 0; i < 3; i++ {
		_, err := e.m.Step(bg, "m")
		must(t, err)
	}
	meta := filepath.Join(e.cfg.StateDir, "snapshots", old.ID, "meta.json")
	real := unlink
	unlink = func(p string) error {
		if p == meta {
			return errors.New("synthetic: unlink failed")
		}
		return real(p)
	}
	t.Cleanup(func() { unlink = real })
	if _, err := e.m.Prune(PrunePolicy{KeepFS: 1, KeepFull: 1}); err == nil {
		t.Fatal("prune hid the failed unlink")
	}
	if _, err := e.m.Snapshot(old.ID); err != nil {
		t.Fatalf("the snapshot's record went with its meta.json still there: %v", err)
	}
	unlink = real
	mc, err := e.m.Get("m")
	must(t, err)
	erase(t, e, mc.Lineage, "m")
	e.reopen()
	if _, err := e.m.Snapshot(old.ID); err == nil {
		t.Error("erased snapshot republished after reopen")
	}
	if left := onDisk(t, e, mc.Lineage, "m"); len(left) != 0 {
		t.Errorf("left on disk: %v", left)
	}
}

// CAP-3: a prune whose unlink is not made durable (the directory sync
// fails) keeps the record too, so a power cut cannot bring back a
// snapshot no record owns.
func TestCAP3PruneSyncFailureKeepsTheRecord(t *testing.T) {
	e := pruneEnv(t)
	e.create("m", admission.Accepted, 100)
	old, err := e.m.Step(bg, "m")
	must(t, err)
	for i := 0; i < 3; i++ {
		_, err := e.m.Step(bg, "m")
		must(t, err)
	}
	real := syncSnapDir
	syncSnapDir = func(d string) error {
		if filepath.Base(d) == old.ID {
			return errors.New("synthetic: sync failed")
		}
		return real(d)
	}
	t.Cleanup(func() { syncSnapDir = real })
	if _, err := e.m.Prune(PrunePolicy{KeepFS: 1, KeepFull: 1}); err == nil {
		t.Fatal("prune hid the failed sync")
	}
	if _, err := e.m.Snapshot(old.ID); err != nil {
		t.Fatalf("record dropped before the unlink was durable: %v", err)
	}
}

// LOG-4 (Security on #3135): an erase running while a prune's unpublish
// is undecided waits for it, so the prune can never put back a record the
// erase reported gone. Here the owner is destroyed, so no machine lock
// orders the two.
func TestLOG4PruneUndecidedUnpublishCannotOutliveAnErase(t *testing.T) {
	e := pruneEnv(t)
	e.create("m", admission.Accepted, 100)
	old, err := e.m.Step(bg, "m")
	must(t, err)
	for i := 0; i < 3; i++ {
		_, err := e.m.Step(bg, "m")
		must(t, err)
	}
	lineage := old.Lineage
	if lineage == "" {
		lineage = "m"
	}
	must(t, e.m.Destroy(bg, "m"))
	entered, release := make(chan struct{}), make(chan struct{})
	real := syncSnapDir
	var once sync.Once
	syncSnapDir = func(d string) error {
		failed := false
		if filepath.Base(d) == old.ID {
			// The prune's sync only; the erase's own goes through.
			once.Do(func() {
				close(entered)
				<-release
				failed = true
			})
		}
		if failed {
			return errors.New("synthetic: sync failed")
		}
		return real(d)
	}
	t.Cleanup(func() { syncSnapDir = real })
	done := make(chan error, 1)
	go func() {
		_, err := e.m.Prune(PrunePolicy{KeepFS: 1, KeepFull: 1})
		done <- err
	}()
	<-entered
	erased := make(chan error, 1)
	go func() { erased <- e.m.ForgetSince(bg, lineage, time.Time{}) }()
	select {
	case err := <-erased:
		t.Fatalf("erase finished while the unpublish was undecided: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-done; err == nil {
		t.Error("prune hid the failed sync")
	}
	if err := <-erased; err != nil {
		t.Fatalf("erase: %v", err)
	}
	if _, err := e.m.Snapshot(old.ID); err == nil {
		t.Fatalf("snapshot %s listed after the erase reported success", old.ID)
	}
	e.reopen()
	if _, err := e.m.Snapshot(old.ID); err == nil {
		t.Fatalf("snapshot %s loaded after the erase and reopen", old.ID)
	}
}

// refuseRename makes the next retirement of id's directory fail at its
// rename.
func refuseRename(t *testing.T, id string) {
	t.Helper()
	real := renameDir
	renameDir = func(from, to string) error {
		if filepath.Base(from) == id {
			renameDir = real
			return errors.New("synthetic: rename refused")
		}
		return real(from, to)
	}
	t.Cleanup(func() { renameDir = real })
}

// LOG-4 (L3 on #3135): Destroy releases a machine only once its directory
// is retired; a refused rename fails it with the record kept, and a retry
// finishes it.
func TestLOG4DestroyKeepsTheRecordUntilRetired(t *testing.T) {
	e := newEnv(t, 8000)
	e.create("m", admission.Accepted, 100)
	refuseRename(t, "m")
	if err := e.m.Destroy(bg, "m"); err == nil || !strings.Contains(err.Error(), "rename refused") {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := e.m.Get("m"); err != nil {
		t.Fatalf("record released before the directory was retired: %v", err)
	}
	must(t, e.m.Destroy(bg, "m"))
	if left := onDisk(t, e, "\x00", "m"); len(left) != 0 {
		t.Errorf("left on disk: %v", left)
	}
}

// LOG-4 (L3 on #3135): a failed fork whose directory cannot be retired
// keeps its record, so an erase finds it.
func TestLOG4UnretiredFailedForkKeepsItsRecord(t *testing.T) {
	e := newEnv(t, 8000)
	e.create("subj", admission.Accepted, 100)
	const id = "subj-f"
	failStartAfterSave(t, e, id)
	refuseRename(t, id)
	if _, err := e.m.Fork(bg, "subj", []string{id}); err == nil || !strings.Contains(err.Error(), "rename refused") {
		t.Fatalf("fork: %v", err)
	}
	if _, err := e.m.Get(id); err != nil {
		t.Fatalf("the unretired fork was released: %v", err)
	}
	must(t, e.m.Destroy(bg, id))
	e.reopen()
	if left := onDisk(t, e, "\x00", id); len(left) != 0 {
		t.Errorf("left on disk: %v", left)
	}
}

// CAP-3 (L3 on #3135): a rename whose sync failed is made durable before a
// retry reports the directory gone.
func TestCAP3RetireSyncsAnEarlierUnsyncedRename(t *testing.T) {
	e := newEnv(t, 8000)
	e.create("m", admission.Accepted, 100)
	realRename := renameDir
	renameDir = func(from, to string) error {
		renameDir = realRename
		if err := os.Rename(from, to); err != nil {
			return err
		}
		return errors.New("synthetic: directory sync failed")
	}
	t.Cleanup(func() { renameDir = realRename })
	if err := e.m.Destroy(bg, "m"); err == nil || !strings.Contains(err.Error(), "directory sync failed") {
		t.Fatalf("destroy: %v", err)
	}
	realSync := syncParent
	syncParent = func(string) error {
		syncParent = realSync
		return errors.New("synthetic: sync failed")
	}
	t.Cleanup(func() { syncParent = realSync })
	if err := e.m.Destroy(bg, "m"); err == nil {
		t.Fatal("retry reported the directory gone with its rename unsynced")
	}
	if _, err := e.m.Get("m"); err != nil {
		t.Fatalf("record released: %v", err)
	}
	must(t, e.m.Destroy(bg, "m"))
	e.reopen()
	if left := onDisk(t, e, "\x00", "m"); len(left) != 0 {
		t.Errorf("left on disk: %v", left)
	}
}

// refusedForkAfterCheckpoint makes a fork of id fail after its checkpoint
// is taken: the guest grows as it is paused and the disk fills.
func refusedForkAfterCheckpoint(t *testing.T, id string) *env {
	t.Helper()
	e := newEnv(t, 8000)
	var full atomic.Bool
	e.cfg.FreeBytes = func(string) (int64, error) {
		if full.Load() {
			return 0, nil
		}
		return 1 << 50, nil
	}
	e.open()
	e.create(id, admission.Accepted, 100)
	e.rt.onPause = func(string) { e.guestWrite(id, "grown", strings.Repeat("x", 1<<16)) }
	e.rt.onCkpt = func(string) { full.Store(true) }
	return e
}

// CAP-3 (L3 on #3135): a refused fork drops its checkpoint durably, and a
// drop that fails keeps the snapshot listed, the fork's error naming why.
func TestCAP3RefusedForkCheckpointDropIsDurable(t *testing.T) {
	e := refusedForkAfterCheckpoint(t, "m")
	if _, err := e.m.Fork(bg, "m", []string{"f"}); !errors.Is(err, ErrQuota) || !strings.Contains(err.Error(), "fork(1)") {
		t.Fatalf("fork, refused after its checkpoint: %v", err)
	}
	if s := e.m.Snapshots("m"); len(s) != 0 {
		t.Fatalf("refused fork left %v", ids2(s))
	}

	e = refusedForkAfterCheckpoint(t, "m")
	real := syncSnapDir
	syncSnapDir = func(string) error { return errors.New("synthetic: sync failed") }
	t.Cleanup(func() { syncSnapDir = real })
	_, err := e.m.Fork(bg, "m", []string{"f"})
	if !errors.Is(err, ErrQuota) || !strings.Contains(err.Error(), "fork(1)") || !strings.Contains(err.Error(), "synthetic: sync failed") {
		t.Fatalf("fork: %v", err)
	}
	s := e.m.Snapshots("m")
	if len(s) != 1 {
		t.Fatalf("an undurable drop unlisted the checkpoint: %v", ids2(s))
	}
	if mc, _ := e.m.Get("m"); mc.Last != s[0].ID {
		t.Errorf("Last %q, want the kept checkpoint %s", mc.Last, s[0].ID)
	}
}

// CAP-3: while a prune's unpublish is undecided, nothing looks the
// snapshot up (a Diff or Merge from another machine would read a layer
// the prune is about to delete); afterwards it is unknown.
func TestCAP3PruneUnpublishHidesTheSnapshotUntilDecided(t *testing.T) {
	e := pruneEnv(t)
	e.create("m", admission.Accepted, 100)
	old, err := e.m.Step(bg, "m")
	must(t, err)
	for i := 0; i < 3; i++ {
		_, err := e.m.Step(bg, "m")
		must(t, err)
	}
	real := syncSnapDir
	var once sync.Once
	looked := make(chan error, 1)
	syncSnapDir = func(d string) error {
		if filepath.Base(d) == old.ID {
			once.Do(func() {
				go func() {
					_, err := e.m.Snapshot(old.ID)
					looked <- err
				}()
				select {
				case err := <-looked:
					t.Errorf("snapshot looked up mid-unpublish: %v", err)
					looked <- err
				case <-time.After(50 * time.Millisecond):
				}
			})
		}
		return real(d)
	}
	t.Cleanup(func() { syncSnapDir = real })
	_, err = e.m.Prune(PrunePolicy{KeepFS: 1, KeepFull: 1})
	must(t, err)
	if err := <-looked; !errors.Is(err, ErrUnknown) {
		t.Errorf("after the unpublish: %v", err)
	}
}
