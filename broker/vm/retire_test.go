package vm

// REQ: LOG-4, CAP-3

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/durable"
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
		return fmt.Errorf("%w: synthetic", durable.ErrDirSync)
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
