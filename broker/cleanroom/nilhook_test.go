package cleanroom

// SR3-8-f3: the builder and intake syncs that pass a nil hook are observed
// by the recorder too. Each test checks, at the moment the real sync runs,
// that the rename, write or remove it makes durable has already happened,
// so dropping the call, or keeping only its hook, fails the test, and so
// does a sync of the same path made before the change it should follow.
//
// REQ: OSS-2 (SR3-8-f3a, SR3-8-f3b)

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// exists reports whether path exists.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// marks counts named events seen by the recorder's callbacks, which may run
// on the builder's goroutine.
type marks struct {
	mu sync.Mutex
	n  map[string]int
}

func (m *marks) hit(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.n == nil {
		m.n = map[string]int{}
	}
	m.n[name]++
}

func (m *marks) seen(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n[name] > 0
}

// SR3-8-f3a rebuild: a damaged artifact whose job is not queued gets a new
// repair entry at open. The entry is synced as a file, its repair-<job>
// directory after the entry's rename, and the queue directory after both
// exist.
func TestRebuildMakesRealSyncs(t *testing.T) {
	dir := t.TempDir()
	st, _, err := openStore(filepath.Join(dir, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.put(Manifest{ID: "a-x", Job: "x", Hint: json.RawMessage(skillHint(t)), Day: "2026-01-01"}, nestedFiles)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(a.dir, "files", "skill", "lib", "tz", "zones.py")); err != nil {
		t.Fatal(err)
	}
	repair := filepath.Join(dir, "queue", "repair-x")
	entry := filepath.Join(repair, "0000-x.json")
	rec := recordSyncs(t, dir)
	var m marks
	rec.at = func(d string) {
		switch {
		case d == repair && exists(entry):
			m.hit("repair dir")
		case d == filepath.Join(dir, "queue") && exists(entry):
			m.hit("queue")
		}
	}
	rec.atFile = func(p string) {
		if p == entry+".tmp" && !exists(entry) {
			m.hit("entry")
		}
	}
	if _, err := New(Config{Dir: dir, Machines: newFake(), Image: "cleanroom"}); err != nil {
		t.Fatal(err)
	}
	seen := strings.Join(rec.list(), "\n")
	for _, k := range []string{"entry", "repair dir", "queue"} {
		if !m.seen(k) {
			t.Errorf("%s not synced after the repair entry was written:\n%s", k, seen)
		}
	}
	jobs, _ := queuedOf(&Builder{cfg: Config{Dir: dir}})
	if len(jobs) != 1 || jobs[0].ID != "x" {
		t.Fatalf("queued %+v", jobs)
	}
}

// sendOne queues one batch and returns its job.
func sendOne(t *testing.T, r *rig) *job {
	t.Helper()
	if err := r.b.Send(nextDay(), [][]byte{skillHint(t)}); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.queued()
	if err != nil || len(jobs) != 1 {
		t.Fatalf("queued %+v %v", jobs, err)
	}
	return jobs[0]
}

// SR3-8-f3a send: Send syncs the queue directory after the batch's rename
// into it.
func TestSendMakesRealSyncs(t *testing.T) {
	r := newRig(t, nil)
	day := nextDay()
	rec := recordSyncs(t, r.cfg.Dir)
	var m marks
	rec.at = func(d string) {
		if d == r.b.queueDir() && exists(filepath.Join(d, day)) {
			m.hit("queue")
		}
	}
	if err := r.b.Send(day, [][]byte{skillHint(t)}); err != nil {
		t.Fatal(err)
	}
	if !m.seen("queue") {
		t.Errorf("queue not synced after the batch rename:\n%s", strings.Join(rec.list(), "\n"))
	}
}

// SR3-8-f3a outcome, finish: finishing a job syncs outcomes.jsonl after the
// line is written, then the job's queue directory after its entry is
// removed.
func TestFinishMakesRealSyncs(t *testing.T) {
	r := newRig(t, nil)
	j := sendOne(t, r)
	log := filepath.Join(r.cfg.Dir, "outcomes.jsonl")
	rec := recordSyncs(t, r.cfg.Dir)
	var m marks
	rec.atFile = func(p string) {
		if p != log {
			return
		}
		if data, _ := os.ReadFile(p); strings.Contains(string(data), `"job":"`+j.ID+`"`) {
			m.hit("outcome")
		}
	}
	rec.at = func(d string) {
		if d == filepath.Dir(j.path) && !exists(j.path) {
			m.hit("job dir")
		}
	}
	if err := r.b.finish(j, "skill_gap", Outcome{Result: "failed", Reason: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	seen := strings.Join(rec.list(), "\n")
	if !m.seen("outcome") {
		t.Errorf("outcomes.jsonl not synced after the line was written:\n%s", seen)
	}
	if !m.seen("job dir") {
		t.Errorf("job's queue directory not synced after its entry was removed:\n%s", seen)
	}
}

// SR3-8-f3a park: a job that needs public material is moved to parked/;
// the source queue directory and parked/ are each synced after the rename.
func TestParkMakesRealSyncs(t *testing.T) {
	r := newRig(t, nil)
	j := sendOne(t, r)
	moved := filepath.Join(r.cfg.Dir, "parked", filepath.Base(j.path))
	rec := recordSyncs(t, r.cfg.Dir)
	var m marks
	rec.at = func(d string) {
		if !exists(moved) || exists(j.path) {
			return
		}
		switch d {
		case filepath.Dir(j.path):
			m.hit("job dir")
		case r.b.parkDir():
			m.hit("parked")
		}
	}
	r.f.guest = func(id, dir string) {
		call(client(dir), "POST", "/cleanroom/unable", []byte(`{"reason":"needs_public_material"}`))
	}
	r.run()
	waitFor(t, "parked", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	if o := r.outcomes()[0]; o.Result != "parked" {
		t.Fatalf("outcome %+v", o)
	}
	seen := strings.Join(rec.list(), "\n")
	if !m.seen("job dir") {
		t.Errorf("job's queue directory not synced after the move to parked:\n%s", seen)
	}
	if !m.seen("parked") {
		t.Errorf("parked not synced after the move:\n%s", seen)
	}
}
