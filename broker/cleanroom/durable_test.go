package cleanroom

// SR3-8: clean-room output is durable before its job is recorded complete,
// and a reopened store repairs what is not.
//
// REQ: OSS-2
//
// These tests inject faults and record the order of file operations
// through the store's hook. They do not cut power: simulated faults do not
// substitute for a hardware power-cut qualification (ASSUMPTIONS C14).

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// opLog records the store's file operations and can fail them.
type opLog struct {
	mu     sync.Mutex
	ops    []string
	failAt int  // fail the op with this index (0-based); -1 never
	sticky bool // and every op after it, until cleared
	failed int
}

var stageName = regexp.MustCompile(`\.stage-[^/]+`)

func (l *opLog) hook(root string) func(op, path string) error {
	return func(op, path string) error {
		l.mu.Lock()
		defer l.mu.Unlock()
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		n := len(l.ops)
		l.ops = append(l.ops, op+" "+stageName.ReplaceAllString(filepath.ToSlash(rel), ".stage"))
		if l.failAt >= 0 && (n == l.failAt || (l.sticky && n > l.failAt)) {
			l.failed++
			l.ops[n] += " !" // failed
			return errors.New("injected fault")
		}
		return nil
	}
}

func (l *opLog) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failAt = -1
}

func (l *opLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ops...)
}

func (l *opLog) failures() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failed
}

var nestedFiles = map[string]string{
	"skill/SKILL.md":           "# ics timezones\n",
	"skill/lib/tz/zones.py":    "ZONES = {}\n",
	"skill/lib/tz/__init__.py": "\n",
	"skill/tests/test_tz.py":   "def test(): pass\n",
}

func nestedResult() []byte {
	b, _ := json.Marshal(Result{Files: nestedFiles, Fixtures: Fixtures{Passed: 1}})
	return b
}

func index(ops []string, op string) int {
	for i, o := range ops {
		if o == op {
			return i
		}
	}
	return -1
}

// Every output file is synced, and every directory the stage created is
// synced deepest first, before the manifest is written; the artifact is
// renamed into place only after the manifest is durable, and the store's
// directory is synced after the rename.
func TestOutputSyncedBottomUpBeforeManifest(t *testing.T) {
	r := newRig(t, nil)
	l := &opLog{failAt: -1}
	r.b.store.fault = l.hook(r.b.store.dir)
	if _, err := r.b.store.put(Manifest{ID: "a-n"}, nestedFiles); err != nil {
		t.Fatal(err)
	}
	ops := l.list()
	manifest := index(ops, "rename .stage/manifest.json")
	commit := index(ops, "rename a-n")
	stored := index(ops, "syncdir .")
	if manifest < 0 || commit < manifest || stored < commit {
		t.Fatalf("manifest %d, commit %d, store sync %d in %q", manifest, commit, stored, ops)
	}
	for p := range nestedFiles {
		w, s := index(ops, "write .stage/files/"+p), index(ops, "sync .stage/files/"+p)
		if w < 0 || s < w || s > manifest {
			t.Fatalf("%s: write %d, sync %d, manifest %d", p, w, s, manifest)
		}
	}
	// Each created directory synced after every file under it, and after
	// every directory under it.
	order := []string{".stage/files/skill/lib/tz", ".stage/files/skill/lib", ".stage/files/skill", ".stage/files", ".stage"}
	last := -1
	for _, d := range order {
		i := index(ops, "syncdir "+d)
		if i < 0 || i < last || i > manifest {
			t.Fatalf("directory %s synced at %d (previous %d, manifest %d): %q", d, i, last, manifest, ops)
		}
		for p := range nestedFiles {
			if f := ".stage/files/" + p; strings.HasPrefix(f, d+"/") && index(ops, "sync "+f) > i {
				t.Fatalf("%s synced before its file %s", d, f)
			}
		}
		last = i
	}
	for _, d := range order[:4] {
		if index(ops, "mkdir "+d) < 0 {
			t.Fatalf("%s not created through the store: %q", d, ops)
		}
	}
}

// A job is recorded complete only with durable, hash-valid output, or its
// queue entry stays for a retry that repairs it. Each store operation of a
// clean job is failed in turn, once and from then on (storage failing),
// and the builder is then restarted with storage working.
func TestFaultAtEachStoreOpKeepsRetryObligation(t *testing.T) {
	// The ops of one fault-free job.
	clean := newRig(t, nil)
	cl := &opLog{failAt: -1}
	clean.b.store.fault = cl.hook(clean.b.store.dir)
	clean.f.guest = func(id, dir string) { call(client(dir), "POST", "/cleanroom/result", nestedResult()) }
	if err := clean.b.Send(nextDay(), [][]byte{skillHint(t)}); err != nil {
		t.Fatal(err)
	}
	clean.run()
	waitFor(t, "clean outcome", func() bool { return len(clean.outcomes()) == 1 })
	n := len(cl.list())
	if n < 10 {
		t.Fatalf("only %d store ops: %q", n, cl.list())
	}
	for k := 0; k < n; k++ {
		for _, sticky := range []bool{false, true} {
			faultRun(t, k, sticky)
		}
	}
}

func faultRun(t *testing.T, k int, sticky bool) {
	t.Helper()
	r := newRig(t, func(c *Config) { c.Timeout = 300 * time.Millisecond; c.Attempts = 3 })
	l := &opLog{failAt: k, sticky: sticky}
	r.b.store.fault = l.hook(r.b.store.dir)
	// The guest resends a refused result, as it may until its time runs out.
	guest := func(id, dir string) {
		for i := 0; i < 3; i++ {
			if code, _ := call(client(dir), "POST", "/cleanroom/result", nestedResult()); code != 500 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	r.f.guest = guest
	if err := r.b.Send(nextDay(), [][]byte{skillHint(t)}); err != nil {
		t.Fatal(err)
	}
	ctx, stop := ctxRun(r)
	waitFor(t, "fault or outcome", func() bool {
		return len(r.outcomes()) > 0 || l.failures() >= 3 || (!sticky && l.failures() > 0)
	})
	if sticky {
		// Storage keeps failing: whatever happens, no job is recorded
		// built without durable output.
		time.Sleep(50 * time.Millisecond)
	} else {
		waitFor(t, "outcome after a transient fault", func() bool { return len(r.outcomes()) > 0 })
	}
	stop()
	<-ctx
	r.f.wg.Wait()
	checkBuiltValid(t, r, k, sticky)
	if built(r) && !syncedAfterCommit(l.list()) {
		t.Fatalf("op %d sticky %v: recorded built though the commit rename was never synced: %q", k, sticky, l.list())
	}
	jobs, _ := r.queued()
	if sticky && len(r.outcomes()) == 0 && len(jobs) != 1 {
		t.Fatalf("op %d sticky: no outcome and %d queued: the retry obligation was lost", k, len(jobs))
	}

	// Restart with storage working: the job finishes built, once.
	l.clear()
	b2, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.f.svc = b2.Services(nil)
	r.f.guest = guest
	r.b = b2
	r.run()
	waitFor(t, "queue drained", func() bool { j, _ := r.queued(); return len(j) == 0 })
	waitFor(t, "final outcome", func() bool {
		o := r.outcomes()
		return len(o) > 0 && o[len(o)-1].Result != ""
	})
	r.f.wg.Wait()
	checkBuiltValid(t, r, k, sticky)
	all, err := r.b.store.list(func(Manifest) bool { return true })
	if err != nil || len(all) > 1 {
		t.Fatalf("op %d sticky %v: %d artifacts, %v", k, sticky, len(all), err)
	}
	if o := r.outcomes(); o[len(o)-1].Result == "built" && len(all) != 1 {
		t.Fatalf("op %d sticky %v: built with no artifact", k, sticky)
	}
}

func built(r *rig) bool {
	for _, o := range r.outcomes() {
		if o.Result == "built" {
			return true
		}
	}
	return false
}

// syncedAfterCommit: the store directory was synced, successfully, after
// the rename that committed the artifact: a rename alone is not durable.
func syncedAfterCommit(ops []string) bool {
	renamed := false
	for _, o := range ops {
		switch {
		case strings.HasPrefix(o, "rename a-") && !strings.HasSuffix(o, " !"):
			renamed = true
		case renamed && o == "syncdir .":
			return true
		}
	}
	return false
}

// ctxRun runs the builder until stop is called; the channel closes when
// Run has returned.
func ctxRun(r *rig) (<-chan struct{}, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	b := r.b
	go func() { b.Run(ctx); close(done) }()
	return done, cancel
}

// checkBuiltValid: every job logged built has its artifact in the store,
// with every file present and matching its manifest hash.
func checkBuiltValid(t *testing.T, r *rig, k int, sticky bool) {
	t.Helper()
	for _, o := range r.outcomes() {
		if o.Result != "built" {
			continue
		}
		a, err := r.b.store.Get(o.Artifact)
		if err != nil {
			t.Fatalf("op %d sticky %v: built %s missing: %v", k, sticky, o.Artifact, err)
		}
		if err := a.verify(); err != nil {
			t.Fatalf("op %d sticky %v: built %s invalid: %v", k, sticky, o.Artifact, err)
		}
	}
}

// buildOne runs one job to completion and returns its artifact.
func buildOne(t *testing.T, r *rig, h []byte) Artifact {
	t.Helper()
	r.f.guest = func(id, dir string) { call(client(dir), "POST", "/cleanroom/result", nestedResult()) }
	if err := r.b.Send(nextDay(), [][]byte{h}); err != nil {
		t.Fatal(err)
	}
	ctx, stop := ctxRun(r)
	waitFor(t, "built", func() bool { return len(r.outcomes()) == 1 })
	stop()
	<-ctx
	r.f.wg.Wait()
	o := r.outcomes()[0]
	if o.Result != "built" {
		t.Fatalf("outcome %+v", o)
	}
	a, err := r.b.store.Get(o.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func reopen(t *testing.T, r *rig) {
	t.Helper()
	b2, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.f.svc = b2.Services(nil)
	r.b = b2
}

// A completed manifest whose output is missing or truncated is found on
// reopen: it is quarantined, its job requeued, matching hints coalesce into
// that job rather than the damaged artifact, and it is rebuilt once.
// Further reopens rebuild nothing and list it once.
func TestReopenRebuildsLostOutput(t *testing.T) {
	damage := map[string]func(path string) error{
		"gone":  os.Remove,
		"short": func(p string) error { return os.Truncate(p, 2) },
		"empty": func(p string) error { return os.WriteFile(p, nil, 0o600) },
	}
	for name, hurt := range damage {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			h := skillHint(t)
			a := buildOne(t, r, h)
			id := a.m.ID
			if err := hurt(filepath.Join(a.dir, "files", "skill", "lib", "tz", "zones.py")); err != nil {
				t.Fatal(err)
			}
			reopen(t, r)
			if _, err := r.b.store.Get(id); !errors.Is(err, ErrNoArtifact) {
				t.Fatalf("damaged artifact still served: %v", err)
			}
			if pub, _ := r.b.store.Publishable(); len(pub) != 0 {
				t.Fatal("damaged artifact publishable")
			}
			q, _ := filepath.Glob(filepath.Join(r.b.store.dir, ".quarantine", id+"-*"))
			if len(q) != 1 {
				t.Fatalf("quarantine %v", q)
			}
			jobs, _ := r.queued()
			if len(jobs) != 1 || artifactID(jobs[0]) != id || jobs[0].Hint != string(h) || jobs[0].Attempts != 0 {
				t.Fatalf("requeued %+v", jobs)
			}
			// A matching hint coalesces into the requeued job, not the
			// damaged artifact.
			if err := r.b.Send(nextDay(), [][]byte{h}); err != nil {
				t.Fatal(err)
			}
			o := r.outcomes()
			if last := o[len(o)-1]; last.Result != "coalesced" || last.Artifact != "" || !strings.Contains(last.Reason, "job ") {
				t.Fatalf("coalesced into %+v", last)
			}
			r.f.guest = func(id, dir string) { call(client(dir), "POST", "/cleanroom/result", nestedResult()) }
			ctx, stop := ctxRun(r)
			waitFor(t, "rebuilt", func() bool { o := r.outcomes(); return o[len(o)-1].Result == "built" })
			stop()
			<-ctx
			r.f.wg.Wait()
			b, err := r.b.store.Get(id)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.verify(); err != nil {
				t.Fatal(err)
			}
			if data, err := b.ReadFile("skill/lib/tz/zones.py"); err != nil || string(data) != nestedFiles["skill/lib/tz/zones.py"] {
				t.Fatalf("rebuilt nested file %q %v", data, err)
			}
			machines := len(r.f.creates())
			for i := 0; i < 2; i++ {
				reopen(t, r)
				ctx, stop := ctxRun(r)
				time.Sleep(30 * time.Millisecond)
				stop()
				<-ctx
			}
			if len(r.f.creates()) != machines {
				t.Fatal("a valid artifact was rebuilt after reopen")
			}
			if jobs, _ := r.queued(); len(jobs) != 0 {
				t.Fatalf("queued after reopen: %+v", jobs)
			}
			if pub, _ := r.b.store.Publishable(); len(pub) != 1 {
				t.Fatalf("publishable %d after repeated reopen", len(pub))
			}
		})
	}
}

// A manifest that does not parse is quarantined on reopen rather than
// failing every listing (and so every intake).
func TestReopenQuarantinesUnreadableManifest(t *testing.T) {
	r := newRig(t, nil)
	a := buildOne(t, r, skillHint(t))
	if err := os.WriteFile(filepath.Join(a.dir, "manifest.json"), []byte(`{"id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	reopen(t, r)
	if _, err := r.b.store.list(func(Manifest) bool { return true }); err != nil {
		t.Fatalf("listing fails: %v", err)
	}
	if err := r.b.Send(nextDay(), [][]byte{skillHintN(t, 0)}); err != nil {
		t.Fatalf("intake blocked: %v", err)
	}
}

// A job still queued beside its artifact (a crash before completion was
// recorded) is completed only after its output is checked: damaged output
// is quarantined and rebuilt, even without a reopen.
func TestRestoredJobValidatesOutputBeforeCompleting(t *testing.T) {
	r := newRig(t, nil)
	h := skillHint(t)
	if err := r.b.Send(nextDay(), [][]byte{h}); err != nil {
		t.Fatal(err)
	}
	jobs, _ := r.queued()
	j := jobs[0]
	j.Attempts = r.cfg.Attempts // its one machine already spent
	if err := writeJSON(j.path, j); err != nil {
		t.Fatal(err)
	}
	a, err := r.b.store.put(Manifest{ID: artifactID(j), Job: j.ID, Hint: json.RawMessage(h), Day: j.Day}, nestedFiles)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(a.dir, "files", "skill", "SKILL.md"), 1); err != nil {
		t.Fatal(err)
	}
	r.f.guest = func(id, dir string) { call(client(dir), "POST", "/cleanroom/result", nestedResult()) }
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) > 0 })
	r.f.wg.Wait()
	o := r.outcomes()
	if len(o) != 1 || o[0].Result != "built" || len(r.f.creates()) != 1 {
		t.Fatalf("outcomes %+v, %d machines", o, len(r.f.creates()))
	}
	b, err := r.b.store.Get(artifactID(j))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.verify(); err != nil {
		t.Fatal(err)
	}
}

// Rebuilds after damage are bounded: past maxRepairs a job keeps its spent
// attempts, so storage that keeps losing output cannot run clean rooms
// without end.
func TestRepairsAreBounded(t *testing.T) {
	r := newRig(t, nil)
	if err := r.b.Send(nextDay(), [][]byte{skillHint(t)}); err != nil {
		t.Fatal(err)
	}
	jobs, _ := r.queued()
	j := jobs[0]
	for i := 0; i < maxRepairs+2; i++ {
		j.Attempts = 2
		if err := r.b.renew(j); err != nil {
			t.Fatal(err)
		}
		if want := i < maxRepairs; (j.Attempts == 0) != want {
			t.Fatalf("repair %d: attempts %d", i, j.Attempts)
		}
	}
	var got job
	if err := readJSON(j.path, &got); err != nil || got.Repairs != maxRepairs {
		t.Fatalf("stored %+v %v", got, err)
	}
}

// Reads stay hash-checked on nested paths after a rebuild.
func TestNestedReadStaysFailClosed(t *testing.T) {
	r := newRig(t, nil)
	a := buildOne(t, r, skillHint(t))
	p := filepath.Join(a.dir, "files", "skill", "lib", "tz", "zones.py")
	if err := os.WriteFile(p, []byte("ZONES = {1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadFile("skill/lib/tz/zones.py"); err == nil {
		t.Fatal("tampered nested file read")
	}
}
