package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/cgroup"
)

// REQ: REV-1, REV-4, ARC-4, RES-1, RES-2, RES-4, REV-5, LOOP-5

var bg = context.Background()

func TestREV1StepSnapshotsFilesAndCannotBeReachedByTheGuest(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m1", admission.Accepted, 1600)
	e.guestWrite("m1", "work/notes", "step one")
	s1, err := e.m.Step(bg, "m1")
	must(t, err)
	e.guestWrite("m1", "work/notes", "step two")
	s2, err := e.m.Step(bg, "m1")
	must(t, err)
	if s1.Tier != FS || s1.ID >= s2.ID {
		t.Fatalf("snapshots %+v %+v: want fs tier, ordered IDs", s1, s2)
	}
	if got := readSnap(t, e, s1.ID, "work/notes"); got != "step one" {
		t.Fatalf("step 1 snapshot holds %q", got)
	}
	// The snapshot was copied while the guest was paused, and it resumed.
	if e.rt.paused["m1"] {
		t.Fatal("guest left paused after a step")
	}

	// Broker-held: the snapshot store is 0700 and lies outside every path the
	// runtime is given for the guest, so the guest cannot reach it.
	store := filepath.Join(e.cfg.StateDir, "snapshots")
	for _, d := range []string{e.cfg.StateDir, store, filepath.Join(store, s1.ID)} {
		fi, err := os.Stat(d)
		must(t, err)
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %v, want 0700", d, fi.Mode().Perm())
		}
	}
	for _, l := range e.rt.launches {
		for _, p := range []string{l.Root, l.Upper, l.Lower} {
			if within(store, p) || within(p, store) {
				t.Errorf("guest path %s overlaps the snapshot store", p)
			}
		}
	}
	// A guest that empties its own file system leaves its snapshots intact.
	must(t, os.RemoveAll(filepath.Join(e.cfg.StateDir, "machines", "m1", "upper", "work")))
	if got := readSnap(t, e, s2.ID, "work/notes"); got != "step two" {
		t.Fatal("snapshot lost when the guest deleted its files")
	}
}

func within(parent, p string) bool {
	rel, err := filepath.Rel(parent, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func readSnap(t *testing.T, e *env, id, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.cfg.StateDir, "snapshots", id, "fs", rel))
	must(t, err)
	return string(b)
}

func TestREV1REV4RollbackFromBothTiers(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m1", admission.Accepted, 1600)
	e.rt.work("m1", 7)
	e.guestWrite("m1", "f", "good")
	full, err := e.m.Checkpoint(bg, "m1")
	must(t, err)
	e.rt.work("m1", 100)
	e.guestWrite("m1", "f", "broken")
	step, err := e.m.Step(bg, "m1")
	must(t, err)
	e.guestWrite("m1", "f", "worse")

	// File-system tier: files come back, the guest restarts cold.
	must(t, e.m.Rollback(bg, "m1", step.ID))
	if got := e.guestRead("m1", "f"); got != "broken" {
		t.Fatalf("after fs rollback f = %q", got)
	}
	if mem, ok := e.rt.memOf("m1"); !ok || mem != 0 {
		t.Fatalf("after fs rollback memory = %d running=%v, want a cold start", mem, ok)
	}
	// Full tier: files and memory come back.
	must(t, e.m.Rollback(bg, "m1", full.ID))
	if got := e.guestRead("m1", "f"); got != "good" {
		t.Fatalf("after full rollback f = %q", got)
	}
	if mem, _ := e.rt.memOf("m1"); mem != 7 {
		t.Fatalf("after full rollback memory = %d, want 7", mem)
	}
	// Rolling back neither consumes nor changes the snapshot.
	must(t, e.m.Rollback(bg, "m1", full.ID))
	if got := e.guestRead("m1", "f"); got != "good" {
		t.Fatal("second rollback differs")
	}
}

func TestREV4RollbackOnlyWithinLineage(t *testing.T) {
	e := newEnv(t, 8192)
	e.create("a", admission.Accepted, 100)
	e.create("b", admission.Accepted, 100)
	sa, err := e.m.Step(bg, "a")
	must(t, err)
	if err := e.m.Rollback(bg, "b", sa.ID); !errors.Is(err, ErrLineage) {
		t.Fatalf("b rolled back to a's snapshot: %v", err)
	}
	if err := e.m.Rollback(bg, "a", "s9999999999"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown snapshot: %v", err)
	}
}

func TestREV4ForkNInheritsMemoryFilesAndLabel(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("src", admission.Accepted, 1000)
	e.rt.work("src", 42)
	e.guestWrite("src", "plan", "v1")
	must(t, e.m.RaiseLabel("src", Private))

	base, err := e.m.Fork(bg, "src", []string{"f1", "f2"})
	must(t, err)
	if base.Tier != Full {
		t.Fatalf("fork base tier %v, want full", base.Tier)
	}
	for _, id := range []string{"f1", "f2"} {
		mc, err := e.m.Get(id)
		must(t, err)
		if mem, _ := e.rt.memOf(id); mem != 42 || e.guestRead(id, "plan") != "v1" {
			t.Errorf("%s: memory %d, plan %q; want the source's", id, mem, e.guestRead(id, "plan"))
		}
		if mc.Label != Private || mc.ForkBase != base.ID || mc.State != Running {
			t.Errorf("%s: %+v; want private, forked from %s, running", id, mc, base.ID)
		}
	}
	// Forks are independent of each other and of the source.
	e.guestWrite("f1", "plan", "f1 idea")
	e.rt.work("f1", 1)
	if e.guestRead("f2", "plan") != "v1" || e.guestRead("src", "plan") != "v1" {
		t.Fatal("a fork's write leaked into a sibling or the source")
	}
	// Each fork holds its own budget (S3: forks share no memory).
	if s := e.adm.Snapshot(); s.FreeMB != 4096-3*1000 {
		t.Fatalf("free after fork = %d", s.FreeMB)
	}
}

func TestREV4ForkIsAllOrNothingUnderAdmission(t *testing.T) {
	e := newEnv(t, 3000)
	e.create("src", admission.Accepted, 1000)
	if _, err := e.m.Fork(bg, "src", []string{"f1", "f2", "f3"}); !errors.Is(err, admission.ErrNoRoom) {
		t.Fatalf("fork past capacity: %v", err)
	}
	if ids := e.m.Machines(); len(ids) != 1 {
		t.Fatalf("machines after a refused fork: %v", ids)
	}
	if s := e.adm.Snapshot(); s.FreeMB != 2000 {
		t.Fatalf("admission leaked: free %d", s.FreeMB)
	}
	if len(e.rt.launches) != 1 {
		t.Fatal("a fork was started before admission said yes")
	}
	// A runtime failure on the second fork also leaves nothing behind.
	e2 := newEnv(t, 8000)
	e2.cfg.Runtime = &failSecond{fakeRuntime: e2.rt}
	e2.open()
	e2.create("src2", admission.Accepted, 1000)
	if _, err := e2.m.Fork(bg, "src2", []string{"g1", "g2"}); err == nil {
		t.Fatal("fork succeeded despite a failed restore")
	}
	for _, id := range []string{"g1", "g2"} {
		if _, err := e2.m.Get(id); err == nil {
			t.Errorf("%s left behind", id)
		}
		if _, ok := e2.rt.memOf(id); ok {
			t.Errorf("%s still running", id)
		}
	}
	if e2.adm.Snapshot().FreeMB != 7000 {
		t.Fatalf("failed fork leaked admission: free %d", e2.adm.Snapshot().FreeMB)
	}
}

// failSecond fails the second Restore.
type failSecond struct {
	*fakeRuntime
	n int
}

func (f *failSecond) Restore(ctx context.Context, l Launch, image string) error {
	f.n++
	if f.n == 2 {
		return errors.New("restore failed")
	}
	return f.fakeRuntime.Restore(ctx, l, image)
}

func TestREV4DiffAndMergeBackFromAFork(t *testing.T) {
	e := newEnv(t, 8192)
	e.create("dst", admission.Accepted, 500)
	e.guestWrite("dst", "src/a.go", "a0")
	e.guestWrite("dst", "src/b.go", "b0")
	_, err := e.m.Fork(bg, "dst", []string{"win"})
	must(t, err)
	e.guestWrite("win", "src/a.go", "a1")   // fork changes a
	e.guestWrite("win", "src/new.go", "n1") // and adds a file
	e.guestWrite("dst", "src/b.go", "b1")   // parent changes b meanwhile
	e.guestWrite("dst", "notes", "parent")  // and adds its own file

	m, err := e.m.Merge(bg, "dst", "win")
	must(t, err)
	for rel, want := range map[string]string{"src/a.go": "a1", "src/new.go": "n1", "src/b.go": "b1", "notes": "parent"} {
		if got := e.guestRead("dst", rel); got != want {
			t.Errorf("after merge %s = %q, want %q", rel, got, want)
		}
	}
	if mc, _ := e.m.Get("dst"); mc.Last != m.ID || mc.State != Running {
		t.Fatalf("dst after merge: %+v", mc)
	}

	// Diff names exactly the merged changes.
	before := e.m.Snapshots("dst")[1] // the step Merge took of dst
	ch, err := e.m.Diff("", before.ID, m.ID)
	must(t, err)
	var got []string
	for _, c := range ch {
		got = append(got, c.Op()+" "+c.Path)
	}
	if strings.Join(got, ", ") != "modified src/a.go, added src/new.go" {
		t.Fatalf("diff = %v", got)
	}
}

func TestREV4MergeRefusesConflicts(t *testing.T) {
	e := newEnv(t, 8192)
	e.create("dst", admission.Accepted, 500)
	e.guestWrite("dst", "f", "0")
	_, err := e.m.Fork(bg, "dst", []string{"k"})
	must(t, err)
	e.guestWrite("k", "f", "fork")
	e.guestWrite("k", "g", "fork only")
	e.guestWrite("dst", "f", "parent")
	if _, err := e.m.Merge(bg, "dst", "k"); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "f") {
		t.Fatalf("conflicting merge: %v", err)
	}
	if e.guestRead("dst", "f") != "parent" || e.guestRead("dst", "g") != "" {
		t.Fatal("a refused merge changed dst")
	}
	// Merging into a machine the fork did not come from is refused.
	e.create("other", admission.Accepted, 500)
	if _, err := e.m.Merge(bg, "other", "k"); !errors.Is(err, ErrLineage) {
		t.Fatalf("merge into a stranger: %v", err)
	}
}

func TestREV5LabelOnlyRisesThroughRollbackMergeAndDiff(t *testing.T) {
	e := newEnv(t, 8192)
	e.create("m", admission.Accepted, 500)
	warm, err := e.m.Checkpoint(bg, "m") // public warm template
	must(t, err)
	must(t, e.m.RaiseLabel("m", Private))
	if err := e.m.RaiseLabel("m", Public); err == nil {
		t.Fatal("label lowered")
	}
	must(t, e.m.Rollback(bg, "m", warm.ID))
	if mc, _ := e.m.Get("m"); mc.Label != Private {
		t.Fatal("rollback to a public snapshot made a private machine public")
	}

	// A public machine merging a private fork becomes private.
	e.create("p", admission.Accepted, 500)
	_, err = e.m.Fork(bg, "p", []string{"q"})
	must(t, err)
	must(t, e.m.RaiseLabel("q", Private))
	e.guestWrite("q", "x", "secret-derived")
	_, err = e.m.Merge(bg, "p", "q")
	must(t, err)
	if mc, _ := e.m.Get("p"); mc.Label != Private {
		t.Fatal("merging private work left the machine public")
	}

	// A public machine reading a diff of private snapshots becomes private.
	e.create("r", admission.Accepted, 500)
	priv, err := e.m.Step(bg, "m")
	must(t, err)
	if priv.Label != Private {
		t.Fatal("snapshot of a private machine not labeled private")
	}
	_, err = e.m.Diff("r", warm.ID, priv.ID)
	must(t, err)
	if mc, _ := e.m.Get("r"); mc.Label != Private {
		t.Fatal("diff of private snapshots left the reader public")
	}
}

func TestARC4RebuildFromImageKeepsDurableState(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	e.guestWrite("m", "etc/os-release", "tampered")
	e.guestWrite("m", "usr/bin/implant", "x")
	s, err := e.m.Step(bg, "m")
	must(t, err)
	must(t, e.m.Rebuild(bg, "m"))
	if e.guestRead("m", "etc/os-release") != "image v1" || e.guestRead("m", "usr/bin/implant") != "" {
		t.Fatal("rebuild kept the guest's changes")
	}
	if got := readSnap(t, e, s.ID, "usr/bin/implant"); got != "x" {
		t.Fatal("rebuild lost a broker-held snapshot")
	}

	// A broker restart keeps every machine record and snapshot; machines
	// come back stopped and can resume from their snapshots.
	e.guestWrite("m", "work", "after rebuild")
	last, err := e.m.Step(bg, "m")
	must(t, err)
	e.adm.Release("m") // the old process's admission state dies with it
	e.rt = newFake()
	e.cfg.Runtime = e.rt
	e.open()
	mc, err := e.m.Get("m")
	must(t, err)
	if mc.State != Stopped || mc.Last != last.ID {
		t.Fatalf("after restart: %+v", mc)
	}
	if got := e.m.Snapshots("m"); len(got) != 2 {
		t.Fatalf("snapshots after restart: %d", len(got))
	}
	must(t, e.m.Resume(bg, "m"))
	if e.guestRead("m", "work") != "after rebuild" {
		t.Fatal("resume after restart lost files")
	}
	next, err := e.m.Step(bg, "m")
	must(t, err)
	if next.ID <= last.ID {
		t.Fatalf("snapshot IDs reused after restart: %s after %s", next.ID, last.ID)
	}
}

func TestARC4DestroyReleasesEverythingButSnapshots(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	s, err := e.m.Step(bg, "m")
	must(t, err)
	must(t, e.m.Destroy(bg, "m"))
	if _, err := e.m.Get("m"); !errors.Is(err, ErrUnknown) {
		t.Fatal("destroyed machine still listed")
	}
	if _, ok := e.rt.memOf("m"); ok {
		t.Fatal("destroyed machine still running")
	}
	if _, err := os.Stat(filepath.Join(e.cfg.StateDir, "machines", "m")); !os.IsNotExist(err) {
		t.Fatal("machine layer left on disk")
	}
	if e.adm.Snapshot().FreeMB != 4096 {
		t.Fatal("admission not released")
	}
	if _, err := e.m.Snapshot(s.ID); err != nil {
		t.Fatal("destroy deleted a broker-held snapshot")
	}
	// The ID can be reused.
	e.create("m", admission.Accepted, 500)
}

func TestRES1ForegroundPreemptsExperimentWhichKeepsItsFiles(t *testing.T) {
	e := newEnv(t, 2000)
	e.create("exp", admission.Experiment, 1500)
	e.guestWrite("exp", "result", "partial")
	start := time.Now()
	e.create("call", admission.Foreground, 1000)
	took := time.Since(start)

	mc, err := e.m.Get("exp")
	must(t, err)
	if mc.State != Preempted {
		t.Fatalf("experiment state %s, want preempted", mc.State)
	}
	if _, ok := e.rt.memOf("exp"); ok {
		t.Fatal("preempted experiment still running")
	}
	if got := e.guestRead("exp", "result"); got != "partial" {
		t.Fatal("preemption lost the experiment's files")
	}
	if len(e.m.Snapshots("exp")) != 0 {
		t.Fatal("preemption copied the layer on the foreground path")
	}
	t.Logf("create with preemption took %v (fake runtime)", took)

	// Snapshots of a preempted machine are refused until it resumes, and it
	// resumes only when admission has room again.
	if _, err := e.m.Step(bg, "exp"); !errors.Is(err, ErrState) {
		t.Fatalf("step of a preempted machine: %v", err)
	}
	if err := e.m.Resume(bg, "exp"); !errors.Is(err, admission.ErrNoRoom) {
		t.Fatalf("resume without room: %v", err)
	}
	must(t, e.m.Destroy(bg, "call"))
	must(t, e.m.Resume(bg, "exp"))
	if e.guestRead("exp", "result") != "partial" {
		t.Fatal("resumed experiment lost its files")
	}
}

func TestRES1AcceptedWorkIsNeverPreempted(t *testing.T) {
	e := newEnv(t, 2000)
	e.create("work", admission.Accepted, 1500)
	if _, err := e.m.Create(bg, "call", Spec{Image: "base", Class: admission.Foreground, MemMB: 1000}); !errors.Is(err, admission.ErrNoRoom) {
		t.Fatalf("foreground over accepted work: %v", err)
	}
	if mc, _ := e.m.Get("work"); mc.State != Running {
		t.Fatal("accepted work was disturbed")
	}
	if _, err := e.m.Get("call"); err == nil {
		t.Fatal("refused machine left in the table")
	}
}

func TestRES2EveryMachineRunsInItsOwnBudgetedCgroup(t *testing.T) {
	parent := t.TempDir()
	write(t, parent, "cgroup.controllers", "memory pids")
	write(t, parent, "cgroup.subtree_control", "")
	g, err := cgroup.Open(parent)
	must(t, err)
	e := newEnv(t, 4096)
	e.cfg.Cgroups, e.cfg.NoCgroups = g, false
	e.open()
	e.create("m1", admission.Accepted, 1600)
	l := e.rt.launches[len(e.rt.launches)-1]
	if l.Cgroup != filepath.Join(parent, "m1") {
		t.Fatalf("machine started in %q", l.Cgroup)
	}
	b, err := os.ReadFile(filepath.Join(l.Cgroup, "memory.max"))
	must(t, err)
	if string(b) != "1677721600" {
		t.Fatalf("memory.max = %s, want the declared 1600 MB", b)
	}
	// Without cgroups, the manager refuses to start unless told it is a test.
	cfg := e.cfg
	cfg.Cgroups, cfg.NoCgroups = nil, false
	if _, err := Open(bg, cfg); err == nil {
		t.Fatal("manager opened with no way to enforce budgets")
	}
}

func TestRES2RefusedAdmissionStartsNothing(t *testing.T) {
	e := newEnv(t, 1000)
	if _, err := e.m.Create(bg, "big", Spec{Image: "base", Class: admission.Accepted, MemMB: 1001}); !errors.Is(err, admission.ErrNoRoom) {
		t.Fatalf("over-budget create: %v", err)
	}
	if len(e.rt.launches) != 0 {
		t.Fatal("runtime started a machine admission refused")
	}
	if _, err := os.Stat(filepath.Join(e.cfg.StateDir, "machines", "big")); !os.IsNotExist(err) {
		t.Fatal("refused machine left a directory")
	}
}

func TestCreateValidatesInput(t *testing.T) {
	e := newEnv(t, 1000)
	for _, id := range []string{"", "UP", "a/b", "../x", "a_b", strings.Repeat("a", 41)} {
		if _, err := e.m.Create(bg, id, Spec{Image: "base", MemMB: 1}); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
	if _, err := e.m.Create(bg, "x", Spec{Image: "nope", MemMB: 1}); !errors.Is(err, ErrUnknown) {
		t.Errorf("unknown image: %v", err)
	}
	e.create("dup", admission.Accepted, 1)
	if _, err := e.m.Create(bg, "dup", Spec{Image: "base", MemMB: 1}); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate: %v", err)
	}
	e.rt.failNext = errors.New("boom")
	if _, err := e.m.Create(bg, "fails", Spec{Image: "base", MemMB: 1}); err == nil {
		t.Fatal("runtime failure not reported")
	}
	if _, err := e.m.Get("fails"); err == nil || e.adm.Snapshot().FreeMB != 999 {
		t.Fatal("failed create left state behind")
	}
}

// preemptOnAdmit plays admission preempting a machine in the window between
// admitting it and its start.
type preemptOnAdmit struct {
	Admitter
	m      **Manager
	target string
}

func (p preemptOnAdmit) Admit(r admission.Request) (admission.Decision, error) {
	d, err := p.Admitter.Admit(r)
	if err == nil && r.ID == p.target {
		(*p.m).Preempt(r.ID)
		p.Admitter.Release(r.ID)
	}
	return d, err
}

func TestRES1PreemptionBeforeStartWinsTheRace(t *testing.T) {
	e := newEnv(t, 4000)
	e.cfg.Admit = preemptOnAdmit{Admitter: e.adm, m: &e.m, target: "x"}
	e.open()
	if _, err := e.m.Create(bg, "x", Spec{Image: "base", Class: admission.Experiment, MemMB: 100}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("create after preemption: %v", err)
	}
	if _, ok := e.rt.memOf("x"); ok {
		t.Fatal("a machine started on a withdrawn admission")
	}
	e.create("src", admission.Experiment, 100)
	e.m.cfg.Admit = preemptOnAdmit{Admitter: e.adm, m: &e.m, target: "f2"}
	if _, err := e.m.Fork(bg, "src", []string{"f1", "f2"}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("fork after preemption: %v", err)
	}
	for _, id := range []string{"f1", "f2"} {
		if _, ok := e.rt.memOf(id); ok {
			t.Errorf("%s running after a failed fork", id)
		}
	}
	if free := e.adm.Snapshot().FreeMB; free != 3900 {
		t.Fatalf("free = %d, want only src admitted", free)
	}
}

// A directory removed (or retyped) on one side while the other side wrote
// beneath it is a conflict in both directions, never a silent loss.
func TestREV4MergeConflictsUnderRemovedDirectories(t *testing.T) {
	// "proj" is not in the image, so deleting it from a layer needs no
	// whiteout (whiteouts need root; the kernel test covers them).
	cases := []struct {
		name      string
		fork, dst func(e *env)
	}{
		{"fork removes dir, parent writes in it",
			func(e *env) { must(t, os.RemoveAll(e.upper("k", "proj"))) },
			func(e *env) { e.guestWrite("dst", "proj/new", "parent work") }},
		{"parent removes dir, fork writes in it",
			func(e *env) { e.guestWrite("k", "proj/new", "fork work") },
			func(e *env) { must(t, os.RemoveAll(e.upper("dst", "proj"))) }},
		{"fork turns dir into a file, parent writes in it",
			func(e *env) { must(t, os.RemoveAll(e.upper("k", "proj"))); e.guestWrite("k", "proj", "file now") },
			func(e *env) { e.guestWrite("dst", "proj/new", "parent work") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, 8192)
			e.create("dst", admission.Accepted, 500)
			e.guestWrite("dst", "proj/main", "v0")
			_, err := e.m.Fork(bg, "dst", []string{"k"})
			must(t, err)
			tc.fork(e)
			tc.dst(e)
			before := e.guestRead("dst", "proj/new")
			if _, err := e.m.Merge(bg, "dst", "k"); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "proj") {
				t.Fatalf("merge: %v", err)
			}
			if e.guestRead("dst", "proj/new") != before {
				t.Fatal("a refused merge changed dst")
			}
		})
	}
	// Both sides removing the same directory is not a conflict.
	e := newEnv(t, 8192)
	e.create("dst", admission.Accepted, 500)
	e.guestWrite("dst", "proj/main", "v0")
	_, err := e.m.Fork(bg, "dst", []string{"k"})
	must(t, err)
	must(t, os.RemoveAll(e.upper("k", "proj")))
	must(t, os.RemoveAll(e.upper("dst", "proj")))
	if _, err := e.m.Merge(bg, "dst", "k"); err != nil {
		t.Fatalf("same removal on both sides: %v", err)
	}
}

func TestRES4SnapshotAdmittedOnlyAboveTheDiskReserve(t *testing.T) {
	free := int64(1 << 20)
	e := newEnv(t, 4096)
	e.cfg.DiskReserveBytes = 900 << 10 // 1 MiB free, 900 KiB reserved: ~124 KiB budget
	e.cfg.FreeBytes = func(string) (int64, error) { return free, nil }
	e.open()
	e.create("m", admission.Accepted, 100)
	e.guestWrite("m", "small", "ok")
	s1, err := e.m.Step(bg, "m")
	must(t, err)
	e.guestWrite("m", "big", strings.Repeat("x", 256<<10))
	_, err = e.m.Step(bg, "m")
	if !errors.Is(err, ErrQuota) || !strings.Contains(err.Error(), "disk budget") {
		t.Fatalf("over-budget step: %v", err)
	}
	// Refusal truncates nothing: the guest's file and old snapshots stay.
	if len(e.guestRead("m", "big")) != 256<<10 || len(e.m.Snapshots("m")) != 1 || e.m.Snapshots("m")[0].ID != s1.ID {
		t.Fatal("a refused snapshot changed state")
	}
	// The guest acts on the error (deletes the file) and the next step works.
	must(t, os.Remove(e.upper("m", "big")))
	if _, err := e.m.Step(bg, "m"); err != nil {
		t.Fatalf("step after pruning: %v", err)
	}
	// A sparse file costs only its data, so it passes.
	f, err := os.Create(e.upper("m", "sparse"))
	must(t, err)
	must(t, f.Truncate(1<<40))
	f.Close()
	if _, err := e.m.Step(bg, "m"); err != nil {
		t.Fatalf("sparse step: %v", err)
	}
	// More free space (measured, not fixed) admits the big layer.
	free = 1 << 30
	e.guestWrite("m", "big", strings.Repeat("x", 256<<10))
	if _, err := e.m.Step(bg, "m"); err != nil {
		t.Fatalf("step with room: %v", err)
	}
}

// RES-4: every copy is admitted against the disk, not only snapshots, and
// a fork that does not fit as a whole starts nothing and takes nothing.
func TestRES4ForkAdmittedOnTheDiskForEveryCopy(t *testing.T) {
	e := newEnv(t, 4096)
	const reserve = 1 << 20
	e.cfg.DiskReserveBytes = reserve
	// Room for the checkpoint (layer plus 1 MiB memory image) and two
	// copies of the layer, not five.
	free := int64(reserve + 1<<20 + 3*(160<<10))
	e.cfg.FreeBytes = func(string) (int64, error) { return free, nil }
	e.open()
	e.create("src", admission.Accepted, 1)
	e.guestWrite("src", "data", strings.Repeat("x", 128<<10))
	before := e.adm.Snapshot().FreeMB
	_, err := e.m.Fork(bg, "src", []string{"f1", "f2", "f3", "f4", "f5"})
	if !errors.Is(err, ErrQuota) {
		t.Fatalf("fork(5) over the disk budget: %v", err)
	}
	if got := e.m.Machines(); len(got) != 1 || len(e.m.Snapshots("src")) != 0 || e.adm.Snapshot().FreeMB != before {
		t.Fatalf("refused fork left state behind: machines %v, %d snapshots", got, len(e.m.Snapshots("src")))
	}
	if m, _ := e.m.Get("src"); m.State != Running {
		t.Fatalf("source is %s after a refused fork", m.State)
	}
	if _, err := e.m.Fork(bg, "src", []string{"f1", "f2"}); err != nil {
		t.Fatalf("fork(2) within the budget: %v", err)
	}
}

// RES-4: a rollback that the disk cannot hold is refused before the
// machine is stopped, so the machine keeps running as it was.
func TestRES4RollbackRefusedLeavesTheMachineRunning(t *testing.T) {
	e := newEnv(t, 4096)
	free := int64(1 << 40)
	e.cfg.DiskReserveBytes = 1 << 20
	e.cfg.FreeBytes = func(string) (int64, error) { return free, nil }
	e.open()
	e.create("m", admission.Accepted, 100)
	e.guestWrite("m", "data", strings.Repeat("x", 128<<10))
	s, err := e.m.Step(bg, "m")
	must(t, err)
	e.guestWrite("m", "after", "kept")
	free = 1<<20 + 64<<10
	if err := e.m.Rollback(bg, "m", s.ID); !errors.Is(err, ErrQuota) {
		t.Fatalf("rollback over the disk budget: %v", err)
	}
	if m, _ := e.m.Get("m"); m.State != Running || e.guestRead("m", "after") != "kept" {
		t.Fatalf("refused rollback changed the machine: %s", m.State)
	}
	free = 1 << 40
	must(t, e.m.Rollback(bg, "m", s.ID))
}

// RES-4: reservations held by copies in progress count against the budget,
// so two copies that each fit alone cannot together eat the reserve.
func TestRES4DiskReservationsAreSerialized(t *testing.T) {
	e := newEnv(t, 4096)
	e.cfg.DiskReserveBytes = 1 << 20
	e.cfg.FreeBytes = func(string) (int64, error) { return 3 << 20, nil }
	e.open()
	h, err := e.m.reserveDisk(1500 << 10)
	must(t, err)
	if _, err := e.m.reserveDisk(1500 << 10); !errors.Is(err, ErrQuota) {
		t.Fatalf("second reservation while the first is held: %v", err)
	}
	h.release()
	h, err = e.m.reserveDisk(1500 << 10)
	must(t, err)
	h.release()
	// Many concurrent reservations never over-commit.
	var wg sync.WaitGroup
	var mu sync.Mutex
	var held []*diskHold
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h, err := e.m.reserveDisk(512 << 10); err == nil {
				mu.Lock()
				held = append(held, h)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(held) != 4 {
		t.Fatalf("%d concurrent reservations of 512 KiB granted from 2 MiB", len(held))
	}
}

// RES-4: a merge reserves its merged layer and dst's restart up front.
func TestRES4MergeRefusedLeavesDestinationRunning(t *testing.T) {
	e := newEnv(t, 4096)
	free := int64(1 << 40)
	e.cfg.DiskReserveBytes = 1 << 20
	e.cfg.FreeBytes = func(string) (int64, error) { return free, nil }
	e.open()
	e.create("dst", admission.Accepted, 1)
	_, err := e.m.Fork(bg, "dst", []string{"k"})
	must(t, err)
	e.guestWrite("k", "data", strings.Repeat("x", 256<<10))
	e.guestWrite("dst", "mine", "kept")
	// Enough for the fork's step, not for the merged layer and restart.
	free = 1<<20 + 400<<10
	if _, err := e.m.Merge(bg, "dst", "k"); !errors.Is(err, ErrQuota) {
		t.Fatalf("merge over the disk budget: %v", err)
	}
	if m, _ := e.m.Get("dst"); m.State != Running || e.guestRead("dst", "mine") != "kept" {
		t.Fatalf("refused merge changed dst: %s", m.State)
	}
	free = 1 << 40
	if _, err := e.m.Merge(bg, "dst", "k"); err != nil {
		t.Fatalf("merge with room: %v", err)
	}
}

// RES-4: a guest that grows its layer while the fork checkpoints it can
// push the fork over the disk budget after the checkpoint is taken; the
// fork is refused and its checkpoint is not left behind.
func TestRES4ForkRefusedAfterCheckpointLeavesNoSnapshot(t *testing.T) {
	e := newEnv(t, 4096)
	e.cfg.DiskReserveBytes = 1 << 20
	calls := 0
	e.cfg.FreeBytes = func(string) (int64, error) {
		calls++
		if calls > 2 { // the reservation before the checkpoint, the checkpoint's own
			return 1<<20 + 64<<10, nil
		}
		return 1 << 40, nil
	}
	e.open()
	e.create("src", admission.Accepted, 1)
	e.guestWrite("src", "small", "x")
	e.rt.onPause = func(id string) {
		e.rt.onPause = nil
		e.guestWrite(id, "grown", strings.Repeat("x", 256<<10))
	}
	before := e.adm.Snapshot().FreeMB
	if _, err := e.m.Fork(bg, "src", []string{"f1", "f2"}); !errors.Is(err, ErrQuota) {
		t.Fatalf("fork over budget after checkpoint: %v", err)
	}
	if calls != 3 {
		t.Fatalf("disk checked %d times, want the post-checkpoint check to run", calls)
	}
	m, _ := e.m.Get("src")
	ents, _ := os.ReadDir(filepath.Join(e.cfg.StateDir, "snapshots"))
	if len(e.m.Snapshots("src")) != 0 || len(ents) != 0 || m.Last != "" || m.State != Running ||
		len(e.m.Machines()) != 1 || e.adm.Snapshot().FreeMB != before {
		t.Fatalf("refused fork left state: %d snapshots, %d dirs, last %q, %s", len(e.m.Snapshots("src")), len(ents), m.Last, m.State)
	}
}

// LOOP-5: a replay hands the guest its inputs by seeding a fresh machine's
// layer; seed paths cannot leave the layer.
func TestLOOP5SeededMachineSeesItsInputs(t *testing.T) {
	e := newEnv(t, 4096)
	seed := map[string][]byte{"etc/agentos/tree/procedures/a.md": []byte("step one")}
	if _, err := e.m.CreateSeeded(bg, "m", Spec{Image: "base", Class: admission.Experiment, MemMB: 100}, seed); err != nil {
		t.Fatal(err)
	}
	if got := e.guestRead("m", "etc/agentos/tree/procedures/a.md"); got != "step one" {
		t.Fatalf("seed = %q", got)
	}
	if e.guestRead("m", "etc/os-release") != "image v1" {
		t.Fatal("seed hid the image")
	}
	must(t, os.Remove(e.upper("m", "etc/agentos/tree/procedures/a.md")))
	must(t, e.m.Rebuild(bg, "m"))
	if got := e.guestRead("m", "etc/agentos/tree/procedures/a.md"); got != "step one" {
		t.Fatalf("seed after rebuild = %q", got)
	}
	for _, p := range []string{"../escape", "/etc/passwd", "a/../../b", "a//b", ""} {
		if _, err := e.m.CreateSeeded(bg, "bad", Spec{Image: "base", Class: admission.Experiment, MemMB: 100}, map[string][]byte{p: nil}); err == nil {
			t.Errorf("seed path %q accepted", p)
		}
	}
	if len(e.m.Machines()) != 1 {
		t.Fatalf("refused seeds left machines: %v", e.m.Machines())
	}
}

// LOOP-5, ARC-6: replay machine IDs are kept for replay. Nothing else can
// take one, and a replay machine is never forked or forked into, so its
// guest services stay replay's.
func TestLOOP5ReplayIDsAreReserved(t *testing.T) {
	e := newEnv(t, 4096)
	if _, err := e.m.Create(bg, EvalPrefix+"x", Spec{Image: "base", Class: admission.Experiment, MemMB: 100}); err == nil {
		t.Fatal("Create took a replay id")
	}
	e.create("src", admission.Accepted, 100)
	if _, err := e.m.Fork(bg, "src", []string{EvalPrefix + "y"}); err == nil {
		t.Fatal("Fork made a replay id")
	}
	if _, err := e.m.CreateSeeded(bg, EvalPrefix+"r", Spec{Image: "base", Class: admission.Experiment, MemMB: 100}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Fork(bg, EvalPrefix+"r", []string{"f"}); err == nil {
		t.Fatal("a replay machine was forked")
	}
}

// RES-4: a seed is admitted against the disk like any layer copy.
func TestRES4SeedAdmittedOnTheDisk(t *testing.T) {
	e := newEnv(t, 4096)
	e.cfg.DiskReserveBytes = 1 << 20
	e.cfg.FreeBytes = func(string) (int64, error) { return 1<<20 + 64<<10, nil }
	e.open()
	big := map[string][]byte{"etc/big": make([]byte, 128<<10)}
	if _, err := e.m.CreateSeeded(bg, "m", Spec{Image: "base", Class: admission.Experiment, MemMB: 100}, big); !errors.Is(err, ErrQuota) {
		t.Fatalf("seed over the disk budget: %v", err)
	}
	e.cfg.FreeBytes = func(string) (int64, error) { return 1 << 40, nil }
	e.cfg.MaxLayerBytes = 64 << 10
	e.open()
	if _, err := e.m.CreateSeeded(bg, "m", Spec{Image: "base", Class: admission.Experiment, MemMB: 100}, big); !errors.Is(err, ErrQuota) {
		t.Fatalf("seed over the layer cap: %v", err)
	}
	if len(e.m.Machines()) != 0 {
		t.Fatalf("refused seeds left machines: %v", e.m.Machines())
	}
}
