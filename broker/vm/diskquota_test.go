package vm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/quota"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// REQ: RES-4
//
// Security review 2, finding 3 (SR2-3): each machine, workers included,
// writes under its own hard disk quota, and the disk its guests may still
// write is held back from the reserve, so no guest, nor all of them
// together, can fill the disk the journal and owner state live on.

// fakeQuota records limits; a project's use is what its directory holds.
type fakeQuota struct {
	mu      sync.Mutex
	dirs    map[uint32]string
	limits  map[uint32][2]int64
	cleared map[uint32]bool
	tagged  []string // "dir=project", every Tag
}

func newFakeQuota() *fakeQuota {
	return &fakeQuota{dirs: map[uint32]string{}, limits: map[uint32][2]int64{}, cleared: map[uint32]bool{}}
}

func (q *fakeQuota) Limit(dir string, p uint32, bytes, inodes int64) error {
	if p == 0 {
		return errors.New("fake: project 0")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.dirs[p], q.limits[p] = dir, [2]int64{bytes, inodes}
	delete(q.cleared, p)
	return nil
}

func (q *fakeQuota) Usage(p uint32) (quota.Usage, error) {
	q.mu.Lock()
	dir, l := q.dirs[p], q.limits[p]
	q.mu.Unlock()
	u, err := overlay.Measure(dir)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return quota.Usage{Bytes: u.Bytes, Inodes: u.Inodes, LimitBytes: l[0], LimitInodes: l[1]}, err
}

func (q *fakeQuota) Tag(root string, p uint32) error {
	if p == 0 {
		return errors.New("fake: project 0")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.tagged = append(q.tagged, fmt.Sprintf("%s=%d", root, p))
	return nil
}

func (q *fakeQuota) Clear(p uint32) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.limits, p)
	q.cleared[p] = true
	return nil
}

func newQuotaEnv(t *testing.T, budget int64) (*env, *fakeQuota) {
	e := newEnv(t, 8192)
	q := newFakeQuota()
	e.cfg.Quota, e.cfg.MachineDiskBytes = q, budget
	e.open()
	return e, q
}

func (e *env) lastLaunch(id string) Launch {
	e.t.Helper()
	e.rt.mu.Lock()
	defer e.rt.mu.Unlock()
	for i := len(e.rt.launches) - 1; i >= 0; i-- {
		if e.rt.launches[i].ID == id {
			return e.rt.launches[i]
		}
	}
	e.t.Fatalf("%s never launched", id)
	return Launch{}
}

func TestEveryMachineKindWritesUnderItsOwnQuota(t *testing.T) {
	e, q := newQuotaEnv(t, 64<<20)
	a := e.create("agent", admission.Accepted, 100)
	if _, err := e.m.Create(bg, BuilderPrefix+"1", Spec{Image: "base", Class: admission.Accepted, MemMB: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.CreateWorker(bg, WorkerPrefix+"1", a.Lineage, Spec{Image: "base", Class: admission.Accepted, MemMB: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.CreateSeeded(bg, EvalPrefix+"1", Spec{Image: "base", Class: admission.Accepted, MemMB: 100, Label: Private}, map[string][]byte{"in": []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Fork(bg, "agent", []string{"fork"}); err != nil {
		t.Fatal(err)
	}
	seen := map[uint32]string{}
	for _, id := range []string{"agent", BuilderPrefix + "1", WorkerPrefix + "1", EvalPrefix + "1", "fork"} {
		mc, err := e.m.Get(id)
		must(t, err)
		p := mc.Project
		if p == 0 || seen[p] != "" {
			t.Fatalf("%s: project %d (seen for %q)", id, p, seen[p])
		}
		seen[p] = id
		dir := filepath.Join(e.cfg.StateDir, "machines", id, "disk")
		if q.dirs[p] != dir || q.limits[p] != [2]int64{64 << 20, 200_000} {
			t.Fatalf("%s: quota on %q limits %v", id, q.dirs[p], q.limits[p])
		}
		l := e.lastLaunch(id)
		for _, w := range []string{l.Upper, l.Work} {
			if !within(dir, w) || w == dir {
				t.Fatalf("%s: guest-written %s is outside its quota directory %s", id, w, dir)
			}
		}
		if within(dir, filepath.Join(l.Dir, "meta.json")) {
			t.Fatalf("%s: the machine's record is inside its guest's quota", id)
		}
	}
	// Projects survive a broker restart and stay unique after it.
	e.open()
	mc, err := e.m.Create(bg, "later", Spec{Image: "base", Class: admission.Accepted, MemMB: 100})
	must(t, err)
	if seen[mc.Project] != "" || mc.Project == 0 {
		t.Fatalf("project %d reused after restart", mc.Project)
	}
	if got, _ := e.m.Get("agent"); got.Project == 0 || seen[got.Project] != "agent" {
		t.Fatalf("agent's project after restart: %d", got.Project)
	}
}

func TestDestroyClearsTheMachinesQuota(t *testing.T) {
	e, q := newQuotaEnv(t, 64<<20)
	mc := e.create("m", admission.Accepted, 100)
	must(t, e.m.Destroy(bg, "m"))
	if !q.cleared[mc.Project] {
		t.Fatal("destroyed machine's quota left set")
	}
}

func TestUnusedQuotaIsHeldBackFromTheReserve(t *testing.T) {
	const budget, reserve = int64(1 << 30), int64(2 << 30)
	free := reserve + 2*(budget+ConsoleMaxBytes) + 1<<20
	e := newEnv(t, 8192)
	e.cfg.Quota, e.cfg.MachineDiskBytes, e.cfg.DiskReserveBytes = newFakeQuota(), budget, reserve
	e.cfg.FreeBytes = func(string) (int64, error) { return free, nil }
	e.open()
	e.create("m1", admission.Accepted, 100)
	e.create("m2", admission.Accepted, 100)
	// Two guests may still write two budgets: a third would let them
	// together write into the reserve.
	_, err := e.m.Create(bg, "m3", Spec{Image: "base", Class: admission.Accepted, MemMB: 100})
	if !errors.Is(err, ErrDiskFull) {
		t.Fatalf("third machine started with its budget over the reserve: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.StateDir, "machines", "m3")); !os.IsNotExist(err) {
		t.Fatal("refused machine left on disk")
	}
	// A snapshot copy is admitted only above what running guests may
	// still write.
	e.guestWrite("m1", "big", strings.Repeat("x", 1536<<10))
	free -= 1536 << 10
	if _, err := e.m.Step(bg, "m1"); !errors.Is(err, ErrQuota) {
		t.Fatalf("snapshot into the room running guests may still fill: %v", err)
	}
	// A stopped guest writes nothing: its budget is free again.
	must(t, e.m.Preempt("m2"))
	e.adm.Release("m2")
	if _, err := e.m.Step(bg, "m1"); err != nil {
		t.Fatalf("snapshot with m2 stopped: %v", err)
	}
	free -= 1536 << 10
	if err := e.m.Resume(bg, "m2"); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("resumed with its budget over the reserve: %v", err)
	}
	must(t, e.m.Destroy(bg, "m1"))
	must(t, e.m.Resume(bg, "m2"))
}

func TestLayerCapDefaultsToTheMachineBudget(t *testing.T) {
	e, _ := newQuotaEnv(t, 64<<10)
	if e.m.cfg.MaxLayerBytes != 64<<10 {
		t.Fatalf("MaxLayerBytes %d, want the machine budget", e.m.cfg.MaxLayerBytes)
	}
	e.create("m", admission.Accepted, 100)
	e.guestWrite("m", "big", strings.Repeat("x", 128<<10))
	if _, err := e.m.Step(bg, "m"); !errors.Is(err, ErrQuota) {
		t.Fatalf("snapshot of a layer over the machine budget: %v", err)
	}
}

func TestOpenRequiresAQuotaUnlessDeclaredOff(t *testing.T) {
	e := newEnv(t, 1024)
	cfg := e.cfg
	cfg.NoQuota, cfg.Quota = false, nil
	if _, err := Open(bg, cfg); err == nil || !strings.Contains(err.Error(), "RES-4") {
		t.Fatalf("opened with no disk quota: %v", err)
	}
}

// A layer resumed as it is may hold files the quota does not cover: one
// written while quotas were off, or copied or restored with its tags
// lost. Every such resume tags the whole layer first (L3 on #152).
func TestEveryResumeOnALayerTagsItAgain(t *testing.T) {
	e := newEnv(t, 1024)
	e.create("m", admission.Accepted, 100)
	e.guestWrite("m", "f", "untracked")
	must(t, e.m.Preempt("m"))
	e.adm.Release("m")
	q := newFakeQuota()
	e.cfg.NoQuota, e.cfg.Quota = false, q
	e.open()
	must(t, e.m.Resume(bg, "m"))
	mc, _ := e.m.Get("m")
	dir := filepath.Join(e.cfg.StateDir, "machines", "m", "disk")
	if mc.Project == 0 || len(q.tagged) != 1 || q.tagged[0] != fmt.Sprintf("%s=%d", dir, mc.Project) {
		t.Fatalf("project %d, tagged %v", mc.Project, q.tagged)
	}
	if e.guestRead("m", "f") != "untracked" {
		t.Fatal("layer lost")
	}
	// Again on every resume on the layer, quotas on all along.
	must(t, e.m.Preempt("m"))
	e.adm.Release("m")
	must(t, e.m.Resume(bg, "m"))
	if len(q.tagged) != 2 {
		t.Fatalf("second resume tagged %v", q.tagged)
	}
}

// A creation whose kill failed leaves its guest counted, even when its ID
// is taken again (L3 on #152).
func TestAFailedCreationWhoseKillFailedStaysCounted(t *testing.T) {
	const budget, reserve = int64(1 << 30), int64(2 << 30)
	e := newEnv(t, 8192)
	e.cfg.Quota, e.cfg.MachineDiskBytes, e.cfg.DiskReserveBytes = newFakeQuota(), budget, reserve
	e.cfg.FreeBytes = func(string) (int64, error) { return reserve + 2*(budget+ConsoleMaxBytes) + 1<<20, nil }
	e.open()
	e.rt.failNext = errors.New("fake: start failed")
	e.rt.failKill = errors.New("fake: kill failed")
	if _, err := e.m.Create(bg, "m", Spec{Image: "base", Class: admission.Accepted, MemMB: 100}); err == nil {
		t.Fatal("creation succeeded")
	}
	e.rt.failKill = nil
	e.create("m", admission.Accepted, 100)
	if _, err := e.m.Create(bg, "m2", Spec{Image: "base", Class: admission.Accepted, MemMB: 100}); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("the unkilled guest's room was handed out: %v", err)
	}
}

// A guest whose kill failed may still be writing: it stays counted against
// the reserve until a kill succeeds (security F1 on #152).
func TestAGuestWhoseKillFailedStaysCounted(t *testing.T) {
	const budget, reserve = int64(1 << 30), int64(2 << 30)
	e := newEnv(t, 8192)
	e.cfg.Quota, e.cfg.MachineDiskBytes, e.cfg.DiskReserveBytes = newFakeQuota(), budget, reserve
	e.cfg.FreeBytes = func(string) (int64, error) { return reserve + budget + ConsoleMaxBytes + 1<<20, nil }
	e.open()
	e.create("m1", admission.Accepted, 100)
	e.rt.failKill = errors.New("fake: kill failed")
	if err := e.m.Destroy(bg, "m1"); err == nil {
		t.Fatal("destroy reported success with the kill failing")
	}
	e.rt.failKill = nil
	e.adm.Release("m1")
	if _, err := e.m.Create(bg, "m2", Spec{Image: "base", Class: admission.Accepted, MemMB: 100}); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("started into the room of a guest that may still run: %v", err)
	}
	must(t, e.m.Destroy(bg, "m1"))
	if _, err := e.m.Create(bg, "m2", Spec{Image: "base", Class: admission.Accepted, MemMB: 100}); err != nil {
		t.Fatalf("after a successful kill: %v", err)
	}
}

// A guest a restarted broker could not kill stays counted (L3 on #152).
func TestAGuestARestartCouldNotKillStaysCounted(t *testing.T) {
	const budget, reserve = int64(1 << 30), int64(2 << 30)
	e := newEnv(t, 8192)
	e.cfg.Quota, e.cfg.MachineDiskBytes, e.cfg.DiskReserveBytes = newFakeQuota(), budget, reserve
	e.cfg.FreeBytes = func(string) (int64, error) { return reserve + 2*(budget+ConsoleMaxBytes) + 1<<20, nil }
	e.open()
	e.create("m1", admission.Accepted, 100)
	e.rt.failKill = errors.New("fake: kill failed")
	e.open()
	e.rt.failKill = nil
	e.create("m2", admission.Accepted, 100)
	if _, err := e.m.Create(bg, "m3", Spec{Image: "base", Class: admission.Accepted, MemMB: 100}); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("the unkilled guest's room was handed out: %v", err)
	}
}

// A worker's quota is its layer cap when that is smaller (CAP-8b).
func TestAWorkersQuotaIsItsLayerCap(t *testing.T) {
	e := newEnv(t, 8192)
	q := newFakeQuota()
	e.cfg.Quota, e.cfg.MachineDiskBytes, e.cfg.WorkerLayerBytes = q, 64<<20, 16<<20
	e.open()
	a := e.create("agent", admission.Accepted, 100)
	if _, err := e.m.CreateWorker(bg, WorkerPrefix+"1", a.Lineage, Spec{Image: "base", Class: admission.Accepted, MemMB: 100}); err != nil {
		t.Fatal(err)
	}
	w, _ := e.m.Get(WorkerPrefix + "1")
	if q.limits[w.Project][0] != 16<<20 || q.limits[a.Project][0] != 64<<20 {
		t.Fatalf("worker limit %v, agent limit %v", q.limits[w.Project], q.limits[a.Project])
	}
}
