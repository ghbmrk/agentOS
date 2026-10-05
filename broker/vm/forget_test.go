package vm

// REQ: CAP-3, REV-4, REV-5

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
)

// CAP-3 deletion reach: once a lineage was given a deleted record at T,
// every machine of it goes back to before T (memory too, where a full
// checkpoint allows), and every snapshot of it from T on is deleted, those
// of destroyed machines included. Other lineages are untouched.
func TestCAP3ForgetSinceTakesBackALineagesMemory(t *testing.T) {
	e := newEnv(t, 8192)
	e.create("m1", admission.Accepted, 500)
	e.create("other", admission.Accepted, 500)
	e.rt.work("m1", 7)
	e.guestWrite("m1", "notes", "before")
	pre, err := e.m.Checkpoint(bg, "m1")
	must(t, err)
	time.Sleep(5 * time.Millisecond)
	since := time.Now().UTC()
	time.Sleep(5 * time.Millisecond)

	// From T the lineage holds the record, in files and memory.
	e.guestWrite("m1", "notes", "secret")
	e.rt.work("m1", 100)
	_, err = e.m.Step(bg, "m1")
	must(t, err)
	base, err := e.m.Fork(bg, "m1", []string{"f1", "f2"})
	must(t, err)
	e.guestWrite("f2", "copy", "secret")
	gone, err := e.m.Step(bg, "f2")
	must(t, err)
	must(t, e.m.Destroy(bg, "f2"))
	must(t, e.m.Preempt("f1"))
	e.guestWrite("other", "x", "unrelated")
	keep, err := e.m.Step(bg, "other")
	must(t, err)

	mc, _ := e.m.Get("m1")
	must(t, e.m.ForgetSince(bg, mc.Lineage, since))

	// The running machine is back at its checkpoint, memory included.
	if got := e.guestRead("m1", "notes"); got != "before" {
		t.Fatalf("m1 notes = %q", got)
	}
	if mem, ok := e.rt.memOf("m1"); !ok || mem != 7 {
		t.Fatalf("m1 memory %d running=%v; want the checkpoint's", mem, ok)
	}
	if mc, _ := e.m.Get("m1"); mc.Last != pre.ID || mc.Label != Public {
		t.Fatalf("m1 after: %+v", mc)
	}
	// The preempted fork, with nothing of its own before T, is back to its
	// image on disk and stays preempted; its fork point is gone.
	f1, _ := e.m.Get("f1")
	if f1.State != Preempted || f1.ForkBase != "" || f1.Last != "" || e.guestRead("f1", "notes") != "" {
		t.Fatalf("f1 after: %+v notes=%q", f1, e.guestRead("f1", "notes"))
	}
	for _, id := range []string{base.ID, gone.ID} {
		if _, err := e.m.Snapshot(id); err == nil {
			t.Errorf("snapshot %s from after T survived", id)
		}
		if _, err := os.Stat(e.m.snapDir(id)); !os.IsNotExist(err) {
			t.Errorf("snapshot %s left on disk", id)
		}
	}
	if got := e.m.Snapshots("m1"); len(got) != 1 || got[0].ID != pre.ID {
		t.Fatalf("m1 snapshots after: %+v", got)
	}
	if _, err := e.m.Snapshot(keep.ID); err != nil || e.guestRead("other", "x") != "unrelated" {
		t.Fatal("another lineage was touched")
	}
	// Idempotent, and the state survives a broker restart.
	must(t, e.m.ForgetSince(bg, mc.Lineage, since))
	e.adm.Release("m1")
	e.adm.Release("other")
	e.adm.Release("f1")
	e.rt = newFake()
	e.cfg.Runtime = e.rt
	e.open()
	if _, err := e.m.Snapshot(base.ID); err == nil {
		t.Fatal("deleted snapshot back after restart")
	}
	must(t, e.m.Resume(bg, "f1"))
	if e.guestRead("f1", "notes") != "" {
		t.Fatal("f1 resumed with the record")
	}
}

// A refused restart (disk) leaves the machine running as it was and the
// call fails, so the caller retries; nothing after T is kept as done.
func TestCAP3ForgetSinceFailsWhenItCannotReset(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	e.guestWrite("m", "big", "before")
	_, err := e.m.Step(bg, "m")
	must(t, err)
	since := time.Now().UTC()
	time.Sleep(5 * time.Millisecond)
	e.guestWrite("m", "big", "secret")
	e.m.cfg.FreeBytes = func(string) (int64, error) { return 0, nil }
	mc, _ := e.m.Get("m")
	if err := e.m.ForgetSince(bg, mc.Lineage, since); err == nil {
		t.Fatal("reset refused but ForgetSince succeeded")
	}
	if got, _ := e.m.Get("m"); got.State != Running {
		t.Fatalf("machine left %s", got.State)
	}
	e.m.cfg.FreeBytes = func(string) (int64, error) { return 1 << 50, nil }
	must(t, e.m.ForgetSince(bg, mc.Lineage, since))
	if e.guestRead("m", "big") != "before" {
		t.Fatal("retry did not reset")
	}
}

// A snapshot is dated when its capture completes (#59 L3 3): a record
// handed to the machine while it was being copied must not land in a
// snapshot that reads as taken before it, or ForgetSince would restore
// it.
func TestCAP3SnapshotTakenDuringAReadIsNotARestorePoint(t *testing.T) {
	e := newEnv(t, 8192)
	e.create("m", admission.Accepted, 500)
	e.rt.work("m", 3)
	pre, err := e.m.Checkpoint(bg, "m")
	must(t, err)
	time.Sleep(2 * time.Millisecond)
	var read time.Time
	e.rt.onCkpt = func(string) {
		// recall_search answered while the capture runs.
		read = time.Now().UTC()
		time.Sleep(2 * time.Millisecond)
	}
	e.rt.work("m", 50)
	during, err := e.m.Checkpoint(bg, "m")
	must(t, err)
	e.rt.onCkpt = nil
	if !during.Taken.After(read) {
		t.Fatalf("snapshot dated %v, before the read at %v it may hold", during.Taken, read)
	}
	mc, _ := e.m.Get("m")
	must(t, e.m.ForgetSince(bg, mc.Lineage, read))
	if mem, _ := e.rt.memOf("m"); mem != 3 {
		t.Fatalf("memory %d after the reset; want the checkpoint before the read", mem)
	}
	if _, err := e.m.Snapshot(during.ID); err == nil {
		t.Fatal("the snapshot taken during the read survived")
	}
	if got := e.m.Snapshots("m"); len(got) != 1 || got[0].ID != pre.ID {
		t.Fatalf("snapshots after: %+v", got)
	}
}

// ResetPlan measures what a reset would lose without changing anything:
// the restore point and the files changed since it (recall W10).
func TestCAP3ResetPlanMeasuresInMachineWork(t *testing.T) {
	e := newEnv(t, 8192)
	e.create("m", admission.Accepted, 500)
	mc, _ := e.m.Get("m")
	since := time.Now().UTC()
	e.guestWrite("m", "a", "1")
	// No snapshot before since: a fresh start, everything in the layer.
	p, err := e.m.ResetPlan(mc.Lineage, since)
	must(t, err)
	if !p.To.IsZero() || p.Changes != 1 {
		t.Fatalf("plan with no restore point: %+v", p)
	}
	pre, err := e.m.Checkpoint(bg, "m")
	must(t, err)
	time.Sleep(2 * time.Millisecond)
	since = time.Now().UTC()
	p, err = e.m.ResetPlan(mc.Lineage, since)
	must(t, err)
	if !p.To.Equal(pre.Taken) || p.Changes != 0 {
		t.Fatalf("plan with nothing done since: %+v (restore point %v)", p, pre.Taken)
	}
	e.guestWrite("m", "a", "2")
	e.guestWrite("m", "b/c", "3")
	p, err = e.m.ResetPlan(mc.Lineage, since)
	must(t, err)
	if !p.To.Equal(pre.Taken) || p.Changes < 2 {
		t.Fatalf("plan after work: %+v", p)
	}
	if e.guestRead("m", "a") != "2" {
		t.Fatal("ResetPlan changed the machine")
	}
	if _, err := e.m.ResetPlan("", since); err == nil {
		t.Fatal("ResetPlan without a lineage")
	}
}

// While a lineage holds a record the owner deleted and is not rolled back,
// it is not forked or merged (recall W10 containment).
func TestCAP3ContainedLineageIsNotForkedOrMerged(t *testing.T) {
	e := newEnv(t, 8192)
	held := map[string]bool{}
	e.cfg.Contained = func(l string) bool { return held[l] }
	e.open()
	e.create("m", admission.Accepted, 500)
	_, err := e.m.Fork(bg, "m", []string{"f"})
	must(t, err)
	mc, _ := e.m.Get("m")
	held[mc.Lineage] = true
	if _, err := e.m.Fork(bg, "m", []string{"g"}); !errors.Is(err, ErrContained) {
		t.Fatalf("fork of a contained lineage: %v", err)
	}
	if _, err := e.m.Merge(bg, "m", "f"); !errors.Is(err, ErrContained) {
		t.Fatalf("merge of a contained lineage: %v", err)
	}
	held[mc.Lineage] = false
	if _, err := e.m.Merge(bg, "m", "f"); err != nil {
		t.Fatalf("merge once released: %v", err)
	}
}

// A reset restarts a running machine, which opens its services again, so
// the guest plane hands its unanswered owner messages out again (guest
// G5): a silent rollback does not drop an owner task (#59 UX-59-3).
func TestCAP3ForgetSinceReopensServices(t *testing.T) {
	e := newEnv(t, 8192)
	svc := &recServices{root: t.TempDir(), open: map[string]bool{}}
	e.cfg.Services = svc
	e.open()
	e.create("m", admission.Accepted, 500)
	_, err := e.m.Checkpoint(bg, "m")
	must(t, err)
	time.Sleep(2 * time.Millisecond)
	since := time.Now().UTC()
	e.guestWrite("m", "read", "deleted mail")
	before := len(svc.opened)
	mc, _ := e.m.Get("m")
	must(t, e.m.ForgetSince(bg, mc.Lineage, since))
	if len(svc.opened) != before+1 || svc.opened[len(svc.opened)-1] != "m" || !svc.open["m"] {
		t.Fatalf("services opened %v (before the reset: %d)", svc.opened, before)
	}
}
