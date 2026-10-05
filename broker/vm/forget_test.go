package vm

// REQ: CAP-3, REV-4, REV-5

import (
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
