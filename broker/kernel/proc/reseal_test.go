package proc

// REQ: KRN-7, LOG-4

import (
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// hungTarget, once hang is set, blocks every call until release closes,
// as a dying drive stuck in D state does, and says so on entered.
type hungTarget struct {
	backup.Target
	hang    *atomic.Bool
	entered chan struct{}
	release chan struct{}
	free    func() // closes release, once
}

func (h hungTarget) wait() {
	if h.hang.Load() {
		select {
		case h.entered <- struct{}{}:
		default:
		}
		<-h.release
	}
}

func (h hungTarget) Tables(id string) ([]uint64, error) {
	h.wait()
	return h.Target.Tables(id)
}

func (h hungTarget) GetTable(id string, gen uint64) ([]byte, error) {
	h.wait()
	return h.Target.GetTable(id, gen)
}

func (h hungTarget) PutTable(id string, gen uint64, b []byte) error {
	h.wait()
	return h.Target.PutTable(id, gen, b)
}

func (h hungTarget) DeleteTable(id string, gen uint64) error {
	h.wait()
	return h.Target.DeleteTable(id, gen)
}

// hungBox is a box with one backup, kept at a target that hangs from now on.
func hungBox(t *testing.T) (b *bbox, gone, live, dir, id string, h hungTarget) {
	b = newBBox(t, recipientWire(t, testRK))
	gone, live = b.subject(), b.subject()
	dir = b.addTarget("drive", false)
	h = hungTarget{hang: new(atomic.Bool), entered: make(chan struct{}, 1), release: make(chan struct{})}
	h.free = sync.OnceFunc(func() { close(h.release) })
	// A failed test still lets the target answer, so it ends.
	t.Cleanup(h.free)
	b.h.bk.wrap = func(tg backup.Target) backup.Target { h.Target = tg; return h }
	id = b.backup()[0].Backup.BackupID
	h.hang.Store(true)
	return
}

// within fails t unless fn returns within two seconds.
func within(t *testing.T, what string, fn func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s waited on a hung backup target", what)
	}
}

// gives reports whether the backup's table at dir still gives sub's key.
func gives(t *testing.T, dir, id, sub string) bool {
	_, keys := openBackup(t, dir, id, testRK)
	_, ok, _ := keys.Get(sub)
	return ok
}

// KRN-7 (#3317, Security on #3311): an erase's backup re-seal at a target
// that hangs holds neither the lock nor STOP, which returns at once; the
// erase's own reply waits. Once the target answers, the re-seal lands.
// A re-seal under the lock fails here.
func TestAnEraseAtAHungTargetNeverHoldsStop(t *testing.T) {
	b, gone, live, dir, id, h := hungBox(t)
	erased := make(chan kernel.Confirmation, 1)
	go func() { c, _ := b.h.Erase(b.now, gone); erased <- c }()
	<-h.entered
	within(t, "STOP", func() error { return b.h.With(func(k *kernel.Kernel) error { return k.Stop(b.now) }) })
	h.free()
	if c := <-erased; !slices.Equal(c.Resealed, []string{id}) || len(c.StillHeld) != 0 {
		t.Fatalf("the erase's confirmation: %+v", c)
	}
	if gives(t, dir, id, gone) || !gives(t, dir, id, live) {
		t.Fatal("the re-sealed table is wrong")
	}
}

// KRN-7 (#3317 scope addition, delta Security on #3311): Tick's re-seal of
// a backup that gives an erased subject's key runs without the lock and
// without holding Tick, so a hung target holds neither Tick nor STOP.
func TestATickAtAHungTargetNeverHoldsStop(t *testing.T) {
	b, gone, _, dir, id, h := hungBox(t)
	// The kernel's own Erase names the backup and leaves its re-seal due.
	if err := b.h.With(func(k *kernel.Kernel) error { _, err := k.Erase(b.now, gone); return err }); err != nil {
		t.Fatal(err)
	}
	within(t, "Tick", func() error { return b.h.Tick(b.now) })
	<-h.entered
	within(t, "STOP", func() error { return b.h.With(func(k *kernel.Kernel) error { return k.Stop(b.now) }) })
	within(t, "a second Tick", func() error { return b.h.Tick(b.now + 1) })
	h.free()
	b.h.reseals.Wait()
	if gives(t, dir, id, gone) {
		t.Fatal("the table still gives the erased key once the target answers")
	}
}
