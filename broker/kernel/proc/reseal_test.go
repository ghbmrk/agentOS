package proc

// REQ: KRN-7, LOG-4

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// hungTarget, once hang is set, blocks every call until release closes,
// as a dying drive stuck in D state does, and says so on entered. Once
// fail is set, a put that gets through fails.
type hungTarget struct {
	backup.Target
	hang    *atomic.Bool
	fail    *atomic.Bool
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

var errDrive = errors.New("synthetic: the drive gave an I/O error")

func (h hungTarget) PutTable(id string, gen uint64, b []byte) error {
	h.wait()
	if h.fail.Load() {
		return errDrive
	}
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
	h = hungTarget{hang: new(atomic.Bool), fail: new(atomic.Bool), entered: make(chan struct{}, 1), release: make(chan struct{})}
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

// erasing erases sub from the process on its own goroutine and returns
// once the erase is logged, so its reply is what remains.
func erasing(t *testing.T, b *bbox, sub string) (<-chan kernel.Confirmation, <-chan error) {
	t.Helper()
	cs, errs := make(chan kernel.Confirmation, 1), make(chan error, 1)
	go func() { c, err := b.h.Erase(b.now, sub); cs <- c; errs <- err }()
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(time.Millisecond) {
		erased := false
		b.h.With(func(k *kernel.Kernel) error { r, _ := k.State().Recall(sub); erased = r.Erased; return nil })
		if erased {
			return cs, errs
		}
		if time.Now().After(deadline) {
			t.Fatal("the erase was never logged")
		}
	}
}

// waiting fails t if a reply comes on cs within a tenth of a second.
func waiting(t *testing.T, what string, cs <-chan kernel.Confirmation) {
	t.Helper()
	select {
	case c := <-cs:
		t.Fatalf("%s replied while a re-seal it names hangs: %+v", what, c)
	case <-time.After(100 * time.Millisecond):
	}
}

// reply is the erase's reply on cs, failing t if none comes in two seconds.
func reply(t *testing.T, cs <-chan kernel.Confirmation) kernel.Confirmation {
	t.Helper()
	select {
	case c := <-cs:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("the erase never replied")
	}
	return kernel.Confirmation{}
}

// tickHung erases gone in the kernel alone, so its re-seal is left due,
// then lets a Tick start that re-seal, which hangs at the target with its
// table prepared while live is still live.
func tickHung(t *testing.T, b *bbox, gone string, h hungTarget) {
	t.Helper()
	if err := b.h.With(func(k *kernel.Kernel) error { _, err := k.Erase(b.now, gone); return err }); err != nil {
		t.Fatal(err)
	}
	within(t, "Tick", func() error { return b.h.Tick(b.now) })
	<-h.entered
}

// LOG-4 (#3338, L3 finding 1 and UX finding 1 on #3332): an erase that
// names a backup whose Tick re-seal is running waits for it, then
// re-seals again, since that table was prepared before the erase; it
// never holds STOP. The reply names the backup Resealed only once its
// table gives neither erased subject. Mutant: drop the wait for the
// running re-seal, or the re-seal after it.
func TestAnEraseWaitsForATickResealItNames(t *testing.T) {
	b, gone, live, dir, id, h := hungBox(t)
	tickHung(t, b, gone, h)
	cs, _ := erasing(t, b, live)
	waiting(t, "the erase", cs)
	within(t, "STOP", func() error { return b.h.With(func(k *kernel.Kernel) error { return k.Stop(b.now) }) })
	h.hang.Store(false)
	h.free()
	if c := reply(t, cs); !slices.Equal(c.Resealed, []string{id}) || len(c.StillHeld) != 0 {
		t.Fatalf("the erase's confirmation: %+v", c)
	}
	if gives(t, dir, id, gone) || gives(t, dir, id, live) {
		t.Fatal("the backup is named Resealed but its table still gives an erased key")
	}
}

// LOG-4 (#3338): when the running Tick re-seal an erase waits for fails,
// the erase does not override its backoff. It names the backup StillHeld
// with the failure's text, and the next Tick after the backoff re-seals.
func TestAnEraseAfterAFailedTickResealSaysWhy(t *testing.T) {
	b, gone, live, dir, id, h := hungBox(t)
	tickHung(t, b, gone, h)
	cs, _ := erasing(t, b, live)
	waiting(t, "the erase", cs)
	h.fail.Store(true)
	h.hang.Store(false)
	h.free()
	c := reply(t, cs)
	if len(c.Resealed) != 0 || len(c.StillHeld) != 1 || c.StillHeld[0].Backup != id || !strings.Contains(c.StillHeld[0].Why, errDrive.Error()) {
		t.Fatalf("the erase's confirmation: %+v", c)
	}
	h.fail.Store(false)
	b.now += kernel.RetryMax
	b.tick()
	if gives(t, dir, id, gone) || gives(t, dir, id, live) {
		t.Fatal("the Tick after the backoff did not re-seal")
	}
}

// LOG-4 (#3338): a Tick that hands out a named backup's re-seal between
// the erase's two waits holds a table that drops the key, since the erase
// is logged; the erase waits for it too. Mutant: drop that last wait.
func TestAResealTakenBetweenTheWaitsIsWaitedFor(t *testing.T) {
	b, gone, live, dir, id, h := hungBox(t)
	if err := b.h.With(func(k *kernel.Kernel) error { _, err := k.Erase(b.now, gone); return err }); err != nil {
		t.Fatal(err)
	}
	took := make(chan struct{})
	b.h.betweenWaits = func() {
		if err := b.h.Tick(b.now); err != nil {
			t.Error(err)
		}
		<-h.entered
		close(took)
	}
	cs, _ := erasing(t, b, live)
	<-took
	waiting(t, "the erase", cs)
	h.hang.Store(false)
	h.free()
	if c := reply(t, cs); !slices.Equal(c.Resealed, []string{id}) || len(c.StillHeld) != 0 {
		t.Fatalf("the erase's confirmation: %+v", c)
	}
	if gives(t, dir, id, gone) || gives(t, dir, id, live) {
		t.Fatal("the table still gives an erased key")
	}
}

// KRN-7 (#3338, L3 finding 2 on #3332; adopts the Security probe
// TestSecProbeCloseWhileAResealHangs): Close does not wait for a hung
// re-seal, whose commit is then dropped; an erase waiting on it returns,
// the kernel closed, and the next start re-seals. Mutant: close the
// re-seal's channel only inside its commit, so the erase never returns.
func TestCloseLeavesAHungResealToTheNextStart(t *testing.T) {
	b, gone, live, dir, id, h := hungBox(t)
	tickHung(t, b, gone, h)
	cs, errs := erasing(t, b, live)
	old := b.h
	within(t, "Close", old.Close)
	h.hang.Store(false)
	h.free()
	reply(t, cs)
	if err := <-errs; err == nil || !strings.Contains(err.Error(), "kernel closed") {
		t.Fatalf("the erase over a closed kernel: %v", err)
	}
	old.reseals.Wait() // its I/O ran; its commit found the kernel closed
	b.open()
	b.h.bk.wrap = func(tg backup.Target) backup.Target { return tg }
	b.now += 1
	b.tick()
	if gives(t, dir, id, gone) || gives(t, dir, id, live) {
		t.Fatal("after a restart the backup still gives an erased key")
	}
	if gens, _ := (backup.DirTarget{Dir: dir}).Tables(id); len(gens) != 1 {
		t.Fatalf("tables %v", gens)
	}
}

// LOG-4 (#3339 item 2, Security finding 3 on #3332): a re-seal that fails
// slowly backs off from when it finished, read from the process's clock,
// not from when it was handed out, so a slow target still gets its
// backoff. Mutant: pass Resealed the hand-out time.
func TestASlowFailedResealBacksOffFromItsFinish(t *testing.T) {
	b, gone, _, _, id, h := hungBox(t)
	var clock atomic.Int64
	b.h.clock = clock.Load
	h.fail.Store(true)
	tickHung(t, b, gone, h)
	end := b.now + 10*kernel.RetryMin
	clock.Store(end)
	h.hang.Store(false)
	h.free()
	b.h.reseals.Wait()
	due := func(now int64) (n int) {
		b.h.With(func(k *kernel.Kernel) error {
			for _, r := range k.Reseals(now) {
				n++
				k.Resealed(now, r)
			}
			return nil
		})
		return n
	}
	if n := due(end + kernel.RetryMin/2); n != 0 {
		t.Fatalf("%s handed out again %dms after its slow failure", id, kernel.RetryMin/2)
	}
	if n := due(end + kernel.RetryMin); n != 1 {
		t.Fatalf("%s not handed out once its backoff from the finish ran out", id)
	}
}
