package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue"
)

// savesStore counts the saves that reach it.
type savesStore struct {
	change.MemStore
	saves int
}

func (s *savesStore) Save(b []byte) error {
	s.saves++
	return s.MemStore.Save(b)
}

// readyNotes leaves a Ready batch holding owner:a in r's queue: its one
// attempt is not sent, so the next step would send it.
func readyNotes(t *testing.T, queue digestqueue.Store) (*digestRig, map[string]digestqueue.Source, string) {
	t.Helper()
	line := "Notes: task 3 finished; reply MORE 3 for it."
	src := &testSource{name: "notes", gen: 1, lines: []string{line}, refs: []string{"owner:a"}}
	srcs := map[string]digestqueue.Source{"notes": src}
	r := newDigestRig(t, queue, srcs)
	r.tr.out = func(int) (digestqueue.Outcome, string) { return digestqueue.NotSent, "not-queued" }
	r.at(0, 8, 0)
	r.tr.out = nil
	if r.holding("owner:a") != 1 {
		t.Fatal("no ready batch holds owner:a")
	}
	return r, srcs, line
}

func tombstone(t *testing.T, store change.Store, goals ...string) *forgotten {
	t.Helper()
	f, err := openForgotten(store, func() time.Time { return day0 })
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range goals {
		if err := f.add(g); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (r *digestRig) sentSince(n int, line string) bool {
	for _, s := range r.tr.sent()[n:] {
		if strings.Contains(s, line) {
			return true
		}
	}
	return false
}

// Security 6080263349 pt 1 and L3 6080272656 pt 2 on #592: the owed save
// fails and the process stops after the tombstone, before the digest's
// purge. Neither the owed file nor the digest's hold names the goal after
// the restart; the tombstone does, so the digest's open replays it.
// REQ: CAP-3 (W5-Dc-r12 DF-1)
func TestDigestForgetCrashAfterTombstoneSendsNothing(t *testing.T) {
	r, srcs, line := readyNotes(t, &change.MemStore{})
	tombStore := &change.MemStore{}
	tomb := tombstone(t, tombStore)
	owed := failSave{&change.MemStore{}}
	was := restartRig(t, owed)
	was.f.wireDigest(r.d, tomb.goals)
	was.f.forget = func(g string) error {
		if err := tomb.add(g); err != nil {
			return err
		}
		runtime.Goexit() // the process stops here
		return nil
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		was.f.Execute(context.Background(), forgetIntent(fmt.Sprintf("1.1.%d", day0.UnixNano()), "owner:a"), 1)
	}()
	<-stopped
	if !tomb.has("owner:a") || r.d.forgets["owner:a"] {
		t.Fatal("not the double fault: no tombstone, or the digest holds the goal")
	}

	// Restart, in main's order: the box is made, learning opens and
	// replays its stores, the forget owner attaches, then the digest runs.
	n := len(r.tr.sent())
	r.make(srcs)
	again := restart(t, owed, nil)
	tomb = tombstone(t, tombStore)
	again.f.forgotten = tomb.has
	again.f.wireDigest(r.d, tomb.goals)
	again.f.finishOwed(context.Background())
	r.at(0, 9, 0)
	r.day(0)
	r.day(1)
	if r.sentSince(n, line) {
		t.Fatalf("forgotten reference sent after the restart: %q", r.tr.sent()[n:])
	}
	if r.holding("owner:a") != 0 {
		t.Fatal("a batch still holds the forgotten reference")
	}
}

// A replay the queue refuses (its store refuses the purge) leaves the box
// down, so nothing is sent; the next step opens again and the replay holds.
// REQ: CAP-3 (W5-Dc-r12 DF-2)
func TestDigestTombstoneReplayRefusedKeepsTheQueueClosed(t *testing.T) {
	r, srcs, line := readyNotes(t, &keepRefStore{ref: "owner:a", refuse: 1})
	tomb := tombstone(t, &change.MemStore{}, "owner:a")
	n := len(r.tr.sent())
	r.make(srcs)
	r.d.cfg.Forgotten = tomb.goals
	r.d.open(context.Background())
	if r.d.q != nil || !r.d.down.Load() {
		t.Fatal("open succeeded with a tombstoned reference the queue still holds")
	}
	r.at(0, 9, 0)
	if r.d.q == nil {
		t.Fatal("the next step did not open the queue")
	}
	r.day(0)
	if r.sentSince(n, line) {
		t.Fatalf("forgotten reference sent: %q", r.tr.sent()[n:])
	}
	if r.holding("owner:a") != 0 {
		t.Fatal("a batch still holds the forgotten reference")
	}
}

// The replay writes only when a batch holds a tombstoned goal; a goal the
// queue cannot hold as a reference is skipped and does not fail the open.
// REQ: CAP-3 (W5-Dc-r12 DF-3)
func TestDigestTombstoneReplayWritesNothingWithoutAMatch(t *testing.T) {
	queue := &savesStore{}
	r, srcs, _ := readyNotes(t, queue)
	state := &savesStore{}
	if b, _ := r.state.Load(); b != nil {
		_ = state.MemStore.Save(b) // not counted
	}
	r.state = state
	tomb := tombstone(t, &change.MemStore{}, "owner:b", "not a reference")
	// open's own recovery may write; the replay must add nothing to it.
	opened := func(forgotten func() []string) (int, int) {
		r.make(srcs)
		r.d.cfg.Forgotten = forgotten
		qn, sn := queue.saves, state.saves
		r.d.open(context.Background())
		if r.d.q == nil {
			t.Fatal("open failed on a goal no batch holds")
		}
		return queue.saves - qn, state.saves - sn
	}
	q0, s0 := opened(nil)
	q1, s1 := opened(tomb.goals)
	if q1 != q0 || s1 != s0 {
		t.Fatalf("replay with no match wrote: queue %d state %d saves, %d %d without it", q1, s1, q0, s0)
	}
	if r.holding("owner:a") != 1 {
		t.Fatal("replay touched a batch it does not hold")
	}
}

// L3 6083352871 on #612: once the queue's forget holds, a held reference
// leaves the box's forgets and its state store.
// REQ: CAP-3 (W5-Dc-r12 HF-1)
func TestDigestHeldForgetIsDroppedOnceItHolds(t *testing.T) {
	r := newDigestRig(t, &change.MemStore{}, nil)
	r.d.mu.Lock()
	r.d.hold("owner:a")
	if err := r.d.keepForgets(); err != nil {
		r.d.mu.Unlock()
		t.Fatal(err)
	}
	r.d.mu.Unlock()
	if b, _ := r.state.Load(); !strings.Contains(string(b), "owner:a") {
		t.Fatal("hold not saved")
	}
	if err := r.d.forget("owner:a"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if len(r.d.forgets) != 0 || len(r.d.st.Forgets) != 0 {
		t.Fatalf("hold kept: %v %v", r.d.forgets, r.d.st.Forgets)
	}
	if b, _ := r.state.Load(); strings.Contains(string(b), "owner:a") {
		t.Fatalf("hold still saved: %s", b)
	}
	r.boot(nil)
	if len(r.d.forgets) != 0 {
		t.Fatalf("hold back after a restart: %v", r.d.forgets)
	}
}
