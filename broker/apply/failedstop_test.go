package apply

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: OP-6
//
// A STOP that failed to record breaks the journal (Halted) without
// setting Stopped. The applier's default STOP gate reads Halted, so a
// release handed over before that STOP is not restarted into after it:
// the restart writes nothing to the journal, and would reopen a broken
// engine and clear the halt (#2463).

// failStore is the rig's journal with appends of one record type failing,
// as a full disk would: the line never lands.
type failStore struct {
	*journal.MemStore
	mu     sync.Mutex
	failOn string
}

func (s *failStore) Append(line []byte) error {
	s.mu.Lock()
	t := s.failOn
	s.mu.Unlock()
	if t != "" && strings.Contains(string(line), `"type":"`+t+`"`) {
		return errors.New("disk full")
	}
	return s.MemStore.Append(line)
}

func TestFailedStopHoldsTheRestartIntoAHandedOverRelease(t *testing.T) {
	for _, failed := range []bool{true, false} {
		r := newRig(t)
		ctx := context.Background()
		rel := r.release(1, true)
		fs := &failStore{MemStore: &journal.MemStore{}}
		var err error
		r.eng, err = journal.Open(fs, r.pol, map[string]journal.Executor{Executor: current{r}},
			func(s string) string { return s }, journal.WithClock(r.clk.now))
		r.must(err)
		// The journal's own STOP gate: Stopped is left nil.
		r.a, err = New(Config{Journal: r.eng, Activator: slowActivator{r.act, func() { r.inCall = true }},
			Store: r.store, Pipeline: r.pipe, State: r.state,
			InCall: func() bool { return r.inCall }, Working: r.isWorking,
			Excluded: func(time.Time) bool { return false },
			LastTalk: func() time.Time { return r.talk },
			Jitter:   6 * time.Hour, Rand: func(n int64) int64 { return n / 2 }, Now: r.clk.now})
		r.must(err)
		r.pol.a = r.a
		r.must(r.a.Schedule(rel, "a1"))
		if ok, err := r.a.Tick(ctx); ok || err != nil || len(r.act.installed) != 1 || r.act.restarts != 0 {
			t.Fatalf("failed=%v: not handed over and held by the call: %v %v", failed, ok, err)
		}
		if failed {
			fs.mu.Lock()
			fs.failOn = string(journal.RecStop)
			fs.mu.Unlock()
			if _, err := r.eng.Stop(ctx); !errors.Is(err, journal.ErrBroken) {
				t.Fatalf("STOP on a failing disk: %v, want ErrBroken", err)
			}
		}
		r.inCall = false
		r.a.Tick(ctx)
		switch {
		case failed && r.act.restarts != 0:
			t.Fatalf("restarted into the release after a STOP that failed to record")
		case !failed && r.act.restarts != 1:
			t.Fatalf("control: restarts %d, want 1", r.act.restarts)
		}
	}
}
