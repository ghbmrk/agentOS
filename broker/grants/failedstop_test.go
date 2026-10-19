package grants

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: OP-6

// A request carried over a restart is not asked again after a STOP that
// failed to record: the engine is halted, so the owner's answer could not
// be acted on (SEC-failed-stop-latch, #2458).
func TestOP6FailedStopAsksNothingAgain(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.invoice("agent/a", "inv-a")
	r.advance(time.Minute)

	// Restart on a journal whose next STOP fails to write.
	fs := &failStore{MemStore: r.store}
	r.own = &fakeOwner{limits: owner.Limits{AmountLimit: 50000}, now: r.now, reqs: map[string][]owner.Item{}}
	r.g = New(r.cfg)
	eng, err := journal.Open(fs, r.g, map[string]journal.Executor{"mail": r.exec, ExecutorName: r.g},
		func(s string) string { return s }, journal.WithClock(r.now))
	if err != nil {
		t.Fatal(err)
	}
	r.eng = eng
	r.g.Attach(eng, r.own)
	fs.fail(string(journal.RecStop))
	if _, err := eng.Stop(context.Background()); !errors.Is(err, journal.ErrBroken) {
		t.Fatalf("STOP on a failing disk: %v, want ErrBroken", err)
	}
	r.g.Reissue(nil)
	r.g.Tick()
	r.g.Flush()
	if n := r.own.count(); n != 0 {
		t.Fatalf("the owner was asked %d times after a failed STOP", n)
	}
}
