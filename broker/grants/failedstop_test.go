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

// A request re-issued before a STOP that failed to record, and not yet
// sent, stays held: flush's re-issue hold reads Halted, as reissueDue
// does (#2463). On a healthy engine the same request goes.
func TestOP6FailedStopHoldsAReissuedRequest(t *testing.T) {
	for _, failed := range []bool{true, false} {
		r := newRig(t, nil)
		r.grant(mailGrant())
		x := sam()
		x.Record = "inv-1"
		r.ver.set("inv-1", x)
		r.effect("agent/inv-1", "invoice.send", map[string]any{"record": "inv-1"}, "sam@example.com")
		r.g.Flush()
		asked := r.now()
		req, items := r.own.last(t)
		var boot []owner.Carried
		for _, it := range items {
			boot = append(boot, owner.Carried{Ref: it.Ref, Request: req, Asked: asked, Expires: asked.Add(15 * time.Minute), Sum: owner.ItemSum(it)})
		}

		// Restart on a journal whose next STOP fails to write; the
		// carried request is batched, not yet sent.
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
		r.g.Reissue(boot)
		if n := r.own.count(); n != 0 {
			t.Fatalf("re-issue sent %d requests before Flush; the test needs it batched", n)
		}
		if failed {
			fs.fail(string(journal.RecStop))
			if _, err := eng.Stop(context.Background()); !errors.Is(err, journal.ErrBroken) {
				t.Fatalf("STOP on a failing disk: %v, want ErrBroken", err)
			}
		}
		r.g.Flush()
		switch n := r.own.count(); {
		case failed && n != 0:
			t.Fatalf("a re-issued request went %d times after a failed STOP", n)
		case !failed && n == 0:
			t.Fatal("control: the re-issued request was not sent on a healthy engine")
		}
	}
}
