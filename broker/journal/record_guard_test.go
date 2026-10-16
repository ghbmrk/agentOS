package journal

// REQ: OP-2, OP-7
//
// Guards on the cancel_requested and quality records (OP-journal-record-
// guards, #1927). Each record type has a table of (state, record) pairs:
// a legal pair commits live and replays to the same status; an illegal
// pair is refused live and, written straight into a journal, makes Open
// fail closed (ErrCorrupt), so live and replay agree.

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// guardCase builds an engine with intent "a" in one state.
type guardCase struct {
	name  string
	state State
	build func(t *testing.T) (*Engine, *MemStore, *fakeService)
}

func guardCases() []guardCase {
	open := func(t *testing.T, svc *fakeService, p *testPolicy) (*Engine, *MemStore) {
		st := &MemStore{}
		e := mustOpen(t, st, p, svc)
		must(e.Submit(intent("a", "acct")))
		return e, st
	}
	dispatched := func(mode execMode) func(t *testing.T) (*Engine, *MemStore, *fakeService) {
		return func(t *testing.T) (*Engine, *MemStore, *fakeService) {
			svc := newService()
			svc.mode = func(string) execMode { return mode }
			e, st := open(t, svc, newPolicy())
			must(e.Authorize(ctx, "a"))
			must(e.Dispatch(ctx, "a"))
			return e, st, svc
		}
	}
	return []guardCase{
		{"pending", Pending, func(t *testing.T) (*Engine, *MemStore, *fakeService) {
			svc := newService()
			e, st := open(t, svc, newPolicy())
			return e, st, svc
		}},
		{"authorized", Authorized, func(t *testing.T) (*Engine, *MemStore, *fakeService) {
			svc := newService()
			e, st := open(t, svc, newPolicy())
			must(e.Authorize(ctx, "a"))
			return e, st, svc
		}},
		{"denied", Denied, func(t *testing.T) (*Engine, *MemStore, *fakeService) {
			svc, p := newService(), newPolicy()
			p.revoke("a", true)
			e, st := open(t, svc, p)
			must(e.Authorize(ctx, "a"))
			return e, st, svc
		}},
		{"denied at recheck", Denied, func(t *testing.T) (*Engine, *MemStore, *fakeService) {
			svc, p := newService(), newPolicy()
			e, st := open(t, svc, p)
			must(e.Authorize(ctx, "a"))
			p.revoke("a", true)
			e.Dispatch(ctx, "a")
			return e, st, svc
		}},
		{"outcome unknown", OutcomeUnknown, dispatched(modeTimeout)},
		{"succeeded", Succeeded, dispatched(modeOK)},
		{"not applied", NotApplied, dispatched(modeRefuse)},
	}
}

// commitLocked commits r as the engine itself would.
func commitLocked(e *Engine, r Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.commit(r)
}

// appendRaw writes r into the journal behind the engine's back, as an
// older or faulty binary might have.
func appendRaw(t *testing.T, e *Engine, st *MemStore, r Record) {
	t.Helper()
	r.V, r.Seq, r.At = recordVersion, e.seq+1, e.newest
	line, err := encodeRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(line); err != nil {
		t.Fatal(err)
	}
}

func reopen(st *MemStore, svc Executor) (*Engine, error) {
	return Open(st, newPolicy(), map[string]Executor{"svc": svc}, testRedact)
}

// checkReplay reopens the journal and requires the status of "a" to match
// the live one.
func checkReplay(t *testing.T, e *Engine, st *MemStore, svc Executor) {
	t.Helper()
	live := must(e.Get("a"))
	e2, err := reopen(st, svc)
	if err != nil {
		t.Fatalf("replay of a legal journal: %v", err)
	}
	if got := must(e2.Get("a")); !reflect.DeepEqual(got, live) {
		t.Fatalf("replayed status differs:\n got %+v\nwant %+v", got, live)
	}
}

// Quality is recorded apart from permission and execution (OP-7): it is
// legal from every state, never changes the state, and replays to the
// same status. A malformed verdict is refused live and on replay.
func TestOP7QualityRecordGuard(t *testing.T) {
	for _, c := range guardCases() {
		t.Run(c.name, func(t *testing.T) {
			e, st, svc := c.build(t)
			if s := must(e.Get("a")).State; s != c.state {
				t.Fatalf("setup: state %s, want %s", s, c.state)
			}
			if _, err := e.RecordQuality("a", Quality{Verdict: "maybe", Source: "owner"}); err == nil {
				t.Fatalf("verdict %q from %s accepted", "maybe", c.state)
			}
			checkReplay(t, e, st, svc) // the refusal journaled nothing
			q := Quality{Verdict: VerdictWrong, Source: "owner", Note: "n"}
			if _, err := e.RecordQuality("a", q); err != nil {
				t.Fatalf("quality from %s refused: %v", c.state, err)
			}
			if got := must(e.Get("a")); got.Quality != q || got.State != c.state {
				t.Fatalf("quality %+v state %s, want %+v and %s unchanged (OP-7)", got.Quality, got.State, q, c.state)
			}
			checkReplay(t, e, st, svc)
			appendRaw(t, e, st, Record{Type: RecQuality, ID: "a", Verdict: "maybe", Source: "owner"})
			if _, err := reopen(st, svc); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("replay of verdict %q from %s: err = %v, want ErrCorrupt", "maybe", c.state, err)
			}
		})
	}
}

// A quality record during an attempt in flight is legal: the owner's
// verdict on a delivered result can race the executor's acknowledgment.
func TestOP7QualityWhileInFlight(t *testing.T) {
	st, svc := &MemStore{}, newService()
	e := mustOpen(t, st, newPolicy(), svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	var qerr error
	svc.onExecute = func(Intent, int) {
		if s := must(e.Get("a")).State; s != InFlight {
			t.Errorf("state during execute = %s", s)
		}
		_, qerr = e.RecordQuality("a", Quality{Verdict: VerdictGood, Source: "owner"})
	}
	must(e.Dispatch(ctx, "a"))
	if qerr != nil {
		t.Fatalf("quality while in flight: %v", qerr)
	}
	checkReplay(t, e, st, svc)
}

// A cancel_requested record is legal only for an attempt that was in
// flight or unknown when a STOP was recorded: Stop is its only writer.
func TestOP2CancelRecordGuard(t *testing.T) {
	for _, c := range guardCases() {
		t.Run(c.name, func(t *testing.T) {
			e, st, svc := c.build(t)
			cancel := Record{Type: RecCancel, ID: "a", Attempt: 1, Accepted: false, Evidence: "cancel requested"}
			// Without a STOP no pair is legal, whatever the state.
			if err := commitLocked(e, cancel); !errors.Is(err, ErrState) {
				t.Fatalf("cancel without STOP from %s: err = %v, want ErrState", c.state, err)
			}
			checkReplay(t, e, st, svc)
			rep, err := e.Stop(ctx)
			if err != nil {
				t.Fatal(err)
			}
			outstanding := c.state == OutcomeUnknown
			if got := len(rep.Cancels) == 1; got != outstanding {
				t.Fatalf("stop from %s cancelled %d attempts", c.state, len(rep.Cancels))
			}
			if outstanding {
				if a := must(e.Get("a")).Attempts[0]; len(a.Cancels) != 1 {
					t.Fatalf("cancels = %+v", a.Cancels)
				}
				// The attempt was outstanding at a STOP: a later cancel
				// of it stays legal.
				if err := commitLocked(e, cancel); err != nil {
					t.Fatalf("second cancel: %v", err)
				}
				checkReplay(t, e, st, svc)
				return
			}
			// After the STOP the attempt (or its absence) was settled:
			// still refused live and on replay.
			if err := commitLocked(e, cancel); !errors.Is(err, ErrState) {
				t.Fatalf("cancel after STOP from %s: err = %v, want ErrState", c.state, err)
			}
			checkReplay(t, e, st, svc)
			appendRaw(t, e, st, cancel)
			if _, err := reopen(st, svc); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("replay of cancel from %s: err = %v, want ErrCorrupt", c.state, err)
			}
		})
	}
}

// settleOnCancel settles the attempt it is asked to cancel before
// answering, as a service that finishes while STOP is running would.
type settleOnCancel struct {
	*fakeService
	settle func(in Intent, attempt int)
}

func (s settleOnCancel) Cancel(ctx context.Context, in Intent, attempt int) (bool, string) {
	s.settle(in, attempt)
	return s.fakeService.Cancel(ctx, in, attempt)
}

// Stop commits each cancel after the lock was released, so the attempt
// can settle, or STOP be lifted, in between. The guard rests on what was
// outstanding at the STOP record, so these cancels still commit, and
// replay accepts them.
func TestOP2CancelAfterAttemptSettles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		settle func(e *Engine, in Intent, n int)
	}{
		{"settled", func(e *Engine, in Intent, n int) {
			must(e.Resolve(in.ID, n, Outcome{Result: ResultSucceeded, Evidence: "found"}, "owner"))
		}},
		{"settled and resumed", func(e *Engine, in Intent, n int) {
			must(e.Resolve(in.ID, n, Outcome{Result: ResultNotApplied, Evidence: "none"}, "owner"))
			if err := e.Resume(); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, svc := &MemStore{}, newService()
			svc.mode = func(string) execMode { return modeTimeout }
			var e *Engine
			ex := settleOnCancel{svc, func(in Intent, n int) { tc.settle(e, in, n) }}
			e = mustOpen(t, st, newPolicy(), ex)
			must(e.Submit(intent("a", "acct")))
			must(e.Authorize(ctx, "a"))
			must(e.Dispatch(ctx, "a"))
			rep, err := e.Stop(ctx)
			if err != nil {
				t.Fatalf("stop: %v", err)
			}
			if len(rep.Cancels) != 1 {
				t.Fatalf("cancels = %+v", rep.Cancels)
			}
			a := must(e.Get("a")).Attempts[0]
			if a.Result == ResultUnknown || len(a.Cancels) != 1 {
				t.Fatalf("attempt = %+v, want settled with one cancel", a)
			}
			checkReplay(t, e, st, ex)
		})
	}
}

// A narrowing intent may dispatch while stopped; its attempt was not
// outstanding at the STOP, so a cancel of it is refused.
func TestOP2CancelOfAttemptAfterStop(t *testing.T) {
	st, svc := &MemStore{}, newService()
	svc.mode = func(string) execMode { return modeTimeout }
	e := mustOpen(t, st, newPolicy(), svc)
	in := intent("a", "broker")
	in.Action = "meta.grant.revoke"
	must(e.Submit(in))
	must(e.Stop(ctx))
	must(e.Authorize(ctx, "a"))
	must(e.Dispatch(ctx, "a"))
	if s := must(e.Get("a")).State; s != OutcomeUnknown {
		t.Fatalf("state = %s", s)
	}
	if err := commitLocked(e, Record{Type: RecCancel, ID: "a", Attempt: 1}); !errors.Is(err, ErrState) {
		t.Fatalf("cancel of an attempt dispatched after STOP: err = %v, want ErrState", err)
	}
	// A second STOP sees it outstanding.
	rep := must(e.Stop(ctx))
	if len(rep.Cancels) != 1 {
		t.Fatalf("second stop cancels = %+v", rep.Cancels)
	}
	checkReplay(t, e, st, svc)
}
