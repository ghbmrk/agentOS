package journalowner

import (
	"context"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CH-2

// allowAll allows every intent but the action "deny".
type allowAll struct{}

func (allowAll) Check(_ context.Context, _ journal.Phase, in journal.Intent) error {
	if in.Action == "deny" {
		return errors.New("denied")
	}
	return nil
}

// outcome is an executor whose every attempt ends in result.
type outcome journal.Result

func (o outcome) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.Result(o)}
}

func (o outcome) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.Result(o)}
}

// blocks holds its attempt open until release closes, so the intent stays
// in flight.
type blocks struct{ started, release chan struct{} }

func (b blocks) Execute(context.Context, journal.Intent, int) journal.Outcome {
	close(b.started)
	<-b.release
	return journal.Outcome{Result: journal.ResultSucceeded}
}

func (b blocks) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultUnknown}
}

// cancels leaves every attempt unknown and takes cancel requests.
type cancels struct{ outcome }

func (cancels) Cancel(context.Context, journal.Intent, int) (bool, string) { return true, "" }

// #2778: the owner channel reads the journal engine through Engine,
// with control's types, and STATUS and STOP count it as they did when
// control read journal's types: pending awaits a decision, authorized
// or proved not done waits to run, in flight or unknown may have
// happened, succeeded or denied is not counted, and STOP counts only the
// cancel requests a service takes. One intent sits in each journal state
// (#3095), so dropping a state from a case fails the test.
func TestCountsAsStatusAndStopDid(t *testing.T) {
	ctx := context.Background()
	f := blocks{make(chan struct{}), make(chan struct{})}
	eng, err := journal.Open(&journal.MemStore{}, allowAll{},
		map[string]journal.Executor{"x": outcome(journal.ResultUnknown), "c": cancels{outcome(journal.ResultUnknown)}, "y": outcome(journal.ResultSucceeded),
			"f": f, "n": outcome(journal.ResultNotApplied)}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	put := func(id, action, exec string, authorize, dispatch bool) {
		t.Helper()
		in := journal.Intent{ID: id, Origin: "guest:agent", Account: "mail", Action: action, Executor: exec}
		if _, err := eng.Submit(in); err != nil {
			t.Fatal(err)
		}
		if authorize {
			if _, err := eng.Authorize(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
		if dispatch {
			if _, err := eng.Dispatch(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	put("open", "ask", "y", false, false)
	put("held", "post", "y", true, false)
	put("unknown", "send", "x", true, true)
	put("cancels", "pay", "c", true, true)
	put("done", "draft", "y", true, true)
	put("inflight", "move", "f", true, false)
	done := make(chan struct{})
	go func() { defer close(done); eng.Dispatch(ctx, "inflight") }()
	<-f.started
	t.Cleanup(func() { close(f.release); <-done })
	put("notapplied", "file", "n", true, true)
	if _, err := eng.Submit(journal.Intent{ID: "denied", Origin: "guest:agent", Account: "mail", Action: "deny", Executor: "y"}); err != nil {
		t.Fatal(err)
	}
	// A policy refusal is journaled as denied, not returned as an error;
	// the state check below proves it landed in Denied.
	if _, err := eng.Authorize(ctx, "denied"); err != nil {
		t.Fatal(err)
	}
	states := map[journal.State]bool{}
	for _, s := range eng.List() {
		states[s.State] = true
	}
	for _, st := range []journal.State{journal.Pending, journal.Authorized, journal.Denied, journal.InFlight,
		journal.OutcomeUnknown, journal.Succeeded, journal.NotApplied} {
		if !states[st] {
			t.Fatalf("no intent in state %s: %v", st, states)
		}
	}

	o := Engine{eng}
	want := map[string]control.Phase{"open": control.Open, "held": control.Held, "unknown": control.Unsettled,
		"cancels": control.Unsettled, "done": control.Settled, "inflight": control.Unsettled,
		"notapplied": control.Held, "denied": control.Settled}
	got := map[string]control.Phase{}
	for _, s := range o.List() {
		if s.Account != "mail" || s.Action == "" {
			t.Fatalf("%+v: account or action lost", s)
		}
		got[s.ID] = s.Phase
	}
	if len(got) != len(want) {
		t.Fatalf("listed %v, want %v", got, want)
	}
	for id, ph := range want {
		if got[id] != ph {
			t.Fatalf("%s: phase %d, want %d", id, got[id], ph)
		}
	}

	h := &control.Handler{Engine: o}
	if s, w := h.Status(), "Running. 3 may have happened (send/mail, pay/mail, move/mail), 2 waiting to run, 1 awaiting a decision."; s != w {
		t.Fatalf("STATUS %q, want %q", s, w)
	}
	rep, err := o.Stop(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Held) != 2 || len(rep.Unresolved) != 3 || rep.Cancels != 1 {
		t.Fatalf("STOP report %+v", rep)
	}
	if !o.Stopped() {
		t.Fatal("not stopped after STOP")
	}
}
