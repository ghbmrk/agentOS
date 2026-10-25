package journalowner

import (
	"context"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CH-2

type allowAll struct{}

func (allowAll) Check(context.Context, journal.Phase, journal.Intent) error { return nil }

// outcome is an executor whose every attempt ends in result.
type outcome journal.Result

func (o outcome) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.Result(o)}
}

func (o outcome) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.Result(o)}
}

// cancels leaves every attempt unknown and takes cancel requests.
type cancels struct{ outcome }

func (cancels) Cancel(context.Context, journal.Intent, int) (bool, string) { return true, "" }

// #2778: the owner channel reads the journal engine through Engine,
// with control's types, and STATUS and STOP count it as they did when
// control read journal's types: pending awaits a decision, authorized
// waits to run, unknown may have happened, settled is not counted, and
// STOP counts only the cancel requests a service takes.
func TestCountsAsStatusAndStopDid(t *testing.T) {
	ctx := context.Background()
	eng, err := journal.Open(&journal.MemStore{}, allowAll{},
		map[string]journal.Executor{"x": outcome(journal.ResultUnknown), "c": cancels{outcome(journal.ResultUnknown)}, "y": outcome(journal.ResultSucceeded)}, func(s string) string { return s })
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

	o := Engine{eng}
	want := map[string]control.Phase{"open": control.Open, "held": control.Held, "unknown": control.Unsettled,
		"cancels": control.Unsettled, "done": control.Settled}
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
	if s, w := h.Status(), "Running. 2 may have happened (send/mail, pay/mail), 1 waiting to run, 1 awaiting a decision."; s != w {
		t.Fatalf("STATUS %q, want %q", s, w)
	}
	rep, err := o.Stop(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Held) != 1 || rep.Held[0] != "held" || len(rep.Unresolved) != 2 || rep.Cancels != 1 {
		t.Fatalf("STOP report %+v", rep)
	}
	if !o.Stopped() {
		t.Fatal("not stopped after STOP")
	}
}
