package recalltool

// REQ: CAP-3

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// newRenewRig: newReachRig with the read cap at 2, so "root" (two reads)
// is full and "bystander" (one) is not.
func newRenewRig(t *testing.T) *reachRig {
	t.Helper()
	x, _ := newReachRig(t)
	x.r.prov.SetLimits(Limits{Reads: 2, Notes: 2})
	return x
}

func full(r *Reach, lineage string) bool {
	for _, l := range r.Full() {
		if l == lineage {
			return true
		}
	}
	return false
}

func renewAsks(x *reachRig) []journal.Status {
	var out []journal.Status
	for _, st := range x.ask.st {
		if renew, _ := st.Intent.Params["renew"].(bool); renew {
			out = append(out, st)
		}
	}
	return out
}

func TestRecallProvOwnerFullListsOnlyFullLineages(t *testing.T) {
	x := newRenewRig(t)
	if got := x.reach.Full(); len(got) != 1 || got[0] != "root" {
		t.Fatalf("Full() = %v, want [root]", got)
	}
	if AgentName("root.3fa9") != "root" || AgentName("root") != "root" {
		t.Fatalf("AgentName: %q %q", AgentName("root.3fa9"), AgentName("root"))
	}
}

func TestRecallProvOwnerAskRenewRefusesALineageNotFull(t *testing.T) {
	x := newRenewRig(t)
	for _, l := range []string{"bystander", "guest-made-up", ""} {
		if err := x.reach.AskRenew(context.Background(), l); !errors.Is(err, ErrNotFull) {
			t.Fatalf("AskRenew(%q) = %v, want ErrNotFull", l, err)
		}
	}
	if len(x.ask.st) != 0 || len(x.ask.asked) != 0 {
		t.Fatalf("asked %v for a lineage not full", x.ask.asked)
	}
}

func TestRecallProvOwnerAskNamesTheRenewalAndItsCost(t *testing.T) {
	x := newRenewRig(t)
	if err := x.reach.AskRenew(context.Background(), "root"); err != nil {
		t.Fatal(err)
	}
	asks := renewAsks(x)
	if len(asks) != 1 || len(x.ask.asked) != 1 {
		t.Fatalf("asks %d, authorized %v; want one", len(asks), x.ask.asked)
	}
	in := asks[0].Intent
	if in.Origin != Origin || in.Executor != ExecutorName || in.Action != journal.ActionRecallRollback || in.Account != journal.BrokerAccount {
		t.Fatalf("intent %+v", in)
	}
	obj, _ := in.Params["object"].(string)
	detail, _ := in.Params["detail"].(string)
	if !strings.Contains(obj, "root") || !strings.Contains(obj, "renew") || len(obj) > fieldCap {
		t.Fatalf("object %q", obj)
	}
	if !strings.Contains(detail, "back to 12:20 Oct 5") || !strings.Contains(detail, "lost") || len(detail) > fieldCap {
		t.Fatalf("detail %q", detail)
	}
	if len(x.vm.calls) != 0 || !full(x.reach, "root") {
		t.Fatalf("asking changed something: machines %v", x.vm.calls)
	}
}

func TestRecallProvOwnerAskStatesTheCostWhateverTheRestorePoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(x *reachRig)
	}{
		{"unknown", func(x *reachRig) { x.vm.planErr = errors.New("no plan") }},
		{"fresh start", func(x *reachRig) { x.vm.plan.To = time.Time{} }},
		{"two-digit day", func(x *reachRig) {
			x.vm.plan.To = time.Date(2026, 10, 15, 12, 20, 0, 0, time.UTC)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newRenewRig(t)
			tc.set(x)
			if err := x.reach.AskRenew(context.Background(), "root"); err != nil {
				t.Fatal(err)
			}
			d, _ := renewAsks(x)[0].Intent.Params["detail"].(string)
			if !strings.Contains(d, "lost") || len(d) > fieldCap {
				t.Fatalf("detail %q", d)
			}
		})
	}
	x := newRenewRig(t)
	if obj, _ := x.reach.renewLine("an-agent-with-a-very-long-root-name", Plan{}, true); len(obj) > fieldCap || !strings.Contains(obj, "renew") {
		t.Fatalf("long name object %q", obj)
	}
}

func TestRecallProvOwnerNoLeavesReadsAndMachines(t *testing.T) {
	x := newRenewRig(t)
	if err := x.reach.AskRenew(context.Background(), "root"); err != nil {
		t.Fatal(err)
	}
	x.ask.answer("no")
	if len(x.vm.calls) != 0 || !full(x.reach, "root") {
		t.Fatalf("NO: machines %v, full %v", x.vm.calls, x.reach.Full())
	}
	x.ask.answer("expired")
	if len(x.vm.calls) != 0 || !full(x.reach, "root") {
		t.Fatalf("no answer: machines %v", x.vm.calls)
	}
}

func TestRecallProvOwnerGuestRenewIsRefused(t *testing.T) {
	x := newRenewRig(t)
	first, _ := x.reach.Prov.firstRead("root")
	in := journal.Intent{ID: "guest-renew", Origin: "guest:root", Account: journal.BrokerAccount,
		Action: journal.ActionRecallRollback, Executor: ExecutorName,
		Params: map[string]any{"lineage": "root", "since": first.Format(time.RFC3339Nano), "renew": true,
			"object": "root's reads to renew its memory", "detail": "x"}}
	for _, bad := range []func(journal.Intent) journal.Intent{
		func(in journal.Intent) journal.Intent { return in },
		func(in journal.Intent) journal.Intent { in.Origin = Origin; in.Account = "mail"; return in },
		func(in journal.Intent) journal.Intent { in.Origin = Origin; in.Action = "meta.grant"; return in },
		func(in journal.Intent) journal.Intent { in.Origin = Origin; in.Params["since"] = "x"; return in },
	} {
		if out := x.reach.Execute(context.Background(), bad(in), 1); out.Result != journal.ResultNotApplied {
			t.Fatalf("Execute(%+v) = %+v", in, out)
		}
	}
	if len(x.vm.calls) != 0 || !full(x.reach, "root") || len(x.told) != 0 {
		t.Fatalf("guest renew changed something: machines %v told %v", x.vm.calls, x.told)
	}
}

func TestRecallProvOwnerYesRenews(t *testing.T) {
	x := newRenewRig(t)
	first, _ := x.reach.Prov.firstRead("root")
	if err := x.reach.AskRenew(context.Background(), "root"); err != nil {
		t.Fatal(err)
	}
	x.ask.answer("yes")
	if len(x.vm.calls) != 1 || x.vm.calls[0] != "root" || !x.vm.since[0].Equal(first) {
		t.Fatalf("machines %v since %v, want root from %v", x.vm.calls, x.vm.since, first)
	}
	if full(x.reach, "root") {
		t.Fatalf("after YES Full() = %v", x.reach.Full())
	}
	if n, _, _ := x.r.prov.Size("root"); n != 0 {
		t.Fatalf("root still holds %d reads", n)
	}
	if len(x.told) != 1 || !strings.HasPrefix(x.told[0], "Done: root's memory starts over") {
		t.Fatalf("told %q", x.told)
	}
	for _, st := range renewAsks(x) {
		if st.State != journal.Succeeded {
			t.Fatalf("renew intent %v", st.State)
		}
	}
	// An approval of a second ask made before the first ran is stale: it
	// changes nothing more.
	x.ask.st["second"] = journal.Status{Intent: renewAsks(x)[0].Intent, State: journal.Pending}
	x.ask.answer("yes")
	if len(x.vm.calls) != 1 {
		t.Fatalf("stale YES reset again: %v", x.vm.calls)
	}
}

// A YES that arrives after the lineage stopped being full (the cap was
// raised between the ask and the answer) changes nothing and says so.
func TestRecallProvOwnerYesOnALineageNoLongerFullIsStale(t *testing.T) {
	x := newRenewRig(t)
	if err := x.reach.AskRenew(context.Background(), "root"); err != nil {
		t.Fatal(err)
	}
	x.r.prov.SetLimits(Limits{Reads: 5})
	if full(x.reach, "root") {
		t.Fatalf("root still full after raising the cap: %v", x.reach.Full())
	}
	x.ask.answer("yes")
	if len(x.vm.calls) != 0 {
		t.Fatalf("outdated YES touched machines: %v", x.vm.calls)
	}
	if n, _, _ := x.r.prov.Size("root"); n != 2 {
		t.Fatalf("outdated YES changed reads: root holds %d", n)
	}
	if len(x.told) != 1 || x.told[0] != "Nothing to do: root's memory is no longer full." {
		t.Fatalf("told %q", x.told)
	}
}

func TestRecallProvOwnerYesWhenTheResetFailsIsCarried(t *testing.T) {
	x := newRenewRig(t)
	if err := x.reach.AskRenew(context.Background(), "root"); err != nil {
		t.Fatal(err)
	}
	x.vm.fail = errors.New("vm down")
	x.ask.answer("yes")
	st := renewAsks(x)[0]
	if st.State != journal.Succeeded || !strings.HasPrefix(st.Attempts[0].Evidence, approvedOnly) {
		t.Fatalf("carried renew: %v %q", st.State, st.Attempts[0].Evidence)
	}
	if len(x.told) != 1 || !strings.Contains(x.told[0], "keep trying") {
		t.Fatalf("told %q", x.told)
	}
	x.vm.fail = nil
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x.vm.calls) != 1 || full(x.reach, "root") {
		t.Fatalf("Retry did not carry the renew: machines %v full %v", x.vm.calls, x.reach.Full())
	}
}

func TestRecallProvOwnerLateExecutorBeforeOpen(t *testing.T) {
	var l LateExecutor
	if l.Full() != nil {
		t.Fatal("Full before open")
	}
	if err := l.AskRenew(context.Background(), "root"); !errors.Is(err, ErrNotOpen) {
		t.Fatalf("AskRenew before open = %v", err)
	}
	in := journal.Intent{ID: "r", Origin: Origin, Account: journal.BrokerAccount, Action: journal.ActionRecallRollback,
		Executor: ExecutorName, Params: map[string]any{"lineage": "root", "since": time.Now().UTC().Format(time.RFC3339Nano), "renew": true}}
	if out := l.Execute(context.Background(), in, 1); out.Result != journal.ResultNotApplied {
		t.Fatalf("renew before open = %+v", out)
	}
	x := newRenewRig(t)
	l.Set(x.reach)
	if got := l.Full(); len(got) != 1 || got[0] != "root" {
		t.Fatalf("Full after open = %v", got)
	}
}
