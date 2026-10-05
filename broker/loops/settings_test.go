package loops

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: LOOP-0, LOOP-2, LOOP-6, OP-5
//
// Loop settings: on by default, changed by the owner's text as journaled
// broker-state intents, and never by a loop, the pipeline, or a guest.

func TestLoopsAreOnByDefaultAndSaidInOneLine(t *testing.T) {
	r := newRig(t)
	set := r.s.Settings()
	for _, l := range All {
		if !set.On(l) {
			t.Fatalf("loop %s is off by default", l)
		}
	}
	if set.SpareCalls != DefaultSpareCalls {
		t.Fatalf("default spare budget %d", set.SpareCalls)
	}
	if _, limit := r.spare.Overall(); limit != SpareLimits(DefaultSpareCalls) {
		t.Fatalf("spare meter cap %+v, want the default budget", limit)
	}
	line := DefaultsLine(set.SpareCalls)
	if strings.Count(line, ".") != 1 || !strings.Contains(line, "LOOPS OFF") || !strings.Contains(line, "100 AI calls a day") {
		t.Fatalf("defaults line %q", line)
	}
}

func TestParseTextTakesWholeMessagesOnly(t *testing.T) {
	cases := []struct {
		msg  string
		ok   bool
		want Request
	}{
		{"loops off", true, Request{Kind: KindLoops}},
		{"Loops on!", true, Request{Kind: KindLoops, On: true}},
		{"LOOP 2 OFF", true, Request{Kind: KindLoops, Loop: Secure}},
		{"loop 3 on.", true, Request{Kind: KindLoops, Loop: Maintain, On: true}},
		{"spare budget 40", true, Request{Kind: KindBudget, Calls: 40}},
		{"stop sharing", true, Request{Kind: KindSharing}},
		{"START SHARING", true, Request{Kind: KindSharing, On: true}},
		{"loop 4 off", false, Request{}},
		{"loop 02 off", false, Request{}},
		{"spare budget 999999", false, Request{}},
		{"spare budget -3", true, Request{Kind: KindBudget, Calls: 3}}, // punctuation is ignored (CH-11)
		{"turn the loops off please", false, Request{}},
		{"loops off and book a table", false, Request{}},
	}
	for _, c := range cases {
		got, ok := ParseText(c.msg)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseText(%q) = %+v, %v; want %+v, %v", c.msg, got, ok, c.want, c.ok)
		}
	}
}

func TestOwnerTextChangesSettingsThroughTheJournal(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	req, _ := ParseText("LOOP 2 OFF")
	must(t, r.s.Set(ctx, req))
	set := r.s.Settings()
	if set.On(Secure) || !set.On(Improve) || !set.On(Maintain) {
		t.Fatalf("after LOOP 2 OFF: %+v", set)
	}
	req, _ = ParseText("LOOPS OFF")
	must(t, r.s.Set(ctx, req))
	if r.s.Settings().On(Improve) {
		t.Fatal("LOOPS OFF left loop 1 on")
	}
	req, _ = ParseText("LOOPS ON")
	must(t, r.s.Set(ctx, req))
	for _, l := range All {
		if !r.s.Settings().On(l) {
			t.Fatalf("LOOPS ON left %s off", l)
		}
	}
	// Every change is a journaled broker-state intent (OP-5).
	n := 0
	for _, s := range r.eng.List() {
		if s.Intent.Executor == Executor && s.State == journal.Succeeded {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("%d journaled settings, want 3", n)
	}
	// Settings survive a restart.
	req, _ = ParseText("LOOP 1 OFF")
	must(t, r.s.Set(ctx, req))
	r.restart()
	if r.s.Settings().On(Improve) {
		t.Fatal("LOOP 1 OFF lost on restart")
	}
	if !strings.Contains(strings.Join(r.s.Digest(), "\n"), "Loop 1 (learning from your tasks) is off. Reply LOOP 1 ON") {
		t.Fatalf("digest does not say loop 1 is off: %q", r.s.Digest())
	}
}

func TestLoopsOffWorksDuringStop(t *testing.T) {
	r := newRig(t)
	if _, err := r.eng.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	req, _ := ParseText("loops off")
	must(t, r.s.Set(context.Background(), req))
	if !r.s.Settings().Off {
		t.Fatal("LOOPS OFF did not apply during STOP")
	}
	req, _ = ParseText("loops on")
	if err := r.s.Set(context.Background(), req); err == nil || r.s.Settings().On(Improve) {
		t.Fatal("LOOPS ON applied during STOP")
	}
}

func TestSpareBudgetLowersOnTextAndRaisesOnlyWithApproval(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	req, _ := ParseText("SPARE BUDGET 20")
	must(t, r.s.Set(ctx, req))
	if _, limit := r.spare.Overall(); limit != SpareLimits(20) {
		t.Fatalf("lowered budget not applied to the spare meter: %+v", limit)
	}
	if asked := r.pol.wasAsked(); len(asked) != 0 {
		t.Fatalf("lowering the budget asked the owner: %v", asked)
	}
	// A raise spends the owner's quota: a text alone is not enough.
	req, _ = ParseText("SPARE BUDGET 400")
	if err := r.s.Set(ctx, req); err == nil {
		t.Fatal("raise applied without the owner's approval")
	}
	if r.s.Settings().SpareCalls != 20 || len(r.pol.wasAsked()) != 1 {
		t.Fatalf("raise without approval: settings %+v, asked %v", r.s.Settings(), r.pol.wasAsked())
	}
	r.pol.approve = true
	must(t, r.s.Set(ctx, req))
	if _, limit := r.spare.Overall(); limit != SpareLimits(400) {
		t.Fatalf("approved raise not applied: %+v", limit)
	}
}

func TestOnlyTheOwnerChangesLoopSettings(t *testing.T) {
	r := newRig(t)
	r.pol.approve = true // even an approving owner policy does not help a loop
	for _, origin := range []string{"loops", "loop1", change.OriginPipeline, "guest:mail-agent", "update"} {
		for i, id := range []string{"loops:n90:budget:4000", "loops:n91:on:all", "loops:n92:budget:1"} {
			action := []string{ActionBudget, ActionOn, ActionBudgetLower}[i]
			in := journal.Intent{ID: id, Origin: origin, Account: journal.BrokerAccount, Action: action, Executor: Executor}
			err := r.s.Check(context.Background(), journal.PhaseAuthorize, in)
			if err == nil || errors.Is(err, ErrNeedsOwner) {
				t.Fatalf("origin %q may %s: %v", origin, action, err)
			}
		}
	}
	// A loop proposing a change to its own budget through the pipeline
	// fails qualification (LOOP-6, CHG-2).
	rep, err := r.p.Propose(context.Background(), change.Candidate{Origin: "loop1",
		Files: map[string][]byte{"budget/spare.json": []byte(`{"calls":5000}`)}})
	if err != nil || rep.State != change.StateRejected {
		t.Fatalf("budget candidate: %+v, %v", rep, err)
	}
	if _, limit := r.spare.Overall(); limit != SpareLimits(DefaultSpareCalls) {
		t.Fatalf("spare cap changed: %+v", limit)
	}
}

func TestStopSharingGoesToThePipeline(t *testing.T) {
	r := newRig(t)
	r.pol.approve = true
	req, _ := ParseText("START SHARING")
	must(t, r.s.Set(context.Background(), req))
	req, _ = ParseText("STOP SHARING")
	must(t, r.s.Set(context.Background(), req))
	n := 0
	for _, s := range r.eng.List() {
		if s.Intent.Executor == change.Executor && s.State == journal.Succeeded {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d sharing intents through the pipeline, want 2", n)
	}
}

func TestOneLoopOnAfterAllOffTurnsOnOnlyThatLoop(t *testing.T) {
	r := newRig(t)
	for _, msg := range []string{"LOOPS OFF", "LOOP 2 ON"} {
		req, _ := ParseText(msg)
		must(t, r.s.Set(context.Background(), req))
	}
	set := r.s.Settings()
	if !set.On(Secure) || set.On(Improve) || set.On(Maintain) {
		t.Fatalf("after LOOPS OFF, LOOP 2 ON: %+v", set)
	}
}

func TestZeroSpareBudgetAllowsNoModelCall(t *testing.T) {
	r := newRig(t)
	req, _ := ParseText("SPARE BUDGET 0")
	must(t, r.s.Set(context.Background(), req))
	// Every metered call reserves output (meter.Wrap), so the smallest
	// real call is one input and one output token.
	if _, err := r.spare.Start("eval-x", 1, 1); err == nil {
		t.Fatal("a model call fit under a zero spare budget")
	}
}
