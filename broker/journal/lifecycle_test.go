package journal

// REQ: OP-11, DEV-5, CRED-11, SM-JL-1, SM-JL-2, SM-JL-3

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// lamp is a reversible device lifecycle as an actuation adapter would
// declare it. Each test registers its own kind, since the registry is
// process-wide.
func lamp(kind string) Lifecycle {
	return Lifecycle{
		Kind:     kind,
		Inverse:  kind + "restore",
		Target:   "level",
		Prior:    "prior_level",
		Bounds:   []string{"min_level", "max_level"},
		DailyCap: 50,
	}
}

func lampIntent(id, kind string, prior, level int) Intent {
	return Intent{
		ID:       id,
		Origin:   "agent",
		Account:  "lamp-1",
		Action:   kind + "set",
		Params:   map[string]any{"level": level, "prior_level": prior, "min_level": 0, "max_level": 80},
		Executor: "svc",
	}
}

// SM-JL-1: a declaration that leaves out what UNDO or the cap needs is
// refused, as is a second declaration of the same kind.
func TestRegisterRejectsIncompleteLifecycle(t *testing.T) {
	full := lamp("actuate.reg_test.")
	cases := map[string]func(*Lifecycle){
		"no kind":            func(l *Lifecycle) { l.Kind = "" },
		"kind without dot":   func(l *Lifecycle) { l.Kind = "actuate"; l.Inverse = "actuate.restore" },
		"no inverse":         func(l *Lifecycle) { l.Inverse = "" },
		"inverse off kind":   func(l *Lifecycle) { l.Inverse = "other.restore" },
		"no prior state":     func(l *Lifecycle) { l.Prior = "" },
		"no target":          func(l *Lifecycle) { l.Target = "" },
		"prior is target":    func(l *Lifecycle) { l.Prior = l.Target },
		"no bounds":          func(l *Lifecycle) { l.Bounds = nil },
		"empty bound key":    func(l *Lifecycle) { l.Bounds = []string{""} },
		"no daily cap":       func(l *Lifecycle) { l.DailyCap = 0 },
		"irreversible prior": func(l *Lifecycle) { l.Inverse = Irreversible; l.Target = "" },
	}
	for name, mutate := range cases {
		l := full
		l.Bounds = append([]string(nil), full.Bounds...)
		mutate(&l)
		if err := Register(l); !errors.Is(err, ErrLifecycle) {
			t.Errorf("%s: Register = %v, want ErrLifecycle", name, err)
		}
	}
	if err := Register(full); err != nil {
		t.Fatalf("complete declaration: %v", err)
	}
	if err := Register(full); !errors.Is(err, ErrLifecycle) {
		t.Fatalf("duplicate kind: Register = %v, want ErrLifecycle", err)
	}
	// A kind nested inside another would make one action belong to two
	// lifecycles, so two caps and two inverses.
	inner := lamp("actuate.reg_test.inner.")
	if err := Register(inner); !errors.Is(err, ErrLifecycle) {
		t.Fatalf("nested kind: Register = %v, want ErrLifecycle", err)
	}
	// An irreversible lifecycle (a CRED-11 hand-off) names no inverse and
	// no prior state, but still names the scalars it must journal.
	hand := Lifecycle{Kind: "handoff.reg_test.", Inverse: Irreversible, Bounds: []string{"source", "destination", "size", "sha256"}, DailyCap: 20}
	if err := Register(hand); err != nil {
		t.Fatalf("irreversible declaration: %v", err)
	}
	if got, ok := LifecycleOf("handoff.reg_test.copy"); !ok || got.Kind != hand.Kind {
		t.Fatalf("LifecycleOf = %+v, %v", got, ok)
	}
	if _, ok := LifecycleOf("send"); ok {
		t.Fatal("an action outside every kind has a lifecycle")
	}
}

// SM-JL-1: an actuation intent journaled without its prior state could
// never be undone, so Check refuses it before Submit.
func TestCheckRejectsIntentMissingPriorState(t *testing.T) {
	kind := "actuate.check_test."
	l := lamp(kind)
	if err := Register(l); err != nil {
		t.Fatal(err)
	}
	if err := l.Check(lampIntent("ok", kind, 10, 40)); err != nil {
		t.Fatalf("complete intent: %v", err)
	}
	bad := map[string]func(*Intent){
		"no prior state":    func(in *Intent) { delete(in.Params, "prior_level") },
		"nil prior state":   func(in *Intent) { in.Params["prior_level"] = nil },
		"no target":         func(in *Intent) { delete(in.Params, "level") },
		"no bound":          func(in *Intent) { delete(in.Params, "max_level") },
		"nested prior":      func(in *Intent) { in.Params["prior_level"] = map[string]any{"v": 1} },
		"list bound":        func(in *Intent) { in.Params["min_level"] = []any{0} },
		"long string prior": func(in *Intent) { in.Params["prior_level"] = strings.Repeat("x", MaxScalarBytes+1) },
		"no account":        func(in *Intent) { in.Account = "" },
		"other kind":        func(in *Intent) { in.Action = "send" },
		"inverse no target": func(in *Intent) { in.Action = l.Inverse; in.Params = map[string]any{ParamUndoes: "e1"} },
		"inverse no effect": func(in *Intent) { in.Action = l.Inverse; delete(in.Params, ParamUndoes) },
	}
	for name, mutate := range bad {
		in := lampIntent("x", kind, 10, 40)
		mutate(&in)
		if err := l.Check(in); !errors.Is(err, ErrLifecycle) {
			t.Errorf("%s: Check = %v, want ErrLifecycle", name, err)
		}
	}
	// What Check passes survives the journal: submit, reopen, read back.
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	must(e.Submit(lampIntent("a", kind, 10, 40)))
	e2 := mustOpen(t, st, newPolicy(), newService())
	recs := must(e2.ReadTrail())
	var got *Intent
	for _, r := range recs {
		if r.Type == RecSubmitted && r.ID == "a" {
			got = r.Intent
		}
	}
	if got == nil {
		t.Fatal("submitted record not found")
	}
	if err := l.Check(*got); err != nil {
		t.Fatalf("intent read back from the journal fails Check: %v", err)
	}
}

// SM-JL-2: the daily count is read from records, so replay after a restart
// and across a midnight gives the same count as the live engine.
func TestDailyCountFromRecords(t *testing.T) {
	kind := "actuate.count_test."
	l := lamp(kind)
	if err := Register(l); err != nil {
		t.Fatal(err)
	}
	loc := time.FixedZone("owner", 2*3600)
	day1 := time.Date(2026, 10, 16, 0, 0, 0, 0, loc)
	day2 := day1.AddDate(0, 0, 1)
	now := day1.Add(23*time.Hour + 58*time.Minute)
	clock := func() time.Time { return now }
	svc := newService()
	st := &MemStore{}
	open := func() *Engine {
		e, err := Open(st, newPolicy(), map[string]Executor{"svc": svc}, testRedact, WithClock(clock))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := open()
	run := func(e *Engine, in Intent) {
		t.Helper()
		must(e.Submit(in))
		must(e.Authorize(context.Background(), in.ID))
		must(e.Dispatch(context.Background(), in.ID))
	}
	run(e, lampIntent("d1-a", kind, 0, 10))
	run(e, lampIntent("d1-b", kind, 10, 20))
	// Refused by the device: not an effect, so not counted.
	svc.mode = func(key string) execMode {
		if strings.HasPrefix(key, "d1-refused") {
			return modeRefuse
		}
		return modeOK
	}
	run(e, lampIntent("d1-refused", kind, 20, 30))
	svc.mode = func(string) execMode { return modeOK }
	// Another device, another lifecycle, and a submitted but never
	// dispatched effect do not count.
	other := lampIntent("d1-other", kind, 0, 5)
	other.Account = "lamp-2"
	run(e, other)
	run(e, intent("d1-send", "lamp-1"))
	must(e.Submit(lampIntent("d1-pending", kind, 0, 1)))
	// Lost acknowledgement: it may have landed, so it counts. It fences
	// the device until resolved (OP-4), so it comes last.
	svc.mode = func(string) execMode { return modeDropAck }
	run(e, lampIntent("d1-unknown", kind, 20, 30))
	svc.mode = func(string) execMode { return modeOK }

	// Midnight passes; the broker restarts.
	now = day2.Add(time.Minute)
	e = open()
	if _, err := e.Resolve("d1-unknown", 1, Outcome{Result: ResultSucceeded, Evidence: "device reports 30"}, "owner"); err != nil {
		t.Fatal(err)
	}
	run(e, lampIntent("d2-a", kind, 30, 40))
	// An undo is not counted against the cap: it only restores.
	undo := must(UndoPlan(e.Trail(), "d2-a", map[string]any{"level": 40}))
	undo.Origin = "owner-sms"
	run(e, undo)

	live := e.Trail()
	read := must(open().ReadTrail())
	for name, recs := range map[string][]Record{"live": live, "replayed": read} {
		if n := l.DailyCount(recs, "lamp-1", day1.Add(5*time.Hour)); n != 3 {
			t.Errorf("%s: day 1 count = %d, want 3 (two applied, one unknown)", name, n)
		}
		if n := l.DailyCount(recs, "lamp-1", day2.Add(20*time.Hour)); n != 1 {
			t.Errorf("%s: day 2 count = %d, want 1", name, n)
		}
		if n := l.DailyCount(recs, "lamp-2", day1); n != 1 {
			t.Errorf("%s: other device count = %d, want 1", name, n)
		}
	}
}

// SM-JL-3: UNDO restores a device only while its state is still what the
// agent set; once someone else has changed it, there is no plan.
func TestUndoPlanOnlyWhileStateMatches(t *testing.T) {
	kind := "actuate.undo_test."
	l := lamp(kind)
	if err := Register(l); err != nil {
		t.Fatal(err)
	}
	svc := newService()
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), svc)
	ctx := context.Background()
	in := lampIntent("eff", kind, 10, 40)
	must(e.Submit(in))
	must(e.Authorize(ctx, "eff"))

	// Not yet dispatched: nothing to undo.
	if _, err := UndoPlan(e.Trail(), "eff", map[string]any{"level": 40}); !errors.Is(err, ErrNoUndo) {
		t.Fatalf("before dispatch: err = %v, want ErrNoUndo", err)
	}
	must(e.Dispatch(ctx, "eff"))
	recs := must(mustOpen(t, st, newPolicy(), svc).ReadTrail())

	// The state still matches (a float from a JSON device reading equals
	// the number the journal read back): the plan sets the prior value back.
	plan, err := UndoPlan(recs, "eff", map[string]any{"level": 40.0})
	if err != nil {
		t.Fatalf("matching state: %v", err)
	}
	if plan.Action != l.Inverse || plan.Account != "lamp-1" || plan.Executor != "svc" || plan.ID != UndoID("eff") {
		t.Fatalf("plan = %+v", plan)
	}
	if !sameValue(plan.Params["level"], 10) || plan.Params[ParamUndoes] != "eff" {
		t.Fatalf("plan params = %v, want level 10 and undoes eff", plan.Params)
	}
	if err := l.Check(plan); err != nil {
		t.Fatalf("plan fails its own lifecycle's Check: %v", err)
	}
	// Planning twice gives the same intent, so a repeated UNDO is one
	// effect (OP-1).
	again := must(UndoPlan(recs, "eff", map[string]any{"level": 40}))
	if again.ID != plan.ID {
		t.Fatalf("second plan ID %q, first %q", again.ID, plan.ID)
	}

	// Someone has since turned the lamp to 70: no plan.
	for name, cur := range map[string]map[string]any{
		"changed": {"level": 70},
		"unknown": {},
		"nil":     nil,
	} {
		if _, err := UndoPlan(recs, "eff", cur); !errors.Is(err, ErrNoUndo) {
			t.Errorf("%s: err = %v, want ErrNoUndo", name, err)
		}
	}

	// A refused effect never happened, an unknown one may not have; an
	// undo is not itself undone; an irreversible kind has no plan.
	svc.mode = func(key string) execMode {
		switch {
		case strings.HasPrefix(key, "refused"):
			return modeRefuse
		case strings.HasPrefix(key, "lost"):
			return modeTimeout
		}
		return modeOK
	}
	for _, id := range []string{"refused", "lost"} {
		x := lampIntent(id, kind, 40, 50)
		x.Account = "lamp-" + id
		must(e.Submit(x))
		must(e.Authorize(ctx, id))
		must(e.Dispatch(ctx, id))
		if _, err := UndoPlan(e.Trail(), id, map[string]any{"level": 50}); !errors.Is(err, ErrNoUndo) {
			t.Errorf("%s effect: err = %v, want ErrNoUndo", id, err)
		}
	}
	svc.mode = func(string) execMode { return modeOK }
	if plan.Origin != "" {
		t.Fatalf("plan origin %q: the broker sets the authenticated source", plan.Origin)
	}
	plan.Origin = "owner-sms"
	must(e.Submit(plan))
	must(e.Authorize(ctx, plan.ID))
	must(e.Dispatch(ctx, plan.ID))
	if _, err := UndoPlan(e.Trail(), plan.ID, map[string]any{"level": 10}); !errors.Is(err, ErrNoUndo) {
		t.Errorf("undo of an undo: err = %v, want ErrNoUndo", err)
	}
	hand := Lifecycle{Kind: "handoff.undo_test.", Inverse: Irreversible, Bounds: []string{"size"}, DailyCap: 5}
	if err := Register(hand); err != nil {
		t.Fatal(err)
	}
	h := Intent{ID: "h1", Origin: "agent", Account: "exec-1", Action: "handoff.undo_test.copy", Params: map[string]any{"size": 3}, Executor: "svc"}
	must(e.Submit(h))
	must(e.Authorize(ctx, "h1"))
	must(e.Dispatch(ctx, "h1"))
	if _, err := UndoPlan(e.Trail(), "h1", map[string]any{}); !errors.Is(err, ErrNoUndo) {
		t.Errorf("irreversible: err = %v, want ErrNoUndo", err)
	}
	if _, err := UndoPlan(e.Trail(), "missing", map[string]any{}); !errors.Is(err, ErrNoUndo) {
		t.Errorf("unknown effect: err = %v, want ErrNoUndo", err)
	}
}
