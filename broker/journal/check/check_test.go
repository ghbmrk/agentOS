package check

// Counterexamples and mutants: each predicate rejects a generated journal
// that breaks only its invariant and accepts the valid journal it was grown
// from; a checker with that predicate dropped accepts the counterexample, so
// no predicate is dead weight.
//
// REQ: OP-3, OP-4, OP-5, CAP-3

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// trail builds records by hand, continuing the sequence of a valid prefix.
type trail struct{ recs []journal.Record }

func (t *trail) add(r journal.Record) *trail {
	r.V, r.Seq, r.At = 1, uint64(len(t.recs)+1), time.Unix(int64(len(t.recs)), 0).UTC()
	t.recs = append(t.recs, r)
	return t
}

func (t *trail) sub(in journal.Intent) *trail {
	return t.add(journal.Record{Type: journal.RecSubmitted, ID: in.ID, Intent: &in})
}
func (t *trail) rec(typ journal.RecordType, id string) *trail {
	return t.add(journal.Record{Type: typ, ID: id})
}
func (t *trail) disp(id string, n int) *trail {
	return t.add(journal.Record{Type: journal.RecDispatched, ID: id, Attempt: n})
}
func (t *trail) obs(id string, n int, res journal.Result) *trail {
	return t.add(journal.Record{Type: journal.RecObserved, ID: id, Attempt: n, Result: res, Source: "executor"})
}

// effect is a plain intent with content that erasure must remove.
func effect(id string) journal.Intent {
	return journal.Intent{ID: id, Origin: "agent", Account: "mail", Action: "send", Executor: "svc",
		Params: map[string]any{"body": "canary-" + id}}
}

// grown returns a valid journal from a seeded workload: the prefix every
// counterexample extends.
func grown(t *testing.T, seed int64) []journal.Record {
	t.Helper()
	w := newWorld(t, seed, honest)
	for i := 0; i < 40; i++ {
		w.step()
	}
	w.restart()
	if w.eng.Stopped() {
		if err := w.eng.Resume(); err != nil {
			t.Fatal(err)
		}
	}
	return w.eng.Trail()
}

type shows map[string]bool

func (s shows) Name() string         { return "projection" }
func (s shows) Shows(id string) bool { return s[id] }

// counterexamples maps each rule to journals that break only it, given a
// valid prefix. Each returns the records and the options to judge them by.
var counterexamples = map[string][]func(p []journal.Record) ([]journal.Record, Options){
	"OP-3": {
		func(p []journal.Record) ([]journal.Record, Options) { // never authorized
			t := &trail{recs: p}
			t.sub(effect("x")).disp("x", 1).obs("x", 1, journal.ResultSucceeded)
			return t.recs, Options{}
		},
		func(p []journal.Record) ([]journal.Record, Options) { // recheck failed, then dispatched
			t := &trail{recs: p}
			t.sub(effect("x")).rec(journal.RecAuthorized, "x")
			t.add(journal.Record{Type: journal.RecRecheckFailed, ID: "x", Reason: "revoked"})
			t.disp("x", 1).obs("x", 1, journal.ResultSucceeded)
			return t.recs, Options{}
		},
		func(p []journal.Record) ([]journal.Record, Options) { // dispatched while stopped
			t := &trail{recs: p}
			t.rec(journal.RecStop, "").sub(effect("x")).rec(journal.RecAuthorized, "x")
			t.disp("x", 1).obs("x", 1, journal.ResultSucceeded).rec(journal.RecResume, "")
			return t.recs, Options{}
		},
		func(p []journal.Record) ([]journal.Record, Options) { // grant revoked before dispatch
			t := &trail{recs: p}
			rv := journal.Intent{ID: "rv", Origin: "owner", Account: journal.BrokerAccount,
				Action: journal.ActionGrantRevoke, GrantRef: "g9", Executor: "grants"}
			x := effect("x")
			x.GrantRef = "g9"
			t.sub(x).rec(journal.RecAuthorized, "x")
			t.sub(rv).rec(journal.RecAuthorized, "rv").disp("rv", 1).obs("rv", 1, journal.ResultSucceeded)
			t.disp("x", 1).obs("x", 1, journal.ResultSucceeded)
			return t.recs, Options{}
		},
	},
	"OP-4": {
		func(p []journal.Record) ([]journal.Record, Options) { // never observed, at rest
			t := &trail{recs: p}
			t.sub(effect("x")).rec(journal.RecAuthorized, "x").disp("x", 1)
			return t.recs, Options{}
		},
		func(p []journal.Record) ([]journal.Record, Options) { // retried while unknown
			t := &trail{recs: p}
			t.sub(effect("x")).rec(journal.RecAuthorized, "x").disp("x", 1).obs("x", 1, journal.ResultUnknown)
			t.disp("x", 2).obs("x", 2, journal.ResultSucceeded)
			return t.recs, Options{}
		},
		func(p []journal.Record) ([]journal.Record, Options) { // settled twice
			t := &trail{recs: p}
			t.sub(effect("x")).rec(journal.RecAuthorized, "x").disp("x", 1).obs("x", 1, journal.ResultSucceeded)
			t.obs("x", 1, journal.ResultNotApplied)
			return t.recs, Options{}
		},
	},
	"OP-5": {
		func(p []journal.Record) ([]journal.Record, Options) { // a gap in the trail
			t := &trail{recs: p}
			t.sub(effect("x"))
			t.recs[len(t.recs)-1].Seq++
			return t.recs, Options{}
		},
		func(p []journal.Record) ([]journal.Record, Options) { // a record for no intent
			t := &trail{recs: p}
			t.rec(journal.RecQuality, "nobody")
			return t.recs, Options{}
		},
		func(p []journal.Record) ([]journal.Record, Options) { // submitted twice
			t := &trail{recs: p}
			t.sub(effect("x")).sub(effect("x"))
			return t.recs, Options{}
		},
	},
	"CAP-3": {
		func(p []journal.Record) ([]journal.Record, Options) { // content left in the journal
			t := &trail{recs: p}
			t.sub(effect("x")).rec(journal.RecAuthorized, "x").disp("x", 1).obs("x", 1, journal.ResultSucceeded)
			t.rec(journal.RecErased, "x")
			return t.recs, Options{}
		},
		func(p []journal.Record) ([]journal.Record, Options) { // a projection still shows it
			t := &trail{recs: p}
			x := effect("x")
			x.Params = nil
			t.sub(x).rec(journal.RecAuthorized, "x").disp("x", 1).obs("x", 1, journal.ResultSucceeded)
			t.rec(journal.RecErased, "x")
			return t.recs, Options{Views: []View{shows{"x": true}}}
		},
	},
}

func without(name string) []Rule {
	var out []Rule
	for _, r := range Rules {
		if r.Name != name {
			out = append(out, r)
		}
	}
	return out
}

func TestEachPredicateRejectsItsCounterexampleAndItsMutantDoesNot(t *testing.T) {
	if len(counterexamples) != len(Rules) {
		t.Fatalf("%d rules, counterexamples for %d", len(Rules), len(counterexamples))
	}
	for seed := int64(1); seed <= 20; seed++ {
		valid := grown(t, seed)
		if v := Journal(valid, Options{}); len(v) > 0 {
			t.Fatalf("seed %d: valid journal rejected: %v", seed, v)
		}
		for rule, makes := range counterexamples {
			for i, mk := range makes {
				recs, o := mk(append([]journal.Record(nil), valid...))
				got := Journal(recs, o)
				if len(got) == 0 {
					t.Fatalf("seed %d: %s counterexample %d accepted", seed, rule, i)
				}
				for _, v := range got {
					if v.Rule != rule {
						t.Fatalf("seed %d: %s counterexample %d also breaks %s: %v", seed, rule, i, v.Rule, v)
					}
				}
				if m := run(without(rule), recs, o); len(m) > 0 {
					t.Fatalf("seed %d: %s counterexample %d caught with the predicate dropped: %v", seed, rule, i, m)
				}
			}
		}
	}
}

func TestLiveAllowsAnAttemptStillRunning(t *testing.T) {
	tr := &trail{}
	tr.sub(effect("x")).rec(journal.RecAuthorized, "x").disp("x", 1)
	if v := Journal(tr.recs, Options{Live: true}); len(v) > 0 {
		t.Fatalf("live journal with one running attempt rejected: %v", v)
	}
	if v := Journal(tr.recs, Options{}); len(v) != 1 || v[0].Rule != "OP-4" {
		t.Fatalf("at rest, want one OP-4 violation, got %v", v)
	}
}

func TestNarrowingRunsDuringStop(t *testing.T) {
	tr := &trail{}
	rv := journal.Intent{ID: "rv", Origin: "owner", Account: journal.BrokerAccount,
		Action: journal.ActionGrantRevoke, GrantRef: "g1", Executor: "grants"}
	tr.rec(journal.RecStop, "").sub(rv).rec(journal.RecAuthorized, "rv").disp("rv", 1).obs("rv", 1, journal.ResultSucceeded)
	if v := Journal(tr.recs, Options{}); len(v) > 0 {
		t.Fatalf("a revoke during STOP rejected: %v", v)
	}
}

// A policy that forgets to recheck a revoked grant at dispatch is a real
// OP-3 defect; the checker finds it from the journal alone.
func TestCatchesAPolicyThatSkipsTheRecheck(t *testing.T) {
	found := false
	for seed := int64(1); seed <= 200 && !found; seed++ {
		w := newWorld(t, seed, lax)
		for i := 0; i < 300; i++ {
			w.step()
		}
		for _, v := range Engine(w.eng, true) {
			if v.Rule == "OP-3" && strings.Contains(v.Detail, "revoked") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no seed's lax policy dispatch under a revoked grant was caught")
	}
}

// Seeded random workloads, with crashes (some torn) and restarts, erasure,
// STOP and revocation: the checker never rejects what an honest engine and
// policy wrote, live after each step, at rest after each restart, and on the
// bytes decoded from the medium.
func TestPropertyHonestEngineNeverViolates(t *testing.T) {
	for seed := int64(1); seed <= 200; seed++ {
		w := newWorld(t, seed, honest)
		for i := 0; i < 60; i++ {
			w.step()
			if v := Engine(w.eng, true); len(v) > 0 {
				t.Fatalf("seed %d step %d: live: %v", seed, i, v)
			}
			if w.rng.Intn(8) == 0 {
				w.restart()
				if v := Engine(w.eng, false); len(v) > 0 {
					t.Fatalf("seed %d step %d: at rest: %v", seed, i, v)
				}
				data, _ := w.mem.ReadAll()
				recs, err := journal.Decode(data)
				if err != nil {
					t.Fatalf("seed %d: decode: %v", seed, err)
				}
				if v := Journal(recs, Options{}); len(v) > 0 {
					t.Fatalf("seed %d step %d: medium: %v", seed, i, v)
				}
			}
		}
	}
}

func TestNoteIsEmptyWhenCleanAndNamesTheRuleOtherwise(t *testing.T) {
	w := newWorld(t, 7, honest)
	for i := 0; i < 20; i++ {
		w.step()
	}
	if n := Note(w.eng)(); n != "" {
		t.Fatalf("clean journal noted %q", n)
	}
	w = newWorld(t, 7, lax)
	for i := 0; i < 400 && len(Engine(w.eng, true)) == 0; i++ {
		w.step()
	}
	n := Note(w.eng)()
	if !strings.HasPrefix(n, "Journal check failed (OP-3)") || strings.Contains(n, "\n") {
		t.Fatalf("note %q", n)
	}
}
