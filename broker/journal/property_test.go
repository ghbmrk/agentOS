package journal

// Property-based tests: random workloads against a fake external service,
// with the broker crashed (cleanly or mid-write) and restarted at random
// points. Seeds are deterministic; set JOURNAL_PROP_SEEDS to run more.
//
// REQ: OP-1, OP-2, OP-3, OP-4, OP-5, OP-6, OP-7

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"testing"
)

func seeds() int {
	if s, err := strconv.Atoi(os.Getenv("JOURNAL_PROP_SEEDS")); err == nil && s > 0 {
		return s
	}
	return 300
}

// world is everything that survives a broker crash.
type world struct {
	t       *testing.T
	seed    int64
	rng     *rand.Rand
	media   *MemStore
	svc     *fakeService
	policy  *testPolicy
	eng     *Engine
	store   *crashStore
	stopped bool // the test's own view of STOP, for checking executes
	params  map[string]Intent
	altered int
}

var (
	propIDs      = []string{"i0", "i1", "i2", "i3", "i4", "i5", "g0", "g1"}
	propAccounts = []string{"mail", "bank", "broker"}
)

func (w *world) fail(format string, args ...any) {
	w.t.Helper()
	w.t.Fatalf("seed %d: %s", w.seed, fmt.Sprintf(format, args...))
}

func (w *world) restart() {
	// Some restarts tear the last write; Open must drop exactly that.
	w.store = &crashStore{MemStore: w.media, budget: w.rng.Intn(40) + 1, torn: w.rng.Intn(2) == 0}
	e, err := Open(w.store, w.policy, map[string]Executor{"svc": w.svc})
	if err != nil {
		if errors.Is(err, errCrash) {
			// Crashed while writing restart records; try again.
			w.restart()
			return
		}
		w.fail("open: %v", err)
	}
	w.eng = e
	w.stopped = e.Stopped()
}

func (w *world) intentFor(id string) Intent {
	if in, ok := w.params[id]; ok {
		return in
	}
	in := intent(id, propAccounts[w.rng.Intn(len(propAccounts))])
	if id[0] == 'g' {
		in.Action = []string{ActionGrantChange, ActionBudgetChange, ActionSkillAdopt}[w.rng.Intn(3)]
		in.Account = "broker"
	}
	in.Params = map[string]any{"v": w.rng.Intn(1000)}
	w.params[id] = in
	return in
}

func (w *world) step() {
	e := w.eng
	id := propIDs[w.rng.Intn(len(propIDs))]
	switch op := w.rng.Intn(100); {
	case op < 20: // submit, sometimes with params no earlier submission used
		in := w.intentFor(id)
		altered := w.rng.Intn(4) == 0
		if altered {
			w.altered++
			in.Params = map[string]any{"v": -w.altered}
		}
		before, getErr := e.Get(id)
		st, err := e.Submit(in)
		switch {
		case errors.Is(err, ErrBroken):
		case getErr == nil && altered:
			if !errors.Is(err, ErrConflict) {
				w.fail("OP-1: altered resubmit of %s: err = %v", id, err)
			}
		case getErr == nil:
			if err != nil || !reflect.DeepEqual(st, before) {
				w.fail("OP-1: resubmit of %s changed state or failed: %v", id, err)
			}
		case err == nil && altered:
			w.params[id] = in // the first submission defines the params
		}
	case op < 35:
		e.Authorize(ctx, id)
	case op < 70:
		allowedNow := w.policy.allowed(id)
		fenced := len(e.Fenced(w.params[id].Account)) > 0
		calls := w.svc.executeCount()
		_, err := e.Dispatch(ctx, id)
		if w.svc.executeCount() > calls {
			if w.stopped {
				w.fail("OP-6: %s executed while stopped", id)
			}
			if !allowedNow {
				w.fail("OP-3: %s executed with its grant revoked", id)
			}
			if fenced {
				w.fail("OP-4: %s executed on an account with unreconciled intents", id)
			}
		}
		if errors.Is(err, ErrUnreconciled) {
			acct := w.params[id].Account
			if len(e.Fenced(acct)) == 0 {
				w.fail("OP-4: dispatch refused on unfenced account %s", acct)
			}
		}
	case op < 78:
		e.Reconcile(ctx)
	case op < 83:
		w.policy.revoke(id, w.rng.Intn(2) == 0)
	case op < 86:
		if _, err := e.Stop(ctx); err == nil {
			w.stopped = true
		}
	case op < 90:
		if err := e.Resume(); err == nil {
			w.stopped = false
		}
	case op < 94:
		v := []Verdict{VerdictGood, VerdictWrong}[w.rng.Intn(2)]
		before, err := e.Get(id)
		after, qerr := e.RecordQuality(id, Quality{Verdict: v, Source: "owner"})
		if err == nil && qerr == nil {
			if after.State != before.State || after.Permission != before.Permission ||
				!reflect.DeepEqual(after.Attempts, before.Attempts) {
				w.fail("OP-7: quality on %s changed permission or execution", id)
			}
		}
	default:
		w.restart()
	}
	if w.store.crashed {
		w.restart()
	}
}

// check asserts the invariants that must hold after every step.
func (w *world) check(replay bool) {
	e := w.eng
	for _, st := range e.List() {
		id := st.Intent.ID
		// No duplicated effect, whatever crashed where (OP-2, OP-4).
		if n := w.svc.effectCount(id); n > 1 {
			w.fail("OP-2/OP-4: %s took effect %d times", id, n)
		}
		// Recorded results never contradict the service.
		for _, a := range st.Attempts {
			applied := w.svc.wasApplied(id, a.N)
			if a.Result == ResultSucceeded && !applied {
				w.fail("%s attempt %d recorded succeeded but did not happen", id, a.N)
			}
			if a.Result == ResultNotApplied && applied {
				w.fail("OP-2: %s attempt %d recorded not_applied but happened", id, a.N)
			}
		}
		// Only the last attempt may be unresolved; earlier ones have evidence.
		for i, a := range st.Attempts {
			if i < len(st.Attempts)-1 && a.Result != ResultNotApplied {
				w.fail("OP-2: %s retried after attempt %d was %s", id, a.N, a.Result)
			}
		}
		// Permission, execution, quality stay separate (OP-7).
		if len(st.Attempts) > 0 && st.Permission.Decision == "" {
			w.fail("OP-7: %s executed with no permission record", id)
		}
	}
	if !replay {
		return
	}
	// Replay reproduces the live state exactly (OP-4). Steps are sequential,
	// so nothing is in flight here.
	data, _ := w.media.ReadAll()
	re, err := Open(&MemStore{data: data}, w.policy, map[string]Executor{"svc": w.svc})
	if err != nil {
		w.fail("replay: %v", err)
	}
	if e.broken == nil && !reflect.DeepEqual(re.List(), e.List()) {
		w.fail("OP-4: replay differs from live state")
	}
}

func TestPropertyRandomWorkloadsWithCrashes(t *testing.T) {
	for s := 0; s < seeds(); s++ {
		seed := int64(s)
		rng := rand.New(rand.NewSource(seed))
		svc := newService()
		svc.cancelOK = rng.Intn(2) == 0
		svc.mode = func(string) execMode { return execMode(rng.Intn(4)) }
		svc.knows = func(string) bool { return rng.Intn(10) < 7 }
		w := &world{t: t, seed: seed, rng: rng, media: &MemStore{}, svc: svc, policy: newPolicy(), params: map[string]Intent{}}
		w.restart()
		for i := 0; i < 150; i++ {
			w.step()
			w.check(i%5 == 4)
		}
		// Drain: with an honest service that always knows, every intent
		// resolves and every fence lifts.
		svc.knows = func(string) bool { return true }
		w.restart()
		w.store.budget = 1 << 30
		w.eng.Reconcile(ctx)
		for _, acct := range propAccounts {
			if f := w.eng.Fenced(acct); len(f) != 0 {
				t.Fatalf("seed %d: OP-4: %s still fenced by %v after full reconciliation", seed, acct, f)
			}
		}
		for _, st := range w.eng.List() {
			if st.State == OutcomeUnknown || st.State == InFlight {
				t.Fatalf("seed %d: %s left %s after full reconciliation", seed, st.Intent.ID, st.State)
			}
		}
	}
}

// OP-1 as a pure property: any two intents with equal fields have equal
// fingerprints, and any single-field change alters it.
func TestPropertyFingerprint(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		a := intent(fmt.Sprint("x", rng.Intn(5)), "acct")
		a.Params = map[string]any{"k": rng.Intn(3), "j": rng.Intn(3), "big": int64(1) << 60}
		b, err := normalize(a)
		if err != nil {
			t.Fatal(err)
		}
		if fingerprint(b) != fingerprint(a) {
			t.Fatalf("normalize changed fingerprint for %+v", a)
		}
		c, _ := normalize(a)
		c.Params["k"] = a.Params["k"].(int) + 1
		if fingerprint(c) == fingerprint(a) {
			t.Fatalf("param change kept fingerprint")
		}
	}
}
