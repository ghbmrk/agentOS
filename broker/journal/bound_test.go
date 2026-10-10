package journal

// REQ: CH-2, OP-4

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// denyAll refuses every intent, as a broker with no grants does.
type denyAll struct{}

func (denyAll) Check(context.Context, Phase, Intent) error { return errors.New("no grant") }

// sinkStore keeps nothing, so a heap measurement sees only the engine.
type sinkStore struct{}

func (sinkStore) Append([]byte) error      { return nil }
func (sinkStore) ReadAll() ([]byte, error) { return nil, nil }
func (sinkStore) Truncate(int64) error     { return nil }
func (sinkStore) Rewrite([]byte) error     { return nil }

// guestParams is a guest request's parameters, about 1 KiB as JSON.
func guestParams(i int) map[string]any {
	p := map[string]any{"n": i}
	for k := 0; k < 12; k++ {
		p[fmt.Sprintf("field%02d", k)] = strings.Repeat("p", 72)
	}
	return p
}

// heapAfterDenials is the live heap with an engine that has refused n
// guest requests.
func heapAfterDenials(t *testing.T, n int) uint64 {
	e := mustOpen(t, sinkStore{}, denyAll{}, newService())
	for i := 0; i < n; i++ {
		in := intent(fmt.Sprintf("m1/req-%d", i), "acct")
		in.Origin = "guest:m1"
		in.Params = guestParams(i)
		must(e.Submit(in))
		if st := must(e.Authorize(ctx, in.ID)); st.State != Denied {
			t.Fatalf("%s: %s", in.ID, st.State)
		}
	}
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	runtime.KeepAlive(e)
	return ms.HeapAlloc
}

// The external review measured memory growing with every refused request.
// Settled denials leave the in-memory indexes (they stay in the journal),
// so 45,000 more of them cost a fixed amount, not their parameters.
func TestSIMBoundDenialsRetainBoundedHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("55,000 requests")
	}
	const bound = 8 << 20
	small := heapAfterDenials(t, 5000)
	large := heapAfterDenials(t, 50000)
	growth := int64(large) - int64(small)
	t.Logf("heap after 5,000 denials %.1f MiB, after 50,000 %.1f MiB", float64(small)/(1<<20), float64(large)/(1<<20))
	if growth > bound {
		t.Fatalf("heap grew %.1f MiB from 5,000 to 50,000 denials, bound %d MiB", float64(growth)/(1<<20), bound>>20)
	}
}

// openMix builds a journal with settled intents (succeeded and denied,
// more denials than stay in memory) and one intent in each open state.
func openMix(t *testing.T, st Store, settled int) (*Engine, *testPolicy) {
	p := newPolicy()
	svc := newService()
	svc.mode = func(key string) execMode {
		if strings.HasPrefix(key, "unknown") {
			return modeTimeout
		}
		return modeOK
	}
	e := mustOpen(t, st, p, svc)
	for i := 0; i < settled; i++ {
		in := intent(fmt.Sprintf("done-%d", i), "acct")
		in.Params = map[string]any{"n": i}
		must(e.Submit(in))
		if i%10 == 0 {
			must(e.Authorize(ctx, in.ID))
			must(e.Dispatch(ctx, in.ID))
			continue
		}
		p.revoke(in.ID, true)
		must(e.Authorize(ctx, in.ID))
	}
	must(e.Submit(intent("pending", "acct")))
	for _, id := range []string{"held", "unknown"} {
		must(e.Submit(intent(id, "acct")))
		must(e.Authorize(ctx, id))
	}
	must(e.Dispatch(ctx, "unknown"))
	return e, p
}

// STOP reads the index of open intents, so its work does not grow with
// the settled history (CH-2: STOP is handled promptly by the broker).
func TestSIMBoundStopIgnoresSettledHistory(t *testing.T) {
	timeStop := func(settled int) (time.Duration, StopReport) {
		e, _ := openMix(t, &MemStore{}, settled)
		best := time.Duration(1 << 62)
		var rep StopReport
		for i := 0; i < 9; i++ {
			start := time.Now()
			rep = must(e.Stop(ctx))
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best, rep
	}
	few, repFew := timeStop(0)
	many, repMany := timeStop(40000)
	want := StopReport{Held: []string{"held"}, Unresolved: []string{"unknown"}}
	for _, rep := range []StopReport{repFew, repMany} {
		if !reflect.DeepEqual(rep.Held, want.Held) || !reflect.DeepEqual(rep.Unresolved, want.Unresolved) {
			t.Fatalf("stop report %+v, want held %v unresolved %v", rep, want.Held, want.Unresolved)
		}
	}
	t.Logf("STOP with 0 settled intents %v, with 40,000 %v", few, many)
	if many > 10*few+time.Millisecond {
		t.Fatalf("STOP took %v with 40,000 settled intents and %v with none", many, few)
	}
}

// Restart replays the journal and rebuilds the open-intent index and the
// evicted denials (OP-4). An evicted denial is still the same intent: Get
// answers its state and refusal from memory, resubmitting it is idempotent
// or a conflict (OP-1), and it is listed whole, found by origin, rated and
// erased like any other.
func TestSIMBoundReplayRebuildsIndexAndEvictedDenials(t *testing.T) {
	st := &MemStore{}
	e, _ := openMix(t, st, 3000)
	before := e.List()
	old := before[1]
	if old.Intent.ID != "done-1" || old.State != Denied || old.Intent.Params["n"] == nil {
		t.Fatalf("done-1 before restart: %+v", old)
	}
	trail := len(e.Trail())

	e2 := mustOpen(t, st, newPolicy(), newService())
	want := old
	want.Intent = Intent{ID: old.Intent.ID, GoalID: old.Intent.GoalID, Origin: old.Intent.Origin,
		Account: old.Intent.Account, Action: old.Intent.Action, Executor: old.Intent.Executor}
	want.Intent, _ = normalize(want.Intent)
	if got := must(e2.Get("done-1")); !reflect.DeepEqual(got, want) {
		t.Fatalf("evicted denial after restart:\n got %+v\nwant %+v", got, want)
	}
	if got := e2.List(); !reflect.DeepEqual(got, before) {
		t.Fatalf("List after restart differs: %d intents, want %d", len(got), len(before))
	}
	if got := len(e2.Trail()); got != trail {
		t.Fatalf("trail has %d records, want %d", got, trail)
	}
	if got := bySeq(e2.open); len(got) != 3 || got[0].intent.ID != "pending" ||
		got[1].intent.ID != "held" || got[2].intent.ID != "unknown" || got[2].state != OutcomeUnknown {
		t.Fatalf("open index after restart has %d intents", len(got))
	}
	if len(e2.intents) > hotDenials+len(e2.open)+300 { // + the 300 succeeded
		t.Fatalf("%d intents in memory after restart", len(e2.intents))
	}
	rep := must(e2.Stop(ctx))
	if !reflect.DeepEqual(rep.Held, []string{"held"}) || !reflect.DeepEqual(rep.Unresolved, []string{"unknown"}) {
		t.Fatalf("stop after restart: %+v", rep)
	}

	in := intent("done-1", "acct")
	in.Params = map[string]any{"n": 1}
	if got := must(e2.Submit(in)); got.State != Denied {
		t.Fatalf("resubmitted evicted denial: %s", got.State)
	}
	in.Params = map[string]any{"n": 2}
	if _, err := e2.Submit(in); !errors.Is(err, ErrConflict) {
		t.Fatalf("resubmitted evicted denial with other params: %v", err)
	}
	if _, err := e2.Get("never-submitted"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if got := must(e2.RecordQuality("done-2", Quality{Verdict: VerdictWrong, Source: "owner"})); got.Quality.Verdict != VerdictWrong {
		t.Fatalf("quality on evicted denial: %+v", got.Quality)
	}
	ids := e2.Between("owner-sms", time.Time{}, time.Time{})
	if len(ids) != len(before) || ids[3] != "done-3" {
		t.Fatalf("between: %d ids, want %d", len(ids), len(before))
	}
	sts := e2.StatusBetween("owner-sms", time.Time{}, time.Time{})
	if len(sts) != len(before) || !reflect.DeepEqual(sts[1], old) {
		t.Fatalf("status between: %d statuses", len(sts))
	}
	erased, _ := must2(e2.Erase([]string{"done-1", "done-3"}))
	if !reflect.DeepEqual(erased, []string{"done-1", "done-3"}) {
		t.Fatalf("erased %v", erased)
	}
	if got := must(e2.Get("done-3")); got.Intent.Params != nil {
		t.Fatalf("erased evicted denial keeps params: %+v", got.Intent.Params)
	}
	if got := e2.Erased(); !reflect.DeepEqual(got, []string{"done-1", "done-3"}) {
		t.Fatalf("Erased() = %v", got)
	}

	// A third run sees the same: the rating and the erasure replay too.
	e3 := mustOpen(t, st, newPolicy(), newService())
	if got := must(e3.Get("done-2")); got.Quality.Verdict != VerdictWrong {
		t.Fatalf("quality after restart: %+v", got.Quality)
	}
	if got := e3.StatusBetween("owner-sms", time.Time{}, time.Time{}); got[3].Intent.ID != "done-3" || got[3].Intent.Params != nil {
		t.Fatalf("erasure after restart: %+v", got[3].Intent)
	}
}

// readCounter counts whole-journal reads.
type readCounter struct {
	Store
	reads atomic.Int64
}

func (c *readCounter) ReadAll() ([]byte, error) {
	c.reads.Add(1)
	return c.Store.ReadAll()
}

// A guest repeating old requests is answered from memory: no Get,
// resubmission, Authorize or Dispatch of an evicted denial reads the journal, which would hold
// the store while STOP waits to append (CH-2, review of #720).
func TestSIMBoundEvictedLookupsReadNoJournal(t *testing.T) {
	st := &readCounter{Store: &MemStore{}}
	e, _ := openMix(t, st, 5000)
	if e.intents["done-1"] != nil || !e.evicted("done-1") {
		t.Fatal("done-1 is not evicted")
	}
	st.reads.Store(0)
	for i := 1; i < 5000; i++ {
		if i%10 == 0 {
			continue // succeeded, still in memory
		}
		id := fmt.Sprintf("done-%d", i)
		got := must(e.Get(id))
		if got.State != Denied || got.Permission.Reason != "grant revoked" || got.Intent.GoalID != "goal-1" {
			t.Fatalf("get %s: %+v", id, got)
		}
		in := intent(id, "acct")
		in.Params = map[string]any{"n": i}
		if got := must(e.Submit(in)); got.State != Denied {
			t.Fatalf("resubmit %s: %s", id, got.State)
		}
		in.Params = map[string]any{"n": -i}
		if _, err := e.Submit(in); !errors.Is(err, ErrConflict) {
			t.Fatalf("resubmit %s with other params: %v", id, err)
		}
		if got, err := e.Authorize(ctx, id); !errors.Is(err, ErrState) || got.State != Denied {
			t.Fatalf("authorize %s: %s %v", id, got.State, err)
		}
		if _, err := e.Dispatch(ctx, id); !errors.Is(err, ErrState) {
			t.Fatalf("dispatch %s: %v", id, err)
		}
	}
	if n := st.reads.Load(); n != 0 {
		t.Fatalf("%d journal reads answering evicted denials", n)
	}
}

// STOP stays prompt while guests hammer evicted denials (CH-2). Before the
// fix each resubmission read the whole journal under the store's mutex,
// and the review measured STOP at 8.9 s under this load.
func TestSIMBoundStopPromptUnderEvictedResubmission(t *testing.T) {
	st := &readCounter{Store: &MemStore{}}
	e, _ := openMix(t, st, 20000)
	best := time.Duration(1 << 62)
	for i := 0; i < 5; i++ {
		start := time.Now()
		must(e.Stop(ctx))
		best = min(best, time.Since(start))
	}
	st.reads.Store(0)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 1 + g; ; i = (i + 8) % 20000 {
				select {
				case <-done:
					return
				default:
				}
				if i%10 == 0 {
					continue
				}
				in := intent(fmt.Sprintf("done-%d", i), "acct")
				in.Params = map[string]any{"n": i}
				if _, err := e.Submit(in); err != nil {
					t.Errorf("resubmit: %v", err)
					return
				}
				e.Get(in.ID)
			}
		}(g)
	}
	worst := time.Duration(0)
	for i := 0; i < 9; i++ {
		start := time.Now()
		must(e.Stop(ctx))
		worst = max(worst, time.Since(start))
		time.Sleep(time.Millisecond)
	}
	close(done)
	wg.Wait()
	t.Logf("STOP alone %v, under resubmission at worst %v", best, worst)
	if n := st.reads.Load(); n != 0 {
		t.Fatalf("%d journal reads under resubmission", n)
	}
	if worst > 10*best+100*time.Millisecond {
		t.Fatalf("STOP took %v under resubmission, %v alone", worst, best)
	}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(fmt.Sprintf("unexpected error: %v", err))
	}
	return a, b
}
