package journal

// Example-based tests, one group per requirement. property_test.go checks
// the same requirements over random workloads with crashes.
//
// REQ: OP-1, OP-2, OP-3, OP-4, OP-5, OP-6, OP-7

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

var ctx = context.Background()

// --- OP-1: idempotent submission ---

func TestOP1SameIDSameParamsReturnsExistingState(t *testing.T) {
	svc := newService()
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	want := must(e.Dispatch(ctx, "a"))

	got, err := e.Submit(intent("a", "acct"))
	if err != nil {
		t.Fatalf("resubmit: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resubmit state = %+v, want %+v", got, want)
	}
	if n := countType(e.Trail(), RecSubmitted); n != 1 {
		t.Fatalf("submitted records = %d, want 1", n)
	}
	if svc.effectCount("a") != 1 {
		t.Fatalf("effects = %d, want 1", svc.effectCount("a"))
	}
}

func TestOP1SameIDDifferentParamsRejected(t *testing.T) {
	e := mustOpen(t, &MemStore{}, newPolicy(), newService())
	must(e.Submit(intent("a", "acct")))
	for name, mut := range map[string]func(*Intent){
		"param":      func(i *Intent) { i.Params["subject"] = "other" },
		"recipient":  func(i *Intent) { i.Recipients = []string{"mallory@example.test"} },
		"visibility": func(i *Intent) { i.Visibility = "public" },
		"account":    func(i *Intent) { i.Account = "other" },
		"grant":      func(i *Intent) { i.GrantRef = "grant-2" },
		"reserve":    func(i *Intent) { i.Reservation = &Reservation{Amount: 5, Unit: "usd_cents"} },
	} {
		in := intent("a", "acct")
		mut(&in)
		if _, err := e.Submit(in); !errors.Is(err, ErrConflict) {
			t.Errorf("%s: err = %v, want ErrConflict", name, err)
		}
	}
	if n := countType(e.Trail(), RecSubmitted); n != 1 {
		t.Fatalf("submitted records = %d, want 1", n)
	}
}

func TestOP1HoldsAcrossRestart(t *testing.T) {
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	must(e.Submit(intent("a", "acct")))
	e2 := mustOpen(t, st, newPolicy(), newService())
	if _, err := e2.Submit(intent("a", "acct")); err != nil {
		t.Fatalf("same params after restart: %v", err)
	}
	in := intent("a", "acct")
	in.Params["subject"] = "changed"
	if _, err := e2.Submit(in); !errors.Is(err, ErrConflict) {
		t.Fatalf("different params after restart: err = %v, want ErrConflict", err)
	}
}

// --- OP-2: outcome_unknown until evidence ---

func TestOP2LostAckStaysUnknownAndBlocksRetry(t *testing.T) {
	svc := newService()
	svc.mode = func(string) execMode { return modeDropAck }
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	st := must(e.Dispatch(ctx, "a"))
	if st.State != OutcomeUnknown {
		t.Fatalf("state = %s, want outcome_unknown", st.State)
	}
	// A new attempt is not allowed while the old one may have happened.
	if _, err := e.Dispatch(ctx, "a"); !errors.Is(err, ErrState) {
		t.Fatalf("retry while unknown: err = %v, want ErrState", err)
	}
	if svc.executeCount() != 1 {
		t.Fatalf("executes = %d, want 1", svc.executeCount())
	}
	// Reconciliation finds the effect: resolved as succeeded, no duplicate.
	rep := e.Reconcile(ctx)
	if !reflect.DeepEqual(rep.Resolved, []string{"a"}) {
		t.Fatalf("resolved = %v", rep.Resolved)
	}
	if got := must(e.Get("a")).State; got != Succeeded {
		t.Fatalf("state = %s, want succeeded", got)
	}
	if svc.effectCount("a") != 1 {
		t.Fatalf("effects = %d, want 1", svc.effectCount("a"))
	}
}

func TestOP2RetryOnlyAfterEvidenceOfNoEffect(t *testing.T) {
	svc := newService()
	first := true
	svc.mode = func(string) execMode {
		if first {
			first = false
			return modeTimeout
		}
		return modeOK
	}
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	must(e.Dispatch(ctx, "a"))
	e.Reconcile(ctx) // service says attempt 1 never happened
	if got := must(e.Get("a")).State; got != NotApplied {
		t.Fatalf("state = %s, want not_applied", got)
	}
	st := must(e.Dispatch(ctx, "a"))
	if st.State != Succeeded || len(st.Attempts) != 2 {
		t.Fatalf("after retry: %+v", st)
	}
	if svc.effectCount("a") != 1 {
		t.Fatalf("effects = %d, want 1", svc.effectCount("a"))
	}
}

func TestOP2ServiceThatCannotTellLeavesUnknown(t *testing.T) {
	svc := newService()
	svc.mode = func(string) execMode { return modeDropAck }
	svc.knows = func(string) bool { return false }
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	must(e.Dispatch(ctx, "a"))
	rep := e.Reconcile(ctx)
	if len(rep.Resolved) != 0 || !reflect.DeepEqual(rep.Unresolved, []string{"a"}) {
		t.Fatalf("report = %+v", rep)
	}
	// Owner-supplied evidence resolves it.
	st, err := e.Resolve("a", 1, Outcome{Result: ResultSucceeded, Evidence: "owner saw it in Sent"}, "owner")
	if err != nil || st.State != Succeeded {
		t.Fatalf("resolve: %+v, %v", st, err)
	}
	// Unknown is not evidence.
	if _, err := e.Resolve("a", 1, Outcome{Result: ResultUnknown}, "owner"); !errors.Is(err, ErrState) {
		t.Fatalf("resolve with unknown: err = %v", err)
	}
}

func TestOP2PanickingExecutorIsUnknown(t *testing.T) {
	e := mustOpen(t, &MemStore{}, newPolicy(), panicExec{})
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	st, err := e.Dispatch(ctx, "a")
	if err != nil || st.State != OutcomeUnknown {
		t.Fatalf("dispatch: %+v, %v", st, err)
	}
}

type panicExec struct{}

func (panicExec) Execute(context.Context, Intent, int) Outcome   { panic("boom") }
func (panicExec) Reconcile(context.Context, Intent, int) Outcome { panic("boom") }

func TestOP2BogusResultIsUnknown(t *testing.T) {
	e := mustOpen(t, &MemStore{}, newPolicy(), bogusExec{})
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	if st := must(e.Dispatch(ctx, "a")); st.State != OutcomeUnknown {
		t.Fatalf("state = %s, want outcome_unknown", st.State)
	}
}

type bogusExec struct{}

func (bogusExec) Execute(context.Context, Intent, int) Outcome {
	return Outcome{Result: "done-ish"}
}
func (bogusExec) Reconcile(context.Context, Intent, int) Outcome { return Outcome{} }

// --- OP-3: recheck immediately before dispatch ---

func TestOP3RevocationAfterAuthorizeBlocksDispatch(t *testing.T) {
	svc := newService()
	p := newPolicy()
	e := mustOpen(t, &MemStore{}, p, svc)
	must(e.Submit(intent("a", "acct")))
	if st := must(e.Authorize(ctx, "a")); st.State != Authorized {
		t.Fatalf("state = %s", st.State)
	}
	p.revoke("a", true)
	st, err := e.Dispatch(ctx, "a")
	if !errors.Is(err, ErrRecheck) {
		t.Fatalf("err = %v, want ErrRecheck", err)
	}
	if st.State != Denied || st.Permission.Phase != PhaseDispatch {
		t.Fatalf("status = %+v", st)
	}
	if svc.executeCount() != 0 {
		t.Fatal("executor ran after a failed recheck")
	}
}

func TestOP3RecheckIsLastPolicyCallBeforeExecute(t *testing.T) {
	svc := newService()
	p := newPolicy()
	svc.onExecute = func(in Intent, _ int) {
		c, ok := p.lastCall()
		if !ok || c.Phase != PhaseDispatch || c.ID != in.ID {
			t.Errorf("last policy call before execute = %+v", c)
		}
	}
	e := mustOpen(t, &MemStore{}, p, svc)
	for _, id := range []string{"a", "b"} {
		must(e.Submit(intent(id, "acct")))
		must(e.Authorize(ctx, id))
	}
	must(e.Dispatch(ctx, "a"))
	must(e.Dispatch(ctx, "b"))
}

// --- OP-4: restart = replay; reconcile before new dispatch on that account ---

func TestOP4CrashAfterEffectReplaysAsUnknownAndFencesAccount(t *testing.T) {
	svc := newService()
	cs := &crashStore{MemStore: &MemStore{}, budget: 3} // submit, authorize, dispatched; crash on observed
	e := mustOpen(t, cs, newPolicy(), svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	if _, err := e.Dispatch(ctx, "a"); !errors.Is(err, ErrBroken) {
		t.Fatalf("dispatch through crash: err = %v, want ErrBroken", err)
	}
	if !svc.wasApplied("a", 1) {
		t.Fatal("setup: effect should have happened")
	}

	// Restart on what reached the medium.
	e2 := mustOpen(t, cs.MemStore, newPolicy(), svc)
	if st := must(e2.Get("a")); st.State != OutcomeUnknown {
		t.Fatalf("after replay: %s, want outcome_unknown", st.State)
	}
	if got := e2.Fenced("acct"); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("fenced = %v", got)
	}
	// New work on the same account waits; another account does not.
	must(e2.Submit(intent("b", "acct")))
	must(e2.Authorize(ctx, "b"))
	if _, err := e2.Dispatch(ctx, "b"); !errors.Is(err, ErrUnreconciled) {
		t.Fatalf("dispatch on fenced account: err = %v", err)
	}
	must(e2.Submit(intent("c", "other")))
	must(e2.Authorize(ctx, "c"))
	if st := must(e2.Dispatch(ctx, "c")); st.State != Succeeded {
		t.Fatalf("other account: %s", st.State)
	}
	// Reconcile finds the effect; the fence lifts; no duplicate.
	e2.Reconcile(ctx)
	if got := e2.Fenced("acct"); len(got) != 0 {
		t.Fatalf("still fenced: %v", got)
	}
	must(e2.Dispatch(ctx, "b"))
	if svc.effectCount("a") != 1 {
		t.Fatalf("effects for a = %d, want 1", svc.effectCount("a"))
	}
}

func TestOP4TornTailIsDropped(t *testing.T) {
	svc := newService()
	cs := &crashStore{MemStore: &MemStore{}, budget: 2, torn: true} // dispatched record torn
	e := mustOpen(t, cs, newPolicy(), svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	if _, err := e.Dispatch(ctx, "a"); !errors.Is(err, ErrBroken) {
		t.Fatalf("err = %v", err)
	}
	if svc.executeCount() != 0 {
		t.Fatal("executor ran although the dispatched record was not durable")
	}
	e2 := mustOpen(t, cs.MemStore, newPolicy(), svc)
	if st := must(e2.Get("a")); st.State != Authorized {
		t.Fatalf("state = %s, want authorized", st.State)
	}
	if st := must(e2.Dispatch(ctx, "a")); st.State != Succeeded {
		t.Fatalf("state = %s", st.State)
	}
	// The journal is clean again: a third open replays without error.
	mustOpen(t, cs.MemStore, newPolicy(), svc)
}

func TestOP4CorruptCompleteRecordFailsClosed(t *testing.T) {
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	st.data[20] ^= 0x01 // flip a bit inside the first, complete record
	if _, err := Open(st, newPolicy(), map[string]Executor{"svc": newService()}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

func TestOP4FileStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	fs, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := newService()
	e := mustOpen(t, fs, newPolicy(), svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	must(e.Dispatch(ctx, "a"))
	want := e.List()
	fs.Close()

	fs2, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fs2.Close()
	e2 := mustOpen(t, fs2, newPolicy(), svc)
	if got := e2.List(); !reflect.DeepEqual(got, want) {
		t.Fatalf("replayed %+v, want %+v", got, want)
	}
}

// --- OP-5: broker-state changes are intents ---

func TestOP5MetaIntentsShareTrailAndRecovery(t *testing.T) {
	svc := newService()
	cs := &crashStore{MemStore: &MemStore{}, budget: 6}
	e := mustOpen(t, cs, newPolicy(), svc)

	send := intent("send-1", "mail")
	grant := Intent{ID: "grant-7", Origin: "owner-sms", Account: "broker", Action: ActionGrantChange,
		Params: map[string]any{"tool": "mail", "verb": "send"}, Executor: "svc"}
	must(e.Submit(send))
	must(e.Submit(grant))
	must(e.Authorize(ctx, "grant-7"))
	must(e.Authorize(ctx, "send-1"))
	must(e.Dispatch(ctx, "send-1"))      // dispatched + observed: 6 records
	_, err := e.Dispatch(ctx, "grant-7") // crash on its dispatched record? budget is spent: yes
	if !errors.Is(err, ErrBroken) {
		t.Fatalf("err = %v", err)
	}

	e2 := mustOpen(t, cs.MemStore, newPolicy(), svc)
	// One trail, in order, with both kinds.
	var ids []string
	for _, r := range e2.Trail() {
		if r.Type == RecSubmitted {
			ids = append(ids, r.ID)
		}
	}
	if !reflect.DeepEqual(ids, []string{"send-1", "grant-7"}) {
		t.Fatalf("trail order = %v", ids)
	}
	// Same recovery rule: the grant change was never dispatched, so it can run.
	if st := must(e2.Dispatch(ctx, "grant-7")); st.State != Succeeded {
		t.Fatalf("grant state = %s", st.State)
	}

	// A meta intent caught mid-flight is outcome_unknown and fences "broker".
	cs2 := &crashStore{MemStore: &MemStore{}, budget: 3}
	e3 := mustOpen(t, cs2, newPolicy(), svc)
	rel := Intent{ID: "rel-2", Origin: "update", Account: "broker", Action: ActionReleaseActivate, Executor: "svc"}
	must(e3.Submit(rel))
	must(e3.Authorize(ctx, "rel-2"))
	e3.Dispatch(ctx, "rel-2")
	e4 := mustOpen(t, cs2.MemStore, newPolicy(), svc)
	if st := must(e4.Get("rel-2")); st.State != OutcomeUnknown {
		t.Fatalf("release state = %s", st.State)
	}
	if !reflect.DeepEqual(e4.Fenced("broker"), []string{"rel-2"}) {
		t.Fatalf("fenced = %v", e4.Fenced("broker"))
	}
}

// --- OP-6: STOP ---

func TestOP6StopBlocksDispatchAndReportsUnresolved(t *testing.T) {
	svc := newService()
	svc.cancelOK = true
	svc.mode = func(k string) execMode {
		if k == "u#1" {
			return modeDropAck
		}
		return modeOK
	}
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	for _, id := range []string{"u", "done", "held"} {
		must(e.Submit(intent(id, "acct-"+id)))
		must(e.Authorize(ctx, id))
	}
	must(e.Dispatch(ctx, "u"))
	must(e.Dispatch(ctx, "done"))

	rep, err := e.Stop(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rep.Unresolved, []string{"u"}) || !reflect.DeepEqual(rep.Held, []string{"held"}) {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Cancels) != 1 || rep.Cancels[0].ID != "u" || !rep.Cancels[0].Accepted {
		t.Fatalf("cancels = %+v", rep.Cancels)
	}
	// An accepted cancellation is not an undo: the intent stays unresolved.
	if st := must(e.Get("u")); st.State != OutcomeUnknown {
		t.Fatalf("u state = %s", st.State)
	}
	if st := must(e.Get("done")); st.State != Succeeded {
		t.Fatalf("done state = %s", st.State)
	}
	if _, err := e.Dispatch(ctx, "held"); !errors.Is(err, ErrStopped) {
		t.Fatalf("dispatch after stop: err = %v", err)
	}
	// STOP survives a restart.
	st := &MemStore{data: must(e.store.ReadAll())}
	e2 := mustOpen(t, st, newPolicy(), svc)
	if !e2.Stopped() {
		t.Fatal("stop lost on restart")
	}
	if _, err := e2.Dispatch(ctx, "held"); !errors.Is(err, ErrStopped) {
		t.Fatalf("dispatch after restart: err = %v", err)
	}
	if err := e2.Resume(); err != nil {
		t.Fatal(err)
	}
	if st := must(e2.Dispatch(ctx, "held")); st.State != Succeeded {
		t.Fatalf("held after resume: %s", st.State)
	}
}

func TestOP6StopWithoutCancelSupportStillReports(t *testing.T) {
	svc := newService()
	svc.mode = func(string) execMode { return modeDropAck }
	e := mustOpen(t, &MemStore{}, newPolicy(), plainExec{svc})
	must(e.Submit(intent("u", "acct")))
	must(e.Authorize(ctx, "u"))
	must(e.Dispatch(ctx, "u"))
	rep := must(e.Stop(ctx))
	if !reflect.DeepEqual(rep.Unresolved, []string{"u"}) {
		t.Fatalf("unresolved = %v", rep.Unresolved)
	}
	if len(rep.Cancels) != 1 || rep.Cancels[0].Supported {
		t.Fatalf("cancels = %+v", rep.Cancels)
	}
}

// After Stop returns, the only executions that may still start are ones
// whose "dispatched" record was already durable, and the report lists them.
func TestOP6StopRacesDispatch(t *testing.T) {
	for round := 0; round < 50; round++ {
		svc := newService()
		var stopped atomic.Bool
		var mu sync.Mutex
		late := map[string]bool{}
		svc.onExecute = func(in Intent, _ int) {
			if stopped.Load() {
				mu.Lock()
				late[in.ID] = true
				mu.Unlock()
			}
		}
		e := mustOpen(t, &MemStore{}, newPolicy(), svc)
		ids := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
		for _, id := range ids {
			must(e.Submit(intent(id, "acct-"+id)))
			must(e.Authorize(ctx, id))
		}
		var wg sync.WaitGroup
		for _, id := range ids {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				e.Dispatch(ctx, id)
			}(id)
		}
		rep := must(e.Stop(ctx))
		stopped.Store(true)
		wg.Wait()
		listed := map[string]bool{}
		for _, id := range rep.Unresolved {
			listed[id] = true
		}
		for id := range late {
			if !listed[id] {
				t.Fatalf("round %d: %s executed after STOP without being reported", round, id)
			}
		}
		for _, id := range rep.Held {
			if st := must(e.Get(id)); st.State != Authorized {
				t.Fatalf("round %d: held %s is %s", round, id, st.State)
			}
		}
	}
}

// --- OP-7: permission, execution, and quality are separate ---

func TestOP7AllowedSuccessfulCanBeWrong(t *testing.T) {
	svc := newService()
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	before := must(e.Dispatch(ctx, "a"))
	if before.Quality != (Quality{}) {
		t.Fatalf("success implied a quality verdict: %+v", before.Quality)
	}
	after, err := e.RecordQuality("a", Quality{Verdict: VerdictWrong, Source: "owner", Note: "wrong recipient list"})
	if err != nil {
		t.Fatal(err)
	}
	if after.Permission != before.Permission || !reflect.DeepEqual(after.Attempts, before.Attempts) || after.State != Succeeded {
		t.Fatalf("quality changed permission or execution: %+v -> %+v", before, after)
	}
	if after.Permission.Decision != "allowed" || after.Quality.Verdict != VerdictWrong {
		t.Fatalf("status = %+v", after)
	}
	// And it survives replay.
	e2 := mustOpen(t, &MemStore{data: must(e.store.ReadAll())}, newPolicy(), svc)
	if got := must(e2.Get("a")); !reflect.DeepEqual(got, after) {
		t.Fatalf("replayed %+v, want %+v", got, after)
	}
	if _, err := e.RecordQuality("a", Quality{Verdict: "meh", Source: "owner"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad verdict: err = %v", err)
	}
}

func TestOP7DeniedIsNotAnExecutionFailure(t *testing.T) {
	p := newPolicy()
	p.revoke("a", true)
	e := mustOpen(t, &MemStore{}, p, newService())
	must(e.Submit(intent("a", "acct")))
	st := must(e.Authorize(ctx, "a"))
	if st.State != Denied || st.Permission.Decision != "denied" || len(st.Attempts) != 0 {
		t.Fatalf("status = %+v", st)
	}
}

// --- input validation ---

func TestSubmitValidation(t *testing.T) {
	e := mustOpen(t, &MemStore{}, newPolicy(), newService())
	for name, mut := range map[string]func(*Intent){
		"no id":       func(i *Intent) { i.ID = "" },
		"no origin":   func(i *Intent) { i.Origin = "" },
		"no account":  func(i *Intent) { i.Account = "" },
		"no action":   func(i *Intent) { i.Action = "" },
		"no executor": func(i *Intent) { i.Executor = "missing" },
		"bad params":  func(i *Intent) { i.Params["f"] = func() {} },
	} {
		in := intent("x", "acct")
		mut(&in)
		if _, err := e.Submit(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if len(e.Trail()) != 0 {
		t.Fatal("invalid intents reached the journal")
	}
}

func countType(rs []Record, typ RecordType) int {
	n := 0
	for _, r := range rs {
		if r.Type == typ {
			n++
		}
	}
	return n
}
