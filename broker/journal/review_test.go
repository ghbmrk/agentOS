package journal

// Tests for the PR #18 review fix-list: durability of a new journal file,
// redaction, duplicates under a new ID, policy checks outside the lock, and
// authority-narrowing intents during STOP and fences.
//
// REQ: OP-2, OP-3, OP-4, OP-6

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOpenFileSyncsParentDirAndLocks(t *testing.T) {
	dir := t.TempDir()
	var synced []string
	orig := syncDir
	syncDir = func(d string) error { synced = append(synced, d); return orig(d) }
	defer func() { syncDir = orig }()

	fs, err := OpenFile(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if !reflect.DeepEqual(synced, []string{dir}) {
		t.Fatalf("synced dirs = %v, want [%s]", synced, dir)
	}
	if _, err := OpenFile(filepath.Join(dir, "journal")); !errors.Is(err, ErrLocked) {
		t.Fatalf("second open: err = %v, want ErrLocked", err)
	}
}

// canaryExec reports the canary as evidence and as cancel detail, as a
// careless executor might echo a token back.
type canaryExec struct{}

func (canaryExec) Execute(context.Context, Intent, int) Outcome {
	return Outcome{Result: ResultUnknown, Evidence: "Authorization: Bearer " + canary}
}
func (canaryExec) Reconcile(context.Context, Intent, int) Outcome {
	return Outcome{Result: ResultSucceeded, Evidence: "receipt for " + canary}
}
func (canaryExec) Cancel(context.Context, Intent, int) (bool, string) { return true, canary }

type canaryPolicy struct{}

func (canaryPolicy) Check(_ context.Context, _ Phase, in Intent) error {
	if in.ID == "deny" {
		return errors.New("grant mismatch for key " + canary)
	}
	return nil
}

func TestRedactorIsRequired(t *testing.T) {
	if _, err := Open(&MemStore{}, newPolicy(), map[string]Executor{"svc": newService()}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil redactor: err = %v, want ErrInvalid", err)
	}
}

func TestCanaryNeverReachesJournal(t *testing.T) {
	st := &MemStore{}
	e, err := Open(st, canaryPolicy{}, map[string]Executor{"svc": canaryExec{}}, testRedact)
	if err != nil {
		t.Fatal(err)
	}
	in := intent("a", "acct")
	in.Params = map[string]any{"tok": "Bearer " + canary, "nested": []any{map[string]any{"k": canary}}}
	in.Recipients = []string{canary + "@example.test"}
	in.Preconditions = []string{"balance > " + canary}
	must(e.Submit(in))
	// Resubmitting the same raw intent is still the same intent (OP-1).
	if _, err := e.Submit(in); err != nil {
		t.Fatalf("resubmit with canary: %v", err)
	}
	must(e.Authorize(ctx, "a"))
	must(e.Dispatch(ctx, "a")) // evidence carries the canary
	must(e.Stop(ctx))          // cancel detail carries the canary
	if err := e.Resume(); err != nil {
		t.Fatal(err)
	}
	e.Reconcile(ctx)
	must(e.RecordQuality("a", Quality{Verdict: VerdictWrong, Source: "owner", Note: "leaked " + canary}))
	deny := intent("deny", "acct")
	deny.Params = map[string]any{"v": 2}
	must(e.Submit(deny))
	must(e.Authorize(ctx, "deny")) // denial reason carries the canary

	data := must(st.ReadAll())
	if bytes.Contains(data, []byte(canary)) {
		t.Fatalf("canary written to the journal:\n%s", data)
	}
	if n := bytes.Count(data, []byte("[redacted]")); n < 7 {
		t.Fatalf("expected redaction markers in every field, found %d", n)
	}
	// Replay of the redacted journal reaches the same state.
	e2 := mustOpen(t, &MemStore{data: data}, canaryPolicy{}, canaryExec{})
	if !reflect.DeepEqual(e2.List(), e.List()) {
		t.Fatal("replay of redacted journal differs from live state")
	}
}

func TestOP2SameEffectUnderNewIDWaitsForEvidence(t *testing.T) {
	svc := newService()
	svc.mode = func(k string) execMode {
		if k == "pay-1#1" {
			return modeDropAck
		}
		return modeOK
	}
	svc.knows = func(string) bool { return false }
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	first := intent("pay-1", "bank")
	must(e.Submit(first))
	must(e.Authorize(ctx, "pay-1"))
	must(e.Dispatch(ctx, "pay-1")) // outcome unknown

	again := first
	again.ID, again.GoalID, again.Origin = "pay-2", "goal-retry", "agent"
	must(e.Submit(again))
	must(e.Authorize(ctx, "pay-2"))
	if _, err := e.Dispatch(ctx, "pay-2"); !errors.Is(err, ErrUnreconciled) {
		t.Fatalf("same effect under new ID: err = %v, want ErrUnreconciled", err)
	}
	// A different effect on the same account is not held up.
	other := intent("pay-3", "bank")
	other.Params = map[string]any{"amount": 7}
	must(e.Submit(other))
	must(e.Authorize(ctx, "pay-3"))
	if st := must(e.Dispatch(ctx, "pay-3")); st.State != Succeeded {
		t.Fatalf("different effect: %s", st.State)
	}
	if svc.effectCount("pay-2") != 0 {
		t.Fatal("duplicate went out")
	}
	// Once evidence resolves the first, a deliberate repeat may go.
	must(e.Resolve("pay-1", 1, Outcome{Result: ResultSucceeded, Evidence: "statement"}, "owner"))
	if st := must(e.Dispatch(ctx, "pay-2")); st.State != Succeeded {
		t.Fatalf("after evidence: %s", st.State)
	}
}

// blockingPolicy blocks every dispatch-phase check until released.
type blockingPolicy struct {
	entered chan struct{}
	release chan struct{}
}

func (p *blockingPolicy) Check(_ context.Context, phase Phase, _ Intent) error {
	if phase == PhaseDispatch {
		p.entered <- struct{}{}
		<-p.release
	}
	return nil
}

func TestOP6HungPolicyCheckDoesNotDelayStop(t *testing.T) {
	svc := newService()
	p := &blockingPolicy{entered: make(chan struct{}), release: make(chan struct{})}
	e := mustOpen(t, &MemStore{}, p, svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	done := make(chan error)
	go func() {
		_, err := e.Dispatch(ctx, "a")
		done <- err
	}()
	<-p.entered

	stopped := make(chan struct{})
	go func() { must(e.Stop(ctx)); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked behind a policy check")
	}
	close(p.release)
	if err := <-done; !errors.Is(err, ErrStopped) {
		t.Fatalf("dispatch after STOP during its check: err = %v, want ErrStopped", err)
	}
	if svc.executeCount() != 0 {
		t.Fatal("executor ran after STOP")
	}
}

// revokingPolicy revokes the grant for "a" the first time it checks "a" at
// dispatch, and journals an unrelated change while doing so, as a concurrent
// grant-change intent would.
type revokingPolicy struct {
	*testPolicy
	e    *Engine
	done bool
}

func (p *revokingPolicy) Check(ctx context.Context, phase Phase, in Intent) error {
	err := p.testPolicy.Check(ctx, phase, in)
	if phase == PhaseDispatch && in.ID == "a" && !p.done {
		p.done = true
		p.revoke("a", true)
		g := Intent{ID: "g", Origin: "owner-sms", Account: BrokerAccount, Action: ActionGrantRevoke, Executor: "svc"}
		if _, serr := p.e.Submit(g); serr != nil {
			return serr
		}
	}
	return err
}

func TestOP3ChangeDuringCheckForcesRecheck(t *testing.T) {
	svc := newService()
	p := &revokingPolicy{testPolicy: newPolicy()}
	e := mustOpen(t, &MemStore{}, p, svc)
	p.e = e
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	// The first check passes, but the journal changed while it ran; the
	// second check sees the revocation.
	if _, err := e.Dispatch(ctx, "a"); !errors.Is(err, ErrRecheck) {
		t.Fatalf("err = %v, want ErrRecheck", err)
	}
	if svc.executeCount() != 0 {
		t.Fatal("executor ran on a stale check")
	}
}

func TestNarrowingIntentsBypassStopAndFence(t *testing.T) {
	svc := newService()
	cs := &crashStore{MemStore: &MemStore{}, budget: 3}
	e := mustOpen(t, cs, newPolicy(), svc)
	rel := Intent{ID: "rel", Origin: "update", Account: BrokerAccount, Action: ActionReleaseActivate, Executor: "svc"}
	must(e.Submit(rel))
	must(e.Authorize(ctx, "rel"))
	e.Dispatch(ctx, "rel") // crash before its observation: broker is fenced after restart

	e2 := mustOpen(t, cs.MemStore, newPolicy(), svc)
	if len(e2.Fenced(BrokerAccount)) == 0 {
		t.Fatal("setup: broker account should be fenced")
	}
	must(e2.Stop(ctx))
	mk := func(id, action, account string) {
		must(e2.Submit(Intent{ID: id, Origin: "owner-sms", Account: account, Action: action,
			Params: map[string]any{"grant": id}, Executor: "svc"}))
		must(e2.Authorize(ctx, id))
	}
	mk("revoke", ActionGrantRevoke, BrokerAccount)
	mk("pause", ActionGrantPause, BrokerAccount)
	mk("lower", ActionBudgetLower, BrokerAccount)
	mk("widen", ActionGrantChange, BrokerAccount)
	mk("fake-revoke", ActionGrantRevoke, "mail") // narrowing only counts on the broker account

	for _, id := range []string{"revoke", "pause", "lower"} {
		if st, err := e2.Dispatch(ctx, id); err != nil || st.State != Succeeded {
			t.Fatalf("%s while stopped and fenced: %+v, %v", id, st, err)
		}
	}
	if _, err := e2.Dispatch(ctx, "widen"); !errors.Is(err, ErrStopped) {
		t.Fatalf("widen while stopped: err = %v", err)
	}
	if _, err := e2.Dispatch(ctx, "fake-revoke"); !errors.Is(err, ErrStopped) {
		t.Fatalf("narrowing action off the broker account: err = %v", err)
	}
	if err := e2.Resume(); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.Dispatch(ctx, "widen"); !errors.Is(err, ErrUnreconciled) {
		t.Fatalf("widen while fenced: err = %v", err)
	}
	// Replay accepts the narrowing dispatches journaled during STOP.
	mustOpen(t, &MemStore{data: must(cs.MemStore.ReadAll())}, newPolicy(), svc)
}

func TestStopReportDoesNotHoldNarrowing(t *testing.T) {
	e := mustOpen(t, &MemStore{}, newPolicy(), newService())
	must(e.Submit(Intent{ID: "revoke", Origin: "owner-sms", Account: BrokerAccount, Action: ActionGrantRevoke, Executor: "svc"}))
	must(e.Authorize(ctx, "revoke"))
	if rep := must(e.Stop(ctx)); len(rep.Held) != 0 {
		t.Fatalf("held = %v", rep.Held)
	}
}

func TestInvalidUTF8LiveMatchesReplay(t *testing.T) {
	st := &MemStore{}
	svc := newService()
	e := mustOpen(t, st, newPolicy(), svc)
	in := intent("a", "acct")
	in.Params = map[string]any{"s": "bad\xffbyte"}
	must(e.Submit(in))
	if _, err := e.Submit(in); err != nil {
		t.Fatalf("resubmit: %v", err)
	}
	must(e.Authorize(ctx, "a"))
	must(e.Dispatch(ctx, "a"))
	must(e.RecordQuality("a", Quality{Verdict: VerdictGood, Source: "owner", Note: "ok\xfe"}))
	e2 := mustOpen(t, &MemStore{data: must(st.ReadAll())}, newPolicy(), svc)
	if !reflect.DeepEqual(e2.List(), e.List()) {
		t.Fatalf("live %+v\nreplay %+v", e.List(), e2.List())
	}
}

func TestSizeLimits(t *testing.T) {
	e := mustOpen(t, &MemStore{}, newPolicy(), newService())
	big := intent("big", "acct")
	big.Params = map[string]any{"blob": strings.Repeat("x", MaxIntentBytes)}
	if _, err := e.Submit(big); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized intent: err = %v", err)
	}
	must(e.Submit(intent("a", "acct")))
	note := strings.Repeat("n", MaxTextBytes*3)
	st := must(e.RecordQuality("a", Quality{Verdict: VerdictGood, Source: "owner", Note: note}))
	if len(st.Quality.Note) > MaxTextBytes+200 || !strings.Contains(st.Quality.Note, "sha256") {
		t.Fatalf("note not clipped: %d bytes", len(st.Quality.Note))
	}
}
