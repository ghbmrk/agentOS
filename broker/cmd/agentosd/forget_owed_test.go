package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recalltool"
)

// REQ: CAP-3, CH-12

// W3-forget-b2c (#327 UX R-1, R-2): an approved item 2 that cannot be
// taken back now (no agent machine, recall off, or the request not
// saved) is owed: the journal holds it, the owner is told what remains,
// and it is taken back once it can be, once, with the done text.

// owedRig is a rig whose approved item 2 is about to run with item 1
// approved.
func owedRig(t *testing.T, w *fakeWork) (*forgetRig, journal.Intent) {
	return owedRigText(t, w, "pay the gas bill")
}

// owedRigText is owedRig with the task's text.
func owedRigText(t *testing.T, w *fakeWork, text string) (*forgetRig, journal.Intent) {
	r := newForgetRig(t)
	r.withAgent(w)
	r.task("owner:a", text, r.now.Add(-time.Hour), viaSMS)
	r.say("FORGET LAST")
	if len(r.gate.got) != 2 {
		t.Fatalf("intents %+v", r.gate.got)
	}
	r.gate.st = map[string]journal.State{r.gate.got[0].ID: journal.Succeeded}
	r.texts = nil
	return r, r.gate.got[1]
}

// nextBoot is a restart: the in-memory queue is gone, the journal holds
// item 2 as it ran, and recall opens.
func (r *forgetRig) nextBoot(in journal.Intent, out journal.Outcome) {
	r.gate.st[in.ID] = map[journal.Result]journal.State{
		journal.ResultSucceeded: journal.Succeeded, journal.ResultNotApplied: journal.NotApplied}[out.Result]
	r.f.mu.Lock()
	r.f.interrupted = nil
	r.f.mu.Unlock()
	r.texts = nil
	r.f.resumeAgent(context.Background())
}

func TestForgetItem2OwedWithNoAgentMachine(t *testing.T) {
	w := &fakeWork{worked: true, ok: true}
	r, in := owedRig(t, w)
	r.f.agent.Store(nil) // the agent machine did not open on this boot
	out := r.f.Execute(context.Background(), in, 1)
	if out.Result != journal.ResultSucceeded || len(r.texts) != 1 || r.texts[0] != forgetAgentNoAgent {
		t.Fatalf("%+v %q", out, r.texts)
	}
	r.f.resumeAgent(context.Background()) // recall opens; still no agent
	if len(w.backs) != 0 {
		t.Fatalf("took back %v with no agent", w.backs)
	}
	r.withAgent(w)
	r.nextBoot(in, out)
	if len(w.backs) != 1 || !w.asked[0] || len(r.texts) != 1 || r.texts[0] != forgetAgentDone {
		t.Fatalf("next boot: took back %v, told %q", w.backs, r.texts)
	}
	r.texts = nil
	r.f.resumeAgent(context.Background())
	if len(w.backs) != 1 || len(r.texts) != 0 {
		t.Fatalf("repeated: %v %q", w.backs, r.texts)
	}
}

func TestForgetItem2OwedWithRecallOff(t *testing.T) {
	w := &fakeWork{worked: true, ok: true, err: recalltool.ErrNotOpen}
	r, in := owedRig(t, w)
	out := r.f.Execute(context.Background(), in, 1) // whenOpen nil: recall off
	if out.Result != journal.ResultSucceeded || len(r.texts) != 1 || r.texts[0] != forgetAgentNotOpen {
		t.Fatalf("%+v %q", out, r.texts)
	}
	w.mu.Lock()
	w.err = nil
	w.mu.Unlock()
	r.nextBoot(in, out)
	if len(w.backs) != 1 || len(r.texts) != 1 || r.texts[0] != forgetAgentDone {
		t.Fatalf("next boot: took back %v, told %q", w.backs, r.texts)
	}
}

// One not saved is tried again with backoff until it is, and the owner
// hears once that it is not yet and once that it is done; while it is
// tried, recall's open does not take it back too.
//
// L3 on #522 (flaky on main): the retry's take-back ran on its own
// goroutine after the first step, unordered with the test clearing w.err,
// so the first retry could already succeed (recall's open then saw it
// Handled, or the second step had no receiver and hung). Each step now
// waits until carryAgent is back in sleep, so that pass has run.
func TestForgetItem2NotSavedIsTriedAgain(t *testing.T) {
	w := &fakeWork{worked: true, ok: true, err: errors.New("disk full")}
	r, in := owedRig(t, w)
	step, asleep, ended := make(chan bool), make(chan struct{}), make(chan struct{})
	var waits []time.Duration
	r.f.sleep = func(_ context.Context, d time.Duration) bool {
		waits = append(waits, d)
		asleep <- struct{}{}
		return <-step
	}
	r.f.retried = func() { close(ended) }
	out := r.f.Execute(context.Background(), in, 1)
	if out.Result != journal.ResultSucceeded || len(r.texts) != 1 || r.texts[0] != forgetAgentNotTaken {
		t.Fatalf("%+v %q", out, r.texts)
	}
	<-asleep
	step <- true // still not saved
	<-asleep     // that pass's take-back has failed
	r.gate.st[in.ID] = journal.Succeeded
	w.mu.Lock()
	w.err = nil
	w.mu.Unlock()
	r.f.resumeAgent(context.Background()) // recall opens meanwhile
	w.mu.Lock()
	if len(w.backs) != 0 {
		t.Fatalf("recall's open took it back during the retries: %v", w.backs)
	}
	w.mu.Unlock()
	step <- true
	<-ended
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(w.backs) != 1 || !w.asked[0] || len(r.texts) != 2 || r.texts[1] != forgetAgentDone {
		t.Fatalf("took back %v, told %q", w.backs, r.texts)
	}
	if len(waits) != 2 || waits[1] <= waits[0] {
		t.Fatalf("waits %v", waits)
	}
}

// A shutdown during the retries leaves it to the next boot, which takes
// it back once.
func TestForgetItem2NotSavedOutlivesARestart(t *testing.T) {
	w := &fakeWork{worked: true, ok: true, err: errors.New("disk full")}
	r, in := owedRig(t, w)
	ended := make(chan struct{})
	r.f.sleep = func(context.Context, time.Duration) bool { return false } // shutdown
	r.f.retried = func() { close(ended) }
	out := r.f.Execute(context.Background(), in, 1)
	<-ended
	w.mu.Lock()
	w.err = nil
	w.mu.Unlock()
	r.nextBoot(in, out)
	if len(w.backs) != 1 || len(r.texts) != 1 || r.texts[0] != forgetAgentDone {
		t.Fatalf("next boot: took back %v, told %q", w.backs, r.texts)
	}
}

// CH-12: each owed text says what remains and that it will be done, never
// ends in "Nothing taken back" and fits one GSM-7 segment. The no-agent
// one names STATUS, whose agent line says why; recall off has no STATUS
// line (LateExecutor.Status), so that one names no step.
func TestForgetItem2OwedTextsSayWhatRemains(t *testing.T) {
	for _, s := range []string{forgetAgentNoAgent, forgetAgentNotOpen, forgetAgentNotTaken} {
		if !strings.HasPrefix(s, "Not taken back yet:") || !strings.Contains(s, "text you") || len(s) > 160 || !gsm7(s) {
			t.Fatalf("%d %q", len(s), s)
		}
	}
	if !strings.HasSuffix(forgetAgentNoAgent, "Send STATUS to see why.") || strings.Contains(forgetAgentNotOpen, "STATUS") {
		t.Fatalf("steps: %q, %q", forgetAgentNoAgent, forgetAgentNotOpen)
	}
}

// Security 4a on #427 (CAP-3): an owed take-back is in the forget log
// once the owner is told it will be done, so a backup restored before it
// was done still takes the agent back, once.
func TestForgetItem2OwedSurvivesARestore(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(*forgetRig, *fakeWork)
	}{
		{"no agent machine", func(r *forgetRig, _ *fakeWork) { r.f.agent.Store(nil) }},
		{"recall off", func(_ *forgetRig, w *fakeWork) { w.err = recalltool.ErrNotOpen }},
		{"recall not open yet", func(r *forgetRig, w *fakeWork) { w.err = recalltool.ErrNotOpen; r.f.whenOpen = func() {} }},
		{"not saved", func(r *forgetRig, w *fakeWork) {
			w.err = errors.New("disk full")
			r.f.sleep = func(context.Context, time.Duration) bool { return false }
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := &fakeWork{worked: true, ok: true}
			r, in := owedRig(t, w)
			fl := &fakeForgetLog{}
			r.f.forgetLog = fl
			c.setup(r, w)
			since, _ := forgetSince(in.ID)
			if out := r.f.Execute(context.Background(), in, 1); out.Result != journal.ResultSucceeded {
				t.Fatalf("%+v", out)
			}
			if len(fl.back) != 1 || !fl.back[0].Equal(since) {
				t.Fatalf("logged %v %v", fl.got, fl.back)
			}
			// The restore: the journal is the backup's, without item 2;
			// the forget log's take-back is replayed once recall opens.
			after := newForgetRig(t)
			w2 := &fakeWork{worked: true, ok: true}
			after.withAgent(w2)
			after.f.restored = fl.back
			after.f.resumeAgent(context.Background())
			after.f.resumeAgent(context.Background())
			if len(w2.backs) != 1 || !w2.backs[0].Equal(since) || !w2.asked[0] {
				t.Fatalf("after the restore: took back %v %v", w2.backs, w2.asked)
			}
		})
	}
}

// W3-forget-b2c-2 (UX-182-3; L3 on #425): item 2's done text is owed on
// disk from the moment its take-back returns nil until it sends, so a
// down modem or a restart does not lose it; a promise is not owed.

// agentOwed is an owed rig whose done texts are kept in store and sent
// over d; sleep blocks on step and reports each wait on asleep.
type agentOwed struct {
	*forgetRig
	in     journal.Intent
	store  *countStore
	d      *downTell
	step   chan bool
	asleep chan struct{}
	told   chan struct{}
}

func newAgentOwed(t *testing.T, w *fakeWork, text string) *agentOwed {
	t.Helper()
	r, in := owedRigText(t, w, text)
	a := &agentOwed{forgetRig: r, in: in, store: &countStore{}, d: &downTell{},
		step: make(chan bool), asleep: make(chan struct{}, 16), told: make(chan struct{}, 4)}
	owed, err := openForgetOwed(a.store)
	if err != nil {
		t.Fatal(err)
	}
	r.f.owed, r.f.tell = owed, a.d.tell
	r.f.sleep = func(context.Context, time.Duration) bool { a.asleep <- struct{}{}; return <-a.step }
	r.f.toldLater = func() { a.told <- struct{}{} }
	return a
}

// within waits for ch, and give sends v on it, failing the test after 10s
// rather than hanging.
func within[T any](t *testing.T, ch chan T) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out")
	}
}

func give[T any](t *testing.T, ch chan T, v T) {
	t.Helper()
	select {
	case ch <- v:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out")
	}
}

// entries reads the owed file as saved.
func (a *agentOwed) entries(t *testing.T) map[string]owedForget {
	t.Helper()
	b, _ := a.store.Load()
	m := map[string]owedForget{}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestForgetItem2DoneTextNotSentStaysOwed(t *testing.T) {
	w := &fakeWork{worked: true, ok: true}
	a := newAgentOwed(t, w, "pay the gas bill")
	if out := a.f.Execute(context.Background(), a.in, 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", out)
	}
	within(t, a.asleep) // tellLater waits to send again
	if e, ok := a.entries(t)[a.in.ID]; !ok || !e.Agent {
		t.Fatalf("not owed on disk: %v", a.entries(t))
	}
	a.d.setUp()
	give(t, a.step, true)
	within(t, a.told)
	if got := a.d.got(); len(got) != 1 || got[0] != forgetAgentDone {
		t.Fatalf("sent %q", got)
	}
	if len(a.entries(t)) != 0 {
		t.Fatalf("still owed after the send: %v", a.entries(t))
	}
}

// A restart with item 2's done text still owed (the modem was down until
// shutdown) texts it once at attach and clears it, with no agent machine
// and recall not open: the entry exists only after a nil take-back.
func TestForgetItem2DoneTextOwedAtShutdownIsToldAfterARestart(t *testing.T) {
	w := &fakeWork{worked: true, ok: true}
	a := newAgentOwed(t, w, "pay the gas bill")
	a.f.Execute(context.Background(), a.in, 1)
	within(t, a.asleep)
	give(t, a.step, false) // shutdown
	within(t, a.told)
	again := restart(t, &a.store.mem, nil)
	if again.f.agent.Load() != nil {
		t.Fatal("rig has an agent machine")
	}
	again.f.finishOwed(context.Background())
	if strings.Join(again.texts, "|") != forgetAgentDone {
		t.Fatalf("after the restart: %q", again.texts)
	}
	third := restart(t, &a.store.mem, nil)
	third.f.finishOwed(context.Background())
	if len(third.texts) != 0 || len(third.f.owed.goals()) != 0 {
		t.Fatalf("told again: %q, owed %v", third.texts, third.f.owed.goals())
	}
}

// Item 2's done text and item 1's for the same goal are owed apart: one
// told, or one overwritten, does not drop the other.
func TestForgetBothItemsOwedForOneGoalAreBothTold(t *testing.T) {
	w := &fakeWork{worked: true, ok: true}
	a := newAgentOwed(t, w, "pay the gas bill")
	a.f.Execute(context.Background(), a.in, 1) // item 2 runs first
	within(t, a.asleep)
	a.f.Execute(context.Background(), a.gate.got[0], 1) // then item 1
	within(t, a.asleep)
	give(t, a.step, false)
	give(t, a.step, false)
	within(t, a.told)
	within(t, a.told)
	again := restart(t, &a.store.mem, map[string]bool{"owner:a": true})
	again.f.finishOwed(context.Background())
	got := strings.Join(again.texts, "|")
	if len(again.texts) != 2 || !strings.Contains(got, forgetAgentDone) || !strings.Contains(got, "is forgotten now.") {
		t.Fatalf("after the restart: %q", again.texts)
	}
}

// On ErrCarried recall's Retry owns the done text (recalltool TakenBack):
// no entry is made or kept, and this path does not send it, so it is not
// doubled. Through carryAgent too.
func TestForgetItem2CarriedByRecallOwesNothingHere(t *testing.T) {
	for _, viaRetry := range []bool{false, true} {
		w := &fakeWork{worked: true, ok: true, err: recalltool.ErrCarried}
		if viaRetry {
			w.err = errors.New("disk full")
		}
		a := newAgentOwed(t, w, "pay the gas bill")
		a.d.setUp()
		// Left by an earlier run: dropped.
		if err := a.f.owed.owe(a.in.ID, owedForget{Agent: true}); err != nil {
			t.Fatal(err)
		}
		ended := make(chan struct{})
		a.f.retried = func() { close(ended) }
		a.f.Execute(context.Background(), a.in, 1)
		want := forgetAgentNotYet
		if viaRetry {
			want = forgetAgentNotTaken
			within(t, a.asleep)
			w.mu.Lock()
			w.err = recalltool.ErrCarried
			w.mu.Unlock()
			give(t, a.step, true)
			within(t, ended)
		}
		if got := a.d.got(); len(got) != 1 || got[0] != want {
			t.Fatalf("retry %v: sent %q", viaRetry, got)
		}
		if len(a.entries(t)) != 0 {
			t.Fatalf("retry %v: owed %v", viaRetry, a.entries(t))
		}
	}
}

// One recall recorded but has not done (Handled true, owed in recall) is
// never told done by this package, at a restart or recall's open.
func TestForgetItem2RecordedNotDoneIsNotToldDone(t *testing.T) {
	w := &fakeWork{worked: true, ok: true, recorded: true}
	a := newAgentOwed(t, w, "pay the gas bill")
	a.d.setUp()
	a.gate.st[a.in.ID] = journal.Succeeded // ran in the last boot
	again := restart(t, &a.store.mem, nil)
	again.f.gate.Store(&pauseGateBox{a.gate})
	again.withAgent(w)
	again.f.finishOwed(context.Background())
	again.f.resumeAgent(context.Background())
	if len(again.texts) != 0 || len(w.backs) != 0 {
		t.Fatalf("told %q, took back %v", again.texts, w.backs)
	}
}

// The b4 order for item 2: the owed entry is on disk when the done text is
// sent, and dropped only after, from agentBack and from carryAgent.
func TestForgetItem2DoneTextIsOwedOnDiskAtTheSend(t *testing.T) {
	for _, viaRetry := range []bool{false, true} {
		w := &fakeWork{worked: true, ok: true}
		if viaRetry {
			w.err = errors.New("disk full")
		}
		a := newAgentOwed(t, w, "pay the gas bill")
		var atSend []bool
		a.f.tell = func(s string) error {
			if s == forgetAgentDone {
				atSend = append(atSend, a.store.holds(a.in.ID))
			}
			return nil
		}
		ended := make(chan struct{})
		a.f.retried = func() { close(ended) }
		a.f.Execute(context.Background(), a.in, 1)
		if viaRetry {
			within(t, a.asleep)
			w.mu.Lock()
			w.err = nil
			w.mu.Unlock()
			give(t, a.step, true)
			within(t, ended)
		}
		if len(atSend) != 1 || !atSend[0] {
			t.Fatalf("retry %v: owed on disk at the send: %v", viaRetry, atSend)
		}
		if len(a.entries(t)) != 0 {
			t.Fatalf("retry %v: still owed after the send: %v", viaRetry, a.entries(t))
		}
	}
}

// The owed file holds goal IDs, times and counts only: a canary in the
// task's text never reaches it.
func TestForgetItem2OwedHoldsNoTaskText(t *testing.T) {
	w := &fakeWork{worked: true, ok: true}
	a := newAgentOwed(t, w, "CANARY-b2c2 pay the gas bill")
	a.f.Execute(context.Background(), a.in, 1)
	within(t, a.asleep)
	b, _ := a.store.Load()
	if len(b) == 0 || strings.Contains(string(b), "CANARY") || strings.Contains(string(b), "gas") {
		t.Fatalf("owed file %q", b)
	}
	give(t, a.step, false)
	within(t, a.told)
}

// -race: item 2's done text owed and sent again while the owner texts
// FORGET and recall's open runs resumeAgent.
func TestForgetItem2OwedUnderRace(t *testing.T) {
	w := &fakeWork{worked: true, ok: true}
	a := newAgentOwed(t, w, "pay the gas bill")
	a.gate.mu.Lock()
	a.gate.st[a.in.ID] = journal.InFlight
	a.gate.mu.Unlock()
	a.f.sleep = func(ctx context.Context, d time.Duration) bool { return sleepCtx(ctx, time.Millisecond) }
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, run := range []func(){
		func() { a.f.Text(context.Background(), "FORGET", true) },
		func() { a.f.resumeAgent(context.Background()) },
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					run()
				}
			}
		}()
	}
	a.f.Execute(context.Background(), a.in, 1)
	time.Sleep(5 * time.Millisecond)
	a.d.setUp()
	within(t, a.told)
	close(stop)
	wg.Wait()
	if got := a.d.got(); len(got) != 1 || got[0] != forgetAgentDone {
		t.Fatalf("sent %q", got)
	}
	if len(a.entries(t)) != 0 {
		t.Fatalf("still owed: %v", a.entries(t))
	}
}

// Security 4a on #528, P1 (mutant S2b): item 1's retry saves the owed
// entry again on every pass until the save holds, not on the first pass
// only; two failed owed saves and two failed forgets still leave the done
// text on disk at the send.
func TestAnOwedSaveIsRetriedOnEveryPassUntilItHolds(t *testing.T) {
	store := &countStore{fail: 2} // Execute's owed save and the first pass's fail
	r := restartRig(t, store)
	r.fail = 3 // Execute's forget and two passes fail (none untombstoned first)
	var atSend []bool
	r.f.tell = func(string) error { atSend = append(atSend, store.holds("owner:a")); return nil }
	done := make(chan struct{})
	r.f.retried = func() { close(done) }
	if out := r.f.Execute(context.Background(), forgetIntent("1.1.1", "owner:a"), 1); out.Evidence != "forgetting; retrying" {
		t.Fatalf("execute: %+v", out)
	}
	within(t, done)
	if len(atSend) != 1 || !atSend[0] {
		t.Fatalf("owed on disk at the send: %v", atSend)
	}
	if store.holds("owner:a") {
		t.Fatal("still owed after the send")
	}
}
