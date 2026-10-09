package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recalltool"
)

// REQ: CAP-3, CH-12
// W3-forget-b2c-f1: a take-back carryAgent carries is bounded and visible
// (F1-1, F1-2), and one a restored forget log replays is told (F1-3).

// carryClock is the fake clock carryAgent sleeps on: each wait adds to
// elapsed, and at returns what the owner was told as each pass began.
type carryClock struct {
	mu      sync.Mutex
	elapsed time.Duration
	// at, per wait, the elapsed time before it and the texts so far.
	at    []time.Duration
	texts [][]string
}

// sleep for r: before each wait, it records the texts and runs step,
// which may change recall; it stops the loop once stop says so.
func (c *carryClock) sleep(r *forgetRig, step func(elapsed time.Duration) bool) func(context.Context, time.Duration) bool {
	return func(_ context.Context, d time.Duration) bool {
		r.mu.Lock()
		texts := append([]string(nil), r.texts...)
		r.mu.Unlock()
		c.mu.Lock()
		c.at, c.texts = append(c.at, c.elapsed), append(c.texts, texts)
		el := c.elapsed
		c.elapsed += d
		c.mu.Unlock()
		return step(el)
	}
}

func count(texts []string, s string) int {
	n := 0
	for _, t := range texts {
		if t == s {
			n++
		}
	}
	return n
}

// F1-1 (a): a transient error is silent until the bound, told once at it
// and never after; the take-back stays owed and retried, and a later
// success is told done once.
func TestForgetItem2CarriedPastTheBoundIsToldOnce(t *testing.T) {
	w := &fakeWork{worked: true, ok: true, err: errors.New("disk full")}
	r, in := owedRig(t, w)
	c := &carryClock{}
	ended := make(chan struct{})
	r.f.sleep = c.sleep(r, func(el time.Duration) bool {
		if el >= 2*forgetCarryBound {
			w.mu.Lock()
			w.err = nil
			w.mu.Unlock()
		}
		return true
	})
	r.f.retried = func() { close(ended) }
	if out := r.f.Execute(context.Background(), in, 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", out)
	}
	within(t, ended)
	for i, el := range c.at {
		want := 0
		if el >= forgetCarryBound {
			want = 1
		}
		if got := count(c.texts[i], forgetAgentStillHeld); got != want {
			t.Fatalf("at %v: told %d bound texts, want %d: %q", el, got, want, c.texts[i])
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.Join(r.texts, "|") != strings.Join([]string{forgetAgentNotTaken, forgetAgentStillHeld, forgetAgentDone}, "|") {
		t.Fatalf("told %q", r.texts)
	}
	if len(w.backs) != 1 {
		t.Fatalf("took back %v", w.backs)
	}
}

// F1-1 (b): an error retrying cannot fix (no agent machine's lineage) is
// told at once, in place of the not-saved text, and only once over later
// passes and past the bound.
func TestForgetItem2CarriedWithAPermanentErrorIsToldAtOnce(t *testing.T) {
	w := &fakeWork{worked: true, ok: true}
	r, in := owedRig(t, w)
	var mu sync.Mutex
	gone := true
	r.f.agent.Store(&forgetAgent{work: w, lineage: func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if gone {
			return "", errors.New("vm: no machine agent")
		}
		return "agent.l1", nil
	}})
	c := &carryClock{}
	ended := make(chan struct{})
	r.f.sleep = c.sleep(r, func(el time.Duration) bool {
		if el >= 2*forgetCarryBound {
			mu.Lock()
			gone = false
			mu.Unlock()
		}
		return true
	})
	r.f.retried = func() { close(ended) }
	r.f.Execute(context.Background(), in, 1)
	within(t, ended)
	if len(c.texts) == 0 || strings.Join(c.texts[0], "|") != forgetAgentStillHeld {
		t.Fatalf("first pass: told %q", c.texts)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.Join(r.texts, "|") != forgetAgentStillHeld+"|"+forgetAgentDone {
		t.Fatalf("told %q", r.texts)
	}
}

// CH-12: the bound text names the state and a next step, and no task.
func TestForgetItem2BoundTextSaysWhatRemains(t *testing.T) {
	s := forgetAgentStillHeld
	if !strings.HasPrefix(s, "Not taken back yet:") || !strings.Contains(s, "still holds") ||
		!strings.Contains(s, "STATUS") || len(s) > 160 || !gsm7(s) {
		t.Fatalf("%q", s)
	}
	for _, n := range []int{1, 2} {
		line := carryNote(n)
		if !strings.HasPrefix(line, "Forget:") || len(line) > 160 || !gsm7(line) {
			t.Fatalf("%q", line)
		}
	}
}

// F1-2: STATUS has one line while a take-back is carried, with its count
// and no task words, and none once it is done.
func TestForgetCarriedTakeBackShowsOnStatus(t *testing.T) {
	w := &fakeWork{worked: true, ok: true, err: errors.New("disk full")}
	r, in := owedRigText(t, w, "pay the gas bill")
	if r.f.Note() != "" {
		t.Fatalf("before: %q", r.f.Note())
	}
	step, asleep, ended := make(chan bool), make(chan struct{}), make(chan struct{})
	r.f.sleep = func(context.Context, time.Duration) bool { asleep <- struct{}{}; return <-step }
	r.f.retried = func() { close(ended) }
	r.f.Execute(context.Background(), in, 1)
	within(t, asleep)
	if got := r.f.Note(); got != carryNote(1) || strings.Contains(got, "gas") {
		t.Fatalf("carried: %q", got)
	}
	w.mu.Lock()
	w.err = nil
	w.mu.Unlock()
	give(t, step, true)
	within(t, ended)
	if got := r.f.Note(); got != "" {
		t.Fatalf("done: %q", got)
	}
}

// restoredRig is a rig with an owed file, whose forget log, restored,
// holds a take-back from since.
func restoredRig(t *testing.T, w *fakeWork, store *countStore, since time.Time) *forgetRig {
	t.Helper()
	r := restartRig(t, store)
	r.f.owedAtStart = r.f.owed.goals()
	r.withAgent(w)
	r.f.restored = []time.Time{since}
	return r
}

// F1-3: a take-back a restored log replays is taken back and told once
// recall says done, owed before the take-back.
func TestForgetRestoredTakeBackIsToldOnce(t *testing.T) {
	since := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	w := &fakeWork{worked: true, ok: true}
	store := &countStore{}
	cw := &crashWork{fakeWork: w, store: store}
	r := restoredRig(t, w, store, since)
	r.f.agent.Store(&forgetAgent{work: cw, lineage: func() (string, error) { return "agent.l1", nil }})
	for range 2 {
		r.f.finishOwed(context.Background())
		r.f.resumeAgent(context.Background())
	}
	if len(w.backs) != 1 || strings.Join(r.texts, "|") != forgetAgentDone || len(r.f.owed.goals()) != 0 {
		t.Fatalf("took back %v, told %q, owed %v", w.backs, r.texts, r.f.owed.goals())
	}
	var owedAt bool
	for g, e := range owedIn(t, cw.at) {
		if at, ok := forgetSince(g); ok && at.Equal(since) && e.Agent && e.Taking {
			owedAt = true
		}
	}
	if !owedAt {
		t.Fatalf("not owed at the take-back: %q", cw.at)
	}
	// The next boot: recall holds it done and the log still has it.
	again := restoredRig(t, w, store, since)
	for range 2 {
		again.f.finishOwed(context.Background())
		again.f.resumeAgent(context.Background())
	}
	if len(w.backs) != 1 || len(again.texts) != 0 {
		t.Fatalf("next boot: took back %v, told %q", w.backs, again.texts)
	}
}

// F1-3: a crash after the replayed take-back and before its done text is
// told after the restart, once.
func TestForgetRestoredTakeBackCrashBeforeTheTextIsToldAfterARestart(t *testing.T) {
	since := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	w := &fakeWork{worked: true, ok: true}
	store := &countStore{}
	cw := &crashWork{fakeWork: w, store: store}
	r := restoredRig(t, w, store, since)
	r.f.agent.Store(&forgetAgent{work: cw, lineage: func() (string, error) { return "agent.l1", nil }})
	r.f.resumeAgent(context.Background())
	st := &countStore{}
	if err := st.Save(cw.at); err != nil { // the crash: the file as at the take-back
		t.Fatal(err)
	}
	again := restoredRig(t, w, st, since)
	for range 2 {
		again.f.finishOwed(context.Background())
		again.f.resumeAgent(context.Background())
	}
	if len(w.backs) != 1 || strings.Join(again.texts, "|") != forgetAgentDone || len(again.f.owed.goals()) != 0 {
		t.Fatalf("after the crash: took back %v, told %q, owed %v", w.backs, again.texts, again.f.owed.goals())
	}
}

// F1-3: a replayed take-back recall says is not done yet is not told
// done; recall's report tells it once.
func TestForgetRestoredTakeBackNotDoneIsToldOnRecallsReport(t *testing.T) {
	since := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	w := &fakeWork{worked: true, ok: true}
	w.setState(since, recalltool.TakeBackOwed)
	r := restoredRig(t, w, &countStore{}, since)
	r.f.resumeAgent(context.Background())
	if len(w.backs) != 1 || len(r.texts) != 0 {
		t.Fatalf("took back %v, told %q", w.backs, r.texts)
	}
	w.setState(since, recalltool.TakeBackDone)
	r.f.agentTakenBack(context.Background(), since)
	r.f.agentTakenBack(context.Background(), since)
	if strings.Join(r.texts, "|") != forgetAgentDone {
		t.Fatalf("told %q", r.texts)
	}
}

// F1-3: a replayed take-back that is not saved is carried as item 2's
// are (F1-1), and told done once it is.
func TestForgetRestoredTakeBackNotSavedIsCarried(t *testing.T) {
	since := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	w := &fakeWork{worked: true, ok: true, err: errors.New("disk full")}
	r := restoredRig(t, w, &countStore{}, since)
	step, asleep, ended := make(chan bool), make(chan struct{}), make(chan struct{})
	r.f.sleep = func(context.Context, time.Duration) bool { asleep <- struct{}{}; return <-step }
	r.f.retried = func() { close(ended) }
	r.f.resumeAgent(context.Background())
	within(t, asleep)
	if r.f.Note() != carryNote(1) {
		t.Fatalf("not carried: %q", r.f.Note())
	}
	r.f.resumeAgent(context.Background()) // recall opens again meanwhile
	w.mu.Lock()
	w.err = nil
	w.mu.Unlock()
	give(t, step, true)
	within(t, ended)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(w.backs) != 1 || strings.Join(r.texts, "|") != forgetAgentDone {
		t.Fatalf("took back %v, told %q", w.backs, r.texts)
	}
}

// F1-3: a replayed take-back an item 2 of this box already carries is
// left to it, so it is neither run twice nor told twice.
func TestForgetRestoredTakeBackAnItem2CarriesIsLeftToIt(t *testing.T) {
	since := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	w := &fakeWork{worked: true, ok: true}
	r := restoredRig(t, w, &countStore{}, since)
	r.f.carrying = map[string]bool{grants.ForgetAgentID(fmt.Sprintf("1.1.%d", since.UnixNano()), "owner:a"): true}
	r.f.resumeAgent(context.Background())
	if len(w.backs) != 0 || len(r.texts) != 0 {
		t.Fatalf("took back %v, told %q", w.backs, r.texts)
	}
}
