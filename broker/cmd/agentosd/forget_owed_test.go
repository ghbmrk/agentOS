package main

import (
	"context"
	"errors"
	"strings"
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
	r := newForgetRig(t)
	r.withAgent(w)
	r.task("owner:a", "pay the gas bill", r.now.Add(-time.Hour), viaSMS)
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
func TestForgetItem2NotSavedIsTriedAgain(t *testing.T) {
	w := &fakeWork{worked: true, ok: true, err: errors.New("disk full")}
	r, in := owedRig(t, w)
	step, ended := make(chan bool), make(chan struct{})
	var waits []time.Duration
	r.f.sleep = func(_ context.Context, d time.Duration) bool { waits = append(waits, d); return <-step }
	r.f.retried = func() { close(ended) }
	out := r.f.Execute(context.Background(), in, 1)
	if out.Result != journal.ResultSucceeded || len(r.texts) != 1 || r.texts[0] != forgetAgentNotTaken {
		t.Fatalf("%+v %q", out, r.texts)
	}
	step <- true // still not saved
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
