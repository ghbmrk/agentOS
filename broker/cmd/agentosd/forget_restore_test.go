package main

// REQ: CAP-3, F3-1, F3-2, F3-3, CH-12

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
)

// W3-forget-b2c-f3 (L3 release 3 on #427): an item 1 forget whose
// tombstone held is in the forget log before the owner hears anything of
// it and before retry starts, so a backup restored while it is still
// retrying forgets the task again.

// loggedForget is one forget log append: goal IDs, times and a flag only.
type loggedForget struct {
	goal      string
	at, since time.Time
	agent     bool
}

// lockedForgetLog records the forget log's appends under a lock, as retry
// appends from its own goroutine; fail fails the first fail appends, and
// always fails every one.
type lockedForgetLog struct {
	mu     sync.Mutex
	fail   int
	always bool
	tries  int
	got    []loggedForget
}

func (l *lockedForgetLog) Append(goal string, at, since time.Time, agent bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tries++
	if l.always || l.fail > 0 {
		l.fail--
		return errors.New("vault closed")
	}
	l.got = append(l.got, loggedForget{goal, at, since, agent})
	return nil
}

func (l *lockedForgetLog) entries() []loggedForget {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]loggedForget(nil), l.got...)
}

// count is the appends that held for goal.
func (l *lockedForgetLog) count(goal string) int {
	n := 0
	for _, e := range l.entries() {
		if e.goal == goal {
			n++
		}
	}
	return n
}

const restoreCanary = "pay the gas bill CANARY-f3"

// F3-1: on the retry path the entry is in the log at the moment retry
// starts (its first wait) and at the moment forgetNotSaved is sent; it
// holds the goal and times only, never the task's words. If the early
// append fails, retry's first pass appends it before that pass's forget,
// so it is still in the log when forgetNotSaved is sent.
func TestForgetRetryingIsLoggedBeforeAnyText(t *testing.T) {
	for _, c := range []struct {
		name    string
		logFail int // failed appends before one holds
	}{
		{name: "early append holds"},
		{name: "early append failed", logFail: 1},
	} {
		t.Run(c.name, func(t *testing.T) { retryingIsLogged(t, c.logFail) })
	}
}

func retryingIsLogged(t *testing.T, logFail int) {
	r := newForgetRig(t)
	fl := &lockedForgetLog{fail: logFail}
	r.f.forgetLog = fl
	r.task("owner:a", restoreCanary, r.now.Add(-time.Hour), viaSMS)
	r.fail = 7 // the tombstone holds, then seven failed passes past forgetNotYet
	var atStart, atNotSaved []loggedForget
	started := false
	r.f.sleep = func(_ context.Context, d time.Duration) bool {
		if !started {
			started = true
			atStart = fl.entries()
		}
		r.mu.Lock()
		r.now = r.now.Add(d)
		r.mu.Unlock()
		return true
	}
	inform := r.f.inform
	r.f.inform = func(s string) {
		if s == forgetNotSaved {
			atNotSaved = fl.entries()
		}
		inform(s)
	}
	done := make(chan struct{})
	r.f.retried = func() { close(done) }
	if out := r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", out)
	}
	within(t, done)
	checks := map[string][]loggedForget{"not saved yet": atNotSaved}
	if logFail == 0 {
		checks["retry start"] = atStart
	}
	for name, got := range checks {
		if len(got) != 1 || got[0].goal != "owner:a" || got[0].agent || !got[0].since.IsZero() || got[0].at.IsZero() {
			t.Fatalf("at %s: logged %+v", name, got)
		}
	}
	for _, e := range fl.entries() {
		if s := fmt.Sprintf("%+v", e); strings.Contains(s, "CANARY") || strings.Contains(s, "gas bill") {
			t.Fatalf("task words in the forget log: %s", s)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// CH-12: the done text keeps its wording; the early entry held, so it
	// says a restore won't bring the task back.
	want := forgetNotSaved + "|" + forgetDone(0, false, true)
	if strings.Join(r.texts, "|") != want || fl.count("owner:a") != 1 {
		t.Fatalf("texts %q, logged %+v", r.texts, fl.entries())
	}
}

// F3-2: one goal is appended at most once per Execute and its retry, and
// the done text's Logged flag reports the entry that holds; a failed
// append is tried again by retry while it has not held. A take-back
// without asking keeps its own agent entry. A tombstone that did not hold
// is not logged.
func TestForgetAppendsOncePerForget(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	for _, c := range []struct {
		name    string
		fail    int  // failed forgets: 1 is a retry, 2 an untombstoned forget
		logFail int  // failed appends before one holds
		always  bool // every append fails
		idle    bool // the agent is taken back without asking
		appends int
		agent   bool
		text    string
	}{
		{name: "done", appends: 1, text: forgetDone(0, false, true)},
		{name: "done, agent back", idle: true, appends: 1, agent: true, text: forgetDone(0, true, true)},
		{name: "done, append failed", always: true, text: forgetDone(0, false, false)},
		{name: "retry", fail: 1, appends: 1, text: forgetDone(0, false, true)},
		{name: "retry, first append failed", fail: 1, logFail: 1, appends: 1, text: forgetDone(0, false, true)},
		{name: "retry, every append failed", fail: 1, always: true, text: forgetDone(0, false, false)},
		{name: "not tombstoned", fail: 2, text: forgetNotDone},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newForgetRig(t)
			fl := &lockedForgetLog{fail: c.logFail, always: c.always}
			r.f.forgetLog = fl
			w := &fakeWork{ok: true, worked: !c.idle}
			r.withAgent(w)
			r.task("owner:a", restoreCanary, at, viaSMS)
			r.say("FORGET LAST")
			in := r.gate.got[0]
			if !c.idle {
				// The agent worked: the request has item 2, left unanswered.
				r.gate.st = map[string]journal.State{grants.ForgetSibling(in.ID): journal.Pending}
			}
			r.texts = nil
			r.fail = c.fail
			done := make(chan struct{})
			r.f.retried = func() { close(done) }
			out := r.f.Execute(context.Background(), in, 1)
			if c.fail == 1 {
				within(t, done)
			}
			if (c.fail == 2) != (out.Result == journal.ResultNotApplied) {
				t.Fatalf("%+v", out)
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			got := fl.entries()
			if len(got) != c.appends || len(r.texts) != 1 || r.texts[0] != c.text {
				t.Fatalf("logged %+v (%d tries), texts %q", got, fl.tries, r.texts)
			}
			if c.appends == 1 && (got[0].goal != "owner:a" || got[0].agent != c.agent || (c.agent && !got[0].since.Equal(at))) {
				t.Fatalf("entry %+v", got[0])
			}
		})
	}
}

// F3-3 (CAP-3): the entry F3-1 appends while the forget still retries is
// enough on its own: a learn dir restored from before the forget, whose
// forgotten.json and owed file lack the goal, opens with the goal
// tombstoned and its task's text and learned items gone.
func TestForgetRetryingSurvivesARestore(t *testing.T) {
	// The forget, cut off while it retries (shutdown before its next pass).
	r := newForgetRig(t)
	fl := &lockedForgetLog{}
	r.f.forgetLog = fl
	r.fail = 1
	r.f.sleep = func(context.Context, time.Duration) bool { return false }
	done := make(chan struct{})
	r.f.retried = func() { close(done) }
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	within(t, done)
	got := fl.entries()
	if len(got) != 1 {
		t.Fatalf("logged %+v", got)
	}
	// The backup: taken before the forget, the task's text kept.
	dir := t.TempDir()
	open := func() *learning {
		t.Helper()
		lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &daemon.Config{
			JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"), OwnerNumber: ownerNum})
		if err != nil {
			t.Fatal(err)
		}
		return lp
	}
	lp := open()
	lp.tasks.put("owner:a", restoreCanary, false, viaSMS)
	lp.tasks.put("owner:b", "water the plants", false, viaSMS)
	if lp.forgotten.has("owner:a") || len(lp.forgetOwner.owedAtStart) != 0 {
		t.Fatal("the backup already holds the forget")
	}
	// The restore puts the backup's learn dir back with the log's entry.
	e := got[0]
	writeRestoredLog(t, dir, fmt.Sprintf(`{"seq":1,"goal":%q,"at":%q,"count":41,"prev":"p","mac":"m"}`,
		e.goal, e.at.Format(time.RFC3339Nano)))
	again := open()
	if !again.forgotten.has("owner:a") || again.forgotten.has("owner:b") {
		t.Fatal("the retrying forget was not replayed")
	}
	if _, ok := again.tasks.get("owner:a"); ok {
		t.Fatal("the forgotten task's text is back after the restore")
	}
	if !again.learn.Forgot("owner:a") || again.learn.Forgot("owner:b") {
		t.Fatal("Loop 1 still learns from the forgotten task")
	}
	if _, ok := again.tasks.get("owner:b"); !ok {
		t.Fatal("a kept task was forgotten")
	}
}
