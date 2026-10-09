package main

// REQ: CAP-3

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
)

// The done texts a forget owes across a restart (W3-forget-b3): UX-182-3
// and SHOULD 4 of L3 on #182.

func forgetIntent(nonce, goal string) journal.Intent {
	return journal.Intent{ID: grants.ForgetID(nonce, goal), Origin: grants.OriginForget, Account: journal.BrokerAccount,
		Action: journal.ActionLearnForget, Executor: grants.ForgetExecutor}
}

// restartRig is a forget rig whose owed done texts are kept in store, and
// restart opens a new one on the same store with the tombstone as held.
func restartRig(t *testing.T, store change.Store) *forgetRig {
	t.Helper()
	r := newForgetRig(t)
	owed, err := openForgetOwed(store)
	if err != nil {
		t.Fatal(err)
	}
	r.f.owed = owed
	return r
}

func restart(t *testing.T, store change.Store, held map[string]bool) *forgetRig {
	t.Helper()
	r := restartRig(t, store)
	r.f.forgotten = func(g string) bool { return held[g] }
	r.f.owedAtStart = r.f.owed.goals()
	return r
}

// UX-182-3: a forget still retrying at shutdown texts its done text, once,
// after the start-up replay finishes it; it names the task by its time,
// since the owner may have sent other texts since.
func TestARetryingForgetTextsItsDoneTextAfterARestart(t *testing.T) {
	store := &change.MemStore{}
	r := restartRig(t, store)
	r.learned["owner:a"] = 2
	r.fail = 1 // a store's save fails, then the retry is cut off
	done := make(chan struct{})
	r.f.sleep = func(context.Context, time.Duration) bool { return false } // shutdown
	r.f.retried = func() { close(done) }
	since := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	in := forgetIntent(fmt.Sprintf("1.1.%d", since.UnixNano()), "owner:a")
	if out := r.f.Execute(context.Background(), in, 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("execute: %+v", out)
	}
	<-done
	if len(r.texts) != 0 {
		t.Fatalf("texted before done: %q", r.texts)
	}
	again := restart(t, store, map[string]bool{"owner:a": true})
	again.f.finishOwed(context.Background())
	want := "Your task from Mon 5 Oct 13:02 is forgotten now. I also undid 2 things I learned from it; I'll relearn what I can without it." +
		" Older backups and your agent's own files may still hold it."
	if strings.Join(again.texts, "|") != want {
		t.Fatalf("texts %q", again.texts)
	}
	// Told once: a second start owes nothing.
	third := restart(t, store, map[string]bool{"owner:a": true})
	third.f.finishOwed(context.Background())
	if len(third.texts) != 0 {
		t.Fatalf("told twice: %q", third.texts)
	}
}

// A forget done before the restart owes nothing after it, nor does one
// whose retry finished.
func TestADoneForgetOwesNothing(t *testing.T) {
	store := &change.MemStore{}
	r := restartRig(t, store)
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	r.fail = 1
	done := make(chan struct{})
	r.f.retried = func() { close(done) }
	r.f.Execute(context.Background(), forgetIntent("2", "owner:b"), 1)
	<-done
	if len(r.texts) != 2 {
		t.Fatalf("texts %q", r.texts)
	}
	again := restart(t, store, map[string]bool{"owner:a": true, "owner:b": true})
	again.f.finishOwed(context.Background())
	if len(again.texts) != 0 {
		t.Fatalf("texts after restart %q", again.texts)
	}
}

// SHOULD 4 of L3 on #182: the owner was told "Not forgotten", but the
// goal stays tombstoned in memory and a later forget's save writes it, so
// the next start's replay forgets the task; the owner is then told it is
// forgotten now. If no save wrote it, nothing is said and nothing is owed.
func TestANotForgottenTaskForgottenAtStartIsTold(t *testing.T) {
	for _, held := range []bool{true, false} {
		store := &change.MemStore{}
		r := restartRig(t, store)
		r.fail = 2 // the tombstone does not save
		since := time.Date(2026, 10, 4, 9, 30, 0, 0, time.UTC)
		r.f.Execute(context.Background(), forgetIntent(fmt.Sprintf("1.1.%d", since.UnixNano()), "owner:a"), 1)
		if strings.Join(r.texts, "|") != forgetNotDone {
			t.Fatalf("texts %q", r.texts)
		}
		again := restart(t, store, map[string]bool{"owner:a": held})
		again.f.finishOwed(context.Background())
		want := ""
		if held {
			want = "Your task from Sun 4 Oct 09:30 is forgotten now. Older backups and your agent's own files may still hold it."
		}
		if strings.Join(again.texts, "|") != want {
			t.Fatalf("held %v: texts %q", held, again.texts)
		}
		third := restart(t, store, map[string]bool{"owner:a": held})
		third.f.finishOwed(context.Background())
		if len(third.texts) != 0 {
			t.Fatalf("held %v: told twice: %q", held, third.texts)
		}
	}
}

// The done text after a restart rides the forget log like any other: the
// forget is appended, and the text then says a restore won't bring it
// back (UX F4 on #317).
func TestTheOwedDoneTextIsLogged(t *testing.T) {
	store := &change.MemStore{}
	r := restartRig(t, store)
	r.fail = 2 // the tombstone does not save
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	again := restart(t, store, map[string]bool{"owner:a": true})
	fl := &fakeForgetLog{}
	again.f.forgetLog = fl
	again.f.finishOwed(context.Background())
	want := "A task you asked me to forget is forgotten now." + forgetLogged
	if strings.Join(again.texts, "|") != want || strings.Join(fl.got, ",") != "owner:a" {
		t.Fatalf("texts %q, logged %v", again.texts, fl.got)
	}
}

// The owed state is written before the tombstone, so a tombstone that
// holds always has its done text owed; a failed write of it does not stop
// the forget, and the next write carries it.
func TestOwedIsKeptBeforeTheTombstone(t *testing.T) {
	store := &flakyStore{fail: 1}
	r := restartRig(t, store)
	r.f.forget = func(g string) error {
		if !strings.Contains(string(store.saved), `"owner:b"`) && g == "owner:b" {
			t.Error("tombstone before the owed done text")
		}
		return errors.New("disk full")
	}
	r.f.sleep = func(context.Context, time.Duration) bool { return false }
	done := make(chan struct{}, 2)
	r.f.retried = func() { done <- struct{}{} }
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1) // its owed write fails
	r.f.Execute(context.Background(), forgetIntent("2", "owner:b"), 1)
	<-done
	<-done
	again := restart(t, store, map[string]bool{"owner:a": true, "owner:b": true})
	again.f.finishOwed(context.Background())
	if len(again.texts) != 2 {
		t.Fatalf("texts %q", again.texts)
	}
}

// The owed state holds goal IDs, counts and times only, never a task's
// text (security C2 on W3-forget).
func TestOwedHoldsNoTaskText(t *testing.T) {
	store := &change.MemStore{}
	r := restartRig(t, store)
	r.task("owner:a", "pay the gas bill CANARY-owed", r.now.Add(-time.Hour), viaSMS)
	r.fail = 2
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	b, _ := store.Load()
	if len(b) == 0 || strings.Contains(string(b), "CANARY") || strings.Contains(string(b), "gas") {
		t.Fatalf("owed state %q", b)
	}
}

// UX on W3-forget (carried by P2-2w d): no forget text points the owner at
// deleting backups until the Wi-Fi page has a backups page to point at.
func TestNoForgetTextPointsAtDeletingBackups(t *testing.T) {
	r := newForgetRig(t)
	texts := []string{forgetNone, forgetStale, forgetRefused, forgetNotSaved, forgetNotDone, forgetAgentNotice, forgetAgentAlone,
		forgetAgentDone, forgetAgentNotYet, forgetAgentNoAgent, forgetAgentNotTaken, forgetAgentNotOpen, forgetAgentWhenOpen, forgetOwedLost}
	for _, logged := range []bool{false, true} {
		for _, back := range []bool{false, true} {
			texts = append(texts, forgetDone(3, back, logged))
		}
		texts = append(texts, r.f.doneLater(3, r.now, true, logged), r.f.doneLater(0, time.Time{}, false, logged))
	}
	for _, s := range texts {
		l := strings.ToLower(s)
		if strings.Contains(l, "delete") || strings.Contains(l, "wi-fi") || strings.Contains(l, "remove") || !gsm7(s) {
			t.Fatalf("%q", s)
		}
	}
}

// flakyStore fails its first fail saves.
type flakyStore struct {
	fail  int
	saved []byte
}

func (s *flakyStore) Load() ([]byte, error) { return s.saved, nil }
func (s *flakyStore) Save(b []byte) error {
	if s.fail > 0 {
		s.fail--
		return errors.New("disk full")
	}
	s.saved = append([]byte(nil), b...)
	return nil
}

// UX-182-3 end to end: approved, the forget's save fails and its retry is
// cut off by a shutdown, so the owner hears nothing; after the restart the
// replay forgets the task and the owner is texted that it is done.
func TestARetryingForgetIsToldAfterARealRestart(t *testing.T) {
	x := newForgetDaemon(t)
	lp := x.lp
	lp.tasks.put("owner:a", "pay the gas bill CANARY-forget", false, viaSMS)
	id, code := x.ask(1, "'pay the gas bill CANARY-..'")
	tasks := lp.tasks.store
	lp.tasks.store = failSave{tasks}
	done := make(chan struct{})
	lp.forgetOwner.sleep = func(context.Context, time.Duration) bool { return false }
	lp.forgetOwner.retried = func() { close(done) }
	if got := x.say("YES " + id + " " + code); !strings.HasPrefix(got, "Approved") {
		t.Fatalf("YES: %q", got)
	}
	x.d.Gate().Wait()
	<-done
	x.stop()
	x.d.Wait()
	lp.running.Wait()
	lp.tasks.store = tasks
	for {
		select {
		case m := <-x.phone.Inbox():
			if strings.Contains(m.Text, "orgotten") && !strings.HasPrefix(m.Text, "Not") {
				t.Fatalf("told before done: %q", m.Text)
			}
			continue
		default:
		}
		break
	}
	y := newForgetDaemonAt(t, x.dir)
	if _, ok := y.lp.tasks.get("owner:a"); ok {
		t.Fatal("the task's text is still kept after the replay")
	}
	for {
		if got := y.text(); strings.HasSuffix(got, " is forgotten now. Older backups and your agent's own files may still hold it.") &&
			strings.HasPrefix(got, "Your task from ") {
			break
		}
	}
}

// downTell is an owner channel whose sends fail (modemlink's ErrDown) until
// up is set; it records what it sent.
type downTell struct {
	mu   sync.Mutex
	up   bool
	sent []string
}

func (d *downTell) tell(s string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.up {
		return errors.New("modem down")
	}
	d.sent = append(d.sent, s)
	return nil
}

func (d *downTell) setUp() { d.mu.Lock(); d.up = true; d.mu.Unlock() }

func (d *downTell) got() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.sent...)
}

// L3 B1 on #425: a done text owed across a restart whose send fails (the
// modem is down just after boot) stays owed and is sent once it can be,
// in this boot or, after a shutdown, the next.
func TestAnOwedTextWhoseSendFailsStaysOwed(t *testing.T) {
	store := &change.MemStore{}
	r := restartRig(t, store)
	r.fail = 2 // not tombstoned: owed until a start finds it tombstoned
	r.f.Execute(context.Background(), forgetIntent("1", "owner:a"), 1)
	held := map[string]bool{"owner:a": true}

	// Down through this boot's shutdown: still owed after it.
	again := restart(t, store, held)
	d := &downTell{}
	again.f.tell = d.tell
	ended := make(chan struct{})
	again.f.sleep = func(context.Context, time.Duration) bool { return false }
	again.f.toldLater = func() { close(ended) }
	again.f.finishOwed(context.Background())
	<-ended
	if len(d.got()) != 0 || len(again.f.owed.goals()) != 1 {
		t.Fatalf("sent %q, owed %v", d.got(), again.f.owed.goals())
	}

	// Down at attach, up a moment later: sent once, then no longer owed.
	third := restart(t, store, held)
	d = &downTell{}
	third.f.tell = d.tell
	ended = make(chan struct{})
	var waits []time.Duration
	third.f.sleep = func(_ context.Context, w time.Duration) bool {
		waits = append(waits, w)
		if len(waits) == 2 {
			d.setUp()
		}
		return true
	}
	third.f.toldLater = func() { close(ended) }
	third.f.finishOwed(context.Background())
	<-ended
	if strings.Join(d.got(), "|") != "A task you asked me to forget is forgotten now. Older backups and your agent's own files may still hold it." ||
		len(third.f.owed.goals()) != 0 || len(waits) != 2 || waits[1] <= waits[0] {
		t.Fatalf("sent %q, owed %v, waits %v", d.got(), third.f.owed.goals(), waits)
	}
	fourth := restart(t, store, held)
	d = &downTell{up: true}
	fourth.f.tell = d.tell
	fourth.f.finishOwed(context.Background())
	if len(d.got()) != 0 {
		t.Fatalf("told twice: %q", d.got())
	}
}

// L3 B1 on #425: a forget done in this boot whose done text does not send
// stays owed, so the next start tells it, logged once and with the tail
// it had.
func TestADoneTextNotSentIsToldAfterARestart(t *testing.T) {
	store := &change.MemStore{}
	r := restartRig(t, store)
	fl := &fakeForgetLog{}
	r.f.forgetLog = fl
	d := &downTell{}
	r.f.tell = d.tell
	ended := make(chan struct{})
	r.f.sleep = func(context.Context, time.Duration) bool { return false } // shutdown
	r.f.toldLater = func() { close(ended) }
	since := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	r.f.Execute(context.Background(), forgetIntent(fmt.Sprintf("1.1.%d", since.UnixNano()), "owner:a"), 1)
	<-ended
	if len(d.got()) != 0 || len(r.f.owed.goals()) != 1 {
		t.Fatalf("sent %q, owed %v", d.got(), r.f.owed.goals())
	}
	again := restart(t, store, map[string]bool{"owner:a": true})
	again.f.forgetLog = fl
	d = &downTell{up: true}
	again.f.tell = d.tell
	again.f.finishOwed(context.Background())
	if strings.Join(d.got(), "|") != "Your task from Mon 5 Oct 13:02 is forgotten now."+forgetLogged || strings.Join(fl.got, ",") != "owner:a" {
		t.Fatalf("sent %q, logged %v", d.got(), fl.got)
	}
}

// L3 B2 on #425: an owed file that does not read, or holds entries no
// forget wrote, fails safe: learning opens, nothing panics, the owner is
// told the owed texts were lost rather than nothing, the unreadable file
// is kept aside, and no text carries the file's own words.
func TestAGarbageOwedFileFailsSafe(t *testing.T) {
	for _, body := range []string{"{", "\x00\xff garbage", `{"owner:a":"CANARY-owed"}`, `[1,2]`} {
		dir := t.TempDir()
		path := filepath.Join(dir, "forget-owed.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &daemon.Config{
			JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"), OwnerNumber: ownerNum})
		if err != nil {
			t.Fatalf("%q: learning did not open: %v", body, err)
		}
		if b, err := os.ReadFile(path + ".bad"); err != nil || string(b) != body {
			t.Fatalf("%q: not kept aside: %q %v", body, b, err)
		}
		d := &downTell{up: true}
		lp.forgetOwner.tell = d.tell
		lp.forgetOwner.finishOwed(context.Background())
		if strings.Join(d.got(), "|") != forgetOwedLost {
			t.Fatalf("%q: sent %q", body, d.got())
		}
	}
	// Injected entries: a goal no tombstone holds is dropped untold, and
	// a count or time no forget writes is not repeated to the owner.
	store := &change.MemStore{}
	_ = store.Save([]byte(`{"owner:x":{"undone":5},"owner:a":{"since":"2099-01-01T00:00:00Z","undone":-3}}`))
	r := restart(t, store, map[string]bool{"owner:a": true})
	r.f.finishOwed(context.Background())
	if strings.Join(r.texts, "|") != "A task you asked me to forget is forgotten now. Older backups and your agent's own files may still hold it." {
		t.Fatalf("texts %q", r.texts)
	}
}

// UX-182-3 with W3-forget-b2c's owed take-backs: a FORGET whose item 1 and
// item 2 were both still retrying at shutdown is told each done text once
// after the restart, item 1's at attach and item 2's when recall opens.
func TestBothOwedForgetTextsComeAfterARestart(t *testing.T) {
	w := &fakeWork{worked: true, ok: true, err: errors.New("disk full")}
	r, in2 := owedRig(t, w)
	in1 := r.gate.got[0]
	store := &change.MemStore{}
	owed, err := openForgetOwed(store)
	if err != nil {
		t.Fatal(err)
	}
	r.f.owed = owed
	ended := make(chan struct{}, 2)
	r.f.sleep = func(context.Context, time.Duration) bool { return false } // shutdown
	r.f.retried = func() { ended <- struct{}{} }
	r.fail = 1 // item 1's save fails, then its retry is cut off
	r.f.Execute(context.Background(), in1, 1)
	out := r.f.Execute(context.Background(), in2, 1)
	<-ended
	<-ended
	r.mu.Lock()
	for _, s := range r.texts {
		if strings.Contains(s, "orgotten") || s == forgetAgentDone {
			t.Errorf("told before done: %q", s)
		}
	}
	r.mu.Unlock()
	w.mu.Lock()
	w.err = nil
	w.mu.Unlock()
	// The restart: the replay finished item 1, the owner channel attaches,
	// then recall opens.
	r.texts = nil
	r.f.forgotten = func(g string) bool { return g == "owner:a" }
	r.f.owedAtStart = r.f.owed.goals()
	r.f.finishOwed(context.Background())
	if len(r.texts) != 1 || !strings.HasPrefix(r.texts[0], "Your task from ") ||
		!strings.HasSuffix(r.texts[0], " is forgotten now. Older backups and your agent's own files may still hold it.") {
		t.Fatalf("item 1 told %q", r.texts)
	}
	r.nextBoot(in2, out) // recall opens: item 2 is taken back
	// Each once: a later attach and open of recall tell nothing more.
	r.f.owedAtStart = r.f.owed.goals()
	r.f.finishOwed(context.Background())
	r.f.resumeAgent(context.Background())
	if len(w.backs) != 1 {
		t.Fatalf("took back %v", w.backs)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.texts) != 1 || r.texts[0] != forgetAgentDone {
		t.Fatalf("item 2 told %q", r.texts)
	}
}

// L3 B1 on #425, as wired: openLearning gives the forget owner a send
// that reports failure (loop2Notify.try), so a text owed at start whose
// send fails (here the owner channel is not attached) stays owed.
func TestAnOwedTextNotSentStaysOwedAsWired(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "forget-owed.json"), []byte(`{"`+owedLostKey+`":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"), OwnerNumber: ownerNum})
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	lp.forgetOwner.sleep = func(context.Context, time.Duration) bool { return false } // shutdown
	lp.forgetOwner.toldLater = func() { close(ended) }
	lp.forgetOwner.finishOwed(context.Background())
	if g := lp.forgetOwner.owed.goals(); len(g) != 1 || g[0] != owedLostKey {
		t.Fatalf("owed after a failed send: %v", g)
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("no resend after a failed send")
	}
}

// L3 B1 on #425: a retried forget whose save then holds but whose done
// text does not send stays owed, and the next start tells it.
func TestARetriedForgetWhoseTextDoesNotSendStaysOwed(t *testing.T) {
	store := &change.MemStore{}
	r := restartRig(t, store)
	r.learned["owner:a"] = 2
	r.fail = 1 // the first save fails; the retry's holds
	r.f.tell = (&downTell{}).tell
	var sleeps atomic.Int32
	r.f.sleep = func(context.Context, time.Duration) bool { return sleeps.Add(1) == 1 } // then shutdown
	retried, ended := make(chan struct{}), make(chan struct{})
	r.f.retried = func() { close(retried) }
	r.f.toldLater = func() { close(ended) }
	since := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	r.f.Execute(context.Background(), forgetIntent(fmt.Sprintf("1.1.%d", since.UnixNano()), "owner:a"), 1)
	<-retried
	if g := r.f.owed.goals(); len(g) != 1 || g[0] != "owner:a" {
		t.Fatalf("owed after a failed send: %v", g)
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("no resend after a failed send")
	}
	again := restart(t, store, map[string]bool{"owner:a": true})
	again.f.finishOwed(context.Background())
	want := "Your task from Mon 5 Oct 13:02 is forgotten now. I also undid 2 things I learned from it; I'll relearn what I can without it." + forgetBackups
	if strings.Join(again.texts, "|") != want {
		t.Fatalf("texts %q", again.texts)
	}
}
