package main

// REQ: CAP-3

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
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
	again.f.finishOwed()
	want := "Your task from Mon 5 Oct 13:02 is forgotten now. I also undid 2 things I learned from it; I'll relearn what I can without it." +
		" Older backups and your agent's own files may still hold it."
	if strings.Join(again.texts, "|") != want {
		t.Fatalf("texts %q", again.texts)
	}
	// Told once: a second start owes nothing.
	third := restart(t, store, map[string]bool{"owner:a": true})
	third.f.finishOwed()
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
	again.f.finishOwed()
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
		again.f.finishOwed()
		want := ""
		if held {
			want = "Your task from Sun 4 Oct 09:30 is forgotten now. Older backups and your agent's own files may still hold it."
		}
		if strings.Join(again.texts, "|") != want {
			t.Fatalf("held %v: texts %q", held, again.texts)
		}
		third := restart(t, store, map[string]bool{"owner:a": held})
		third.f.finishOwed()
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
	again.f.finishOwed()
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
	again.f.finishOwed()
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
		forgetAgentDone, forgetAgentNotYet, forgetAgentNoAgent, forgetAgentNotTaken, forgetAgentNotOpen, forgetAgentWhenOpen}
	for _, logged := range []bool{false, true} {
		for _, back := range []bool{false, true} {
			texts = append(texts, forgetDone(3, back, logged))
		}
		texts = append(texts, r.f.doneLater(3, r.now, logged), r.f.doneLater(0, time.Time{}, logged))
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
