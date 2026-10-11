package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CAP-3, CH-7, CH-8

// W3-forget-b3r (potency R2): the Wi-Fi page lists the owner's recent
// tasks as FORGET does, newest first, by the label FORGET shows; only a
// task the owner texted shows any of its words.
func TestThePageListsTheRecentTasksByTheirLabel(t *testing.T) {
	r := newForgetRig(t)
	for i := 0; i < forgetList+1; i++ {
		r.task(fmt.Sprintf("owner:%d", i), fmt.Sprintf("task %d", i), r.now.Add(-time.Duration(10-i)*time.Hour), viaSMS)
	}
	r.task("owner:mail", "CANARY-mailed renew the passport", r.now.Add(-time.Minute), "mail")
	got := r.f.PageTasks(true)
	if got.Locked || len(got.Tasks) != forgetList {
		t.Fatalf("tasks %+v", got)
	}
	recent := r.tasks.recent(forgetList)
	for i, x := range got.Tasks {
		if x.ID != recent[i].Goal || x.Label != r.f.shown(recent[i].taskText, true) || x.Date != r.f.date(recent[i].At) {
			t.Fatalf("task %d: %+v, want %s", i, x, recent[i].Goal)
		}
	}
	if got.Tasks[0].ID != "owner:mail" || got.Tasks[0].Label != "(a task, today 14:01)" {
		t.Fatalf("newest %+v", got.Tasks[0])
	}
	if got.Tasks[1].Label != `"task 5" (today 09:02)` {
		t.Fatalf("texted %+v", got.Tasks[1])
	}
	if s := fmt.Sprint(got); strings.Contains(s, "CANARY") || strings.Contains(s, "passport") || strings.Contains(s, "owner:0") {
		t.Fatalf("list shows %s", s)
	}
	if got := newForgetRig(t).f.PageTasks(true); got.Locked || len(got.Tasks) != 0 {
		t.Fatalf("no tasks: %+v", got)
	}
}

// Locked (CH-21, the signal FORGET by text gets): the page lists nothing
// and an ask submits nothing.
func TestALockedSessionListsNothingAndAsksNothing(t *testing.T) {
	r := newForgetRig(t)
	r.task("owner:a", "pay the gas bill", r.now.Add(-time.Hour), viaSMS)
	if got := r.f.PageTasks(false); !got.Locked || len(got.Tasks) != 0 {
		t.Fatalf("locked list %+v", got)
	}
	if got := r.f.PageForget(context.Background(), "owner:a", false); got != forgetPageLocked {
		t.Fatalf("locked ask %q", got)
	}
	if len(r.gate.got) != 0 || len(r.forgot) != 0 || len(r.texts) != 0 {
		t.Fatalf("locked ask reached the gate: %v %v %q", r.gate.got, r.forgot, r.texts)
	}
}

// CAP-3: an ask from the page is FORGET's own ask: one request, nothing
// deleted until the owner approves it; approved, the done text is owed
// before the tombstone is written (the W3-forget-b3 order), and a failed
// save tells the owner it is not forgotten.
func TestAPageAskIsOneRequestAndForgetsOnlyOnceApproved(t *testing.T) {
	store := &flakyStore{}
	r := restartRig(t, store)
	r.task("owner:a", "pay the gas bill", r.now.Add(-2*time.Hour), viaSMS)
	r.task("owner:b", "call the bank", r.now.Add(-time.Hour), viaSMS)
	if got := r.f.PageForget(context.Background(), "owner:a", true); got != forgetPageAsked {
		t.Fatalf("ask %q", got)
	}
	if len(r.gate.got) != 1 || grants.ForgetGoal(r.gate.got[0].ID) != "owner:a" || r.gate.got[0].Action != journal.ActionLearnForget ||
		len(r.gate.authorized) != 1 || r.gate.authorized[0] != r.gate.got[0].ID {
		t.Fatalf("submitted %+v authorized %v", r.gate.got, r.gate.authorized)
	}
	if len(r.forgot) != 0 || len(r.texts) != 0 || len(store.saved) != 0 {
		t.Fatalf("forgot before approval: %v %q %q", r.forgot, r.texts, store.saved)
	}
	if strings.Contains(strings.ToLower(forgetPageAsked), "forgotten.") || !strings.Contains(forgetPageAsked, "Asked") {
		t.Fatalf("ask text %q", forgetPageAsked)
	}
	// The owner approves: the gate runs the submitted intent.
	r.f.forget = func(g string) error {
		if !strings.Contains(string(store.saved), `"owner:a"`) {
			t.Error("tombstone before the owed done text")
		}
		r.forgot = append(r.forgot, g)
		return nil
	}
	if out := r.f.Execute(context.Background(), r.gate.got[0], 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("execute: %+v", out)
	}
	if strings.Join(r.forgot, ",") != "owner:a" || len(r.texts) != 1 || !strings.HasPrefix(r.texts[0], "Forgotten.") {
		t.Fatalf("forgot %v texts %q", r.forgot, r.texts)
	}

	// A failed save: the owner hears "Not forgotten", never "Forgotten".
	r.texts = nil
	if got := r.f.PageForget(context.Background(), "owner:b", true); got != forgetPageAsked {
		t.Fatalf("ask %q", got)
	}
	r.f.forget = func(string) error { return fmt.Errorf("%w: disk full", errNotTombstoned) }
	r.f.Execute(context.Background(), r.gate.got[1], 1)
	if len(r.texts) != 1 || !strings.HasPrefix(r.texts[0], "Not forgotten") {
		t.Fatalf("failed save texts %q", r.texts)
	}
}

// An id not among the recent tasks (unknown, past the list, or already
// forgotten) asks nothing and gets fixed text; the gate refusing gets
// FORGET's own refusal.
func TestAnIDNotListedAsksNothing(t *testing.T) {
	r := newForgetRig(t)
	for i := 0; i < forgetList+2; i++ {
		r.task(fmt.Sprintf("owner:%d", i), "task", r.now.Add(-time.Duration(10-i)*time.Hour), viaSMS)
	}
	r.tasks.forget("owner:6") // already forgotten: owner:0 is past the list
	for _, id := range []string{"owner:0", "owner:6", "owner:nope", "", "forget/1/owner:4"} {
		if got := r.f.PageForget(context.Background(), id, true); got != forgetPageUnknown {
			t.Fatalf("%q: %q", id, got)
		}
	}
	if len(r.gate.got) != 0 {
		t.Fatalf("submitted %+v", r.gate.got)
	}
	r.gate.state = journal.Denied
	if got := r.f.PageForget(context.Background(), "owner:4", true); got != forgetRefused {
		t.Fatalf("refused ask %q", got)
	}
	r.f.gate.Store(nil)
	if got := r.f.PageForget(context.Background(), "owner:4", true); got != forgetRefused {
		t.Fatalf("no gate %q", got)
	}
}

// The page's texts are fixed and name no task; nothing the page does
// logs a task's words.
func TestThePageLogsNoTaskWords(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	r := newForgetRig(t)
	r.task("owner:a", "CANARY-page pay the gas bill", r.now.Add(-time.Hour), viaSMS)
	r.task("owner:b", "CANARY-page renew the passport", r.now.Add(-time.Minute), "mail")
	r.f.PageTasks(true)
	r.f.PageForget(context.Background(), "owner:b", true)
	r.gate.state = journal.Denied
	r.f.PageForget(context.Background(), "owner:a", true)
	if strings.Contains(buf.String(), "CANARY") {
		t.Fatalf("logged %q", buf.String())
	}
	for _, s := range []string{forgetPageAsked, forgetPageUnknown, forgetPageLocked} {
		if strings.Contains(s, "CANARY") || strings.Contains(s, "owner:") {
			t.Fatalf("%q", s)
		}
	}
}

// The ask takes f.mu as Text does: run concurrently, every ask gets its
// own intent ID (run with -race).
func TestPageAndTextAsksRunConcurrently(t *testing.T) {
	r := newForgetRig(t)
	r.task("owner:a", "pay the gas bill", r.now.Add(-time.Hour), viaSMS)
	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); r.f.PageForget(context.Background(), "owner:a", true) }()
		go func() { defer wg.Done(); r.f.Text(context.Background(), "FORGET LAST", true) }()
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, in := range r.gate.got {
		if seen[in.ID] {
			t.Fatalf("duplicate intent %s", in.ID)
		}
		seen[in.ID] = true
	}
	if len(seen) != 2*n {
		t.Fatalf("%d intents, want %d", len(seen), 2*n)
	}
}

// wirePage hands the page's ops to the local UI's socket only when there
// is one.
func TestThePageIsWiredOnlyWithItsSocket(t *testing.T) {
	r := newForgetRig(t)
	var cfg daemon.Config
	if r.f.wirePage(&cfg) {
		t.Fatal("wired without a page socket")
	}
	cfg.PageSocket = &daemon.PageSocket{}
	if !r.f.wirePage(&cfg) || cfg.PageSocket.Forget == nil {
		t.Fatal("not wired")
	}
}
