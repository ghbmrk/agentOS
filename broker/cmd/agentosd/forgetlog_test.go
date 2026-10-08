package main

// REQ: CAP-3, REC-2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
)

// fakeForgetLog records the forget log's appends; err fails them.
type fakeForgetLog struct {
	err  error
	got  []string
	back []time.Time
}

func (l *fakeForgetLog) Append(goal string, at, since time.Time, agent bool) error {
	if l.err != nil {
		return l.err
	}
	l.got = append(l.got, goal)
	if agent {
		l.back = append(l.back, since)
	}
	return nil
}

// W3-forget-b1 (UX F4 on #317): the done text says a restored backup
// will not bring the task back only once the forget is in the
// authenticated log; without it, part a's caveat stays.
func TestForgetDoneTextFollowsTheLog(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		err  error
		idle bool // the agent is taken back without asking
		want string
	}{
		{"logged", nil, false, "Forgotten. Your agent's own files may still hold it. Older backups do too, but restoring one won't bring it back."},
		{"logged, agent back", nil, true, "Forgotten. Older backups may still hold it, but restoring one won't bring it back."},
		{"not logged", errors.New("vault closed"), false, "Forgotten. Older backups and your agent's own files may still hold it."},
		{"not logged, agent back", errors.New("vault closed"), true, "Forgotten. Older backups may still hold it."},
	} {
		r := newForgetRig(t)
		fl := &fakeForgetLog{err: c.err}
		r.f.forgetLog = fl
		w := &fakeWork{ok: true, worked: !c.idle}
		r.withAgent(w)
		r.task("owner:a", "pay the gas bill", at, viaSMS)
		r.say("FORGET LAST")
		in := r.gate.got[0]
		if c.idle {
			r.texts = nil
		} else {
			// The agent worked: the request has item 2, left unanswered.
			r.gate.st = map[string]journal.State{grants.ForgetSibling(in.ID): journal.Pending}
			r.texts = nil
		}
		if out := r.f.Execute(context.Background(), in, 1); out.Result != journal.ResultSucceeded || len(r.texts) != 1 || r.texts[0] != c.want {
			t.Fatalf("%s: %+v %q", c.name, out, r.texts)
		}
		if c.err == nil && (strings.Join(fl.got, ",") != "owner:a" || c.idle != (len(fl.back) == 1)) {
			t.Fatalf("%s: logged %v %v", c.name, fl.got, fl.back)
		}
	}
	// A forget finished by the retry is logged too.
	r := newForgetRig(t)
	fl := &fakeForgetLog{}
	r.f.forgetLog = fl
	r.fail = 1 // a failed save, then the retry holds
	done := make(chan struct{})
	r.f.retried = func() { close(done) }
	in := journal.Intent{ID: grants.ForgetID("1", "owner:b"), Origin: grants.OriginForget, Account: journal.BrokerAccount,
		Action: journal.ActionLearnForget, Executor: grants.ForgetExecutor}
	r.f.Execute(context.Background(), in, 1)
	<-done
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.Join(r.texts, "|") != "Forgotten. Your agent's own files may still hold it. Older backups do too, but restoring one won't bring it back." ||
		strings.Join(fl.got, ",") != "owner:b" {
		t.Fatalf("retry: %q %v", r.texts, fl.got)
	}
}

// An approved item 2 that takes the agent back is logged with where it
// went back to, so a restore takes the agent back again.
func TestForgetItem2IsLogged(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	r := newForgetRig(t)
	fl := &fakeForgetLog{}
	r.f.forgetLog = fl
	w := &fakeWork{worked: true, ok: true}
	r.withAgent(w)
	r.task("owner:a", "pay the gas bill", at, viaSMS)
	r.say("FORGET LAST")
	r.gate.st = map[string]journal.State{r.gate.got[0].ID: journal.Succeeded}
	r.texts = nil
	if out := r.f.Execute(context.Background(), r.gate.got[1], 1); out.Result != journal.ResultSucceeded || r.texts[0] != forgetAgentDone {
		t.Fatalf("%+v %q", out, r.texts)
	}
	if strings.Join(fl.got, ",") != "owner:a" || len(fl.back) != 1 || !fl.back[0].Equal(at) {
		t.Fatalf("logged %v %v", fl.got, fl.back)
	}
}

// CH-12: the done texts are GSM-7, and the taken-back one stays within one
// segment at any two-digit count (UX F4 on #317).
func TestForgetLoggedTextsFitOneSegment(t *testing.T) {
	for _, s := range []string{forgetDone(0, false, true), forgetDone(0, true, true), forgetDone(99, true, true)} {
		if len(s) > 160 || !gsm7(s) {
			t.Fatalf("%d %q", len(s), s)
		}
	}
	if s := forgetDone(9, false, true); !gsm7(s) {
		t.Fatalf("%q", s)
	}
}

func gsm7(s string) bool {
	for _, r := range s {
		if r > 0x7e || r < 0x20 || strings.ContainsRune("`^{}[]~|\\", r) {
			return false
		}
	}
	return true
}

// writeRestoredLog is the restore's state-dir copy of the forget log, as
// broker/recovery writes it once the log's check passes.
func writeRestoredLog(t *testing.T, dir, entries string) {
	t.Helper()
	b := `{"format":"agentos-forget-log-v1","id":"AAAAAAAAAAAAAAAAAAAAAA==","host":"pc-1","base":40,"mac":"x","entries":[` + entries + `]}`
	if err := os.WriteFile(filepath.Join(dir, forgetLogFile), []byte(b), 0o600); err != nil {
		t.Fatal(err)
	}
}

// CAP-3 across a restore (security C3; acceptance A8): the restored
// forget log's goals are forgotten again at once, before the tree is
// ready, and its agent take-backs run once recall opens.
func TestRestoredForgetLogIsReplayed(t *testing.T) {
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
	// The backup's state: the task's text is kept.
	lp := open()
	lp.tasks.put("owner:a", "pay the gas bill CANARY-7", false, viaSMS)
	lp.tasks.put("owner:b", "water the plants", false, viaSMS)
	if _, ok := lp.tasks.get("owner:a"); !ok {
		t.Fatal("no task text")
	}
	since := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	writeRestoredLog(t, dir, `{"seq":1,"goal":"owner:a","at":"2026-10-05T14:02:00Z","count":41,"prev":"p","mac":"m"},`+
		`{"seq":2,"goal":"owner:a","at":"2026-10-05T14:03:00Z","since":"2026-10-05T13:02:00Z","agent":true,"count":42,"prev":"p","mac":"m"}`)
	again := open()
	if !again.forgotten.has("owner:a") || again.forgotten.has("owner:b") {
		t.Fatal("restored log not replayed")
	}
	if _, ok := again.tasks.get("owner:a"); ok {
		t.Fatal("the forgotten task's text is back after the restore")
	}
	if _, ok := again.tasks.get("owner:b"); !ok {
		t.Fatal("a kept task was forgotten")
	}
	f := again.forgetOwner
	w := &fakeWork{ok: true}
	f.agent.Store(&forgetAgent{work: w, lineage: func() (string, error) { return "agent.l1", nil }})
	f.resumeAgent(context.Background())
	f.resumeAgent(context.Background()) // done once: recall holds it
	if len(w.backs) != 1 || !w.backs[0].Equal(since) || !w.asked[0] {
		t.Fatalf("agent take-backs %v %v", w.backs, w.asked)
	}
}

// A restore the forget log's check held (broker/recovery's marker), or a
// state-dir copy that does not read, never opens the learning plane: the
// tree is never ready.
func TestPendingRestoreHoldsLearning(t *testing.T) {
	for _, c := range []struct {
		name, file, body string
	}{
		{"pending", forgetLogFile + ".pending", "forget-log-unanchored"},
		{"unreadable", forgetLogFile, "{"},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, c.file), []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		lt := newLiveTree(t.Logf)
		_, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json"), Tree: lt}, false, &daemon.Config{
			JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"), OwnerNumber: ownerNum})
		if err == nil {
			t.Fatalf("%s: learning opened", c.name)
		}
	}
}
