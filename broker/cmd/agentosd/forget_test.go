package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CAP-3, CH-21, OP-5

// askRec is a gate that records intents and asks the owner (or not).
type askRec struct {
	got   []journal.Intent
	state journal.State
}

func (g *askRec) Submit(in journal.Intent) (journal.Status, error) {
	g.got = append(g.got, in)
	return journal.Status{Intent: in, State: journal.Pending}, nil
}
func (g *askRec) Authorize(context.Context, string) (journal.Status, error) {
	return journal.Status{State: g.state}, nil
}
func (g *askRec) Dispatch(context.Context, string) (journal.Status, error) {
	return journal.Status{}, errors.New("not dispatched here")
}

// forgetRig is the owner's FORGET with fake stores and gate.
type forgetRig struct {
	t       *testing.T
	f       *ownerForget
	tasks   *taskTexts
	now     time.Time
	gate    *askRec
	mu      sync.Mutex
	texts   []string
	learned map[string]int
	fail    int // forgets that fail before one succeeds
	forgot  []string
}

func newForgetRig(t *testing.T) *forgetRig {
	r := &forgetRig{t: t, now: time.Date(2026, 10, 5, 14, 2, 0, 0, time.UTC), gate: &askRec{state: journal.Pending},
		learned: map[string]int{}}
	tasks, err := openTaskTexts(&change.MemStore{}, func() time.Time { return r.now }, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	r.tasks = tasks
	r.f = &ownerForget{
		tasks:   tasks,
		learned: func(g string) int { return r.learned[g] },
		forget: func(g string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.fail > 0 {
				r.fail--
				return errors.New("disk full")
			}
			r.forgot = append(r.forgot, g)
			return nil
		},
		inform: func(s string) { r.mu.Lock(); r.texts = append(r.texts, s); r.mu.Unlock() },
		now:    func() time.Time { return r.now },
		loc:    time.UTC,
		sleep:  func(context.Context, time.Duration) bool { return true },
	}
	r.f.gate.Store(&pauseGateBox{r.gate})
	return r
}

func (r *forgetRig) task(goal, text string, at time.Time, via string) {
	r.t.Helper()
	old := r.now
	r.now = at
	r.tasks.put(goal, text, false, via)
	r.now = old
}

func (r *forgetRig) say(msg string) string {
	r.t.Helper()
	got, ok := r.f.Text(context.Background(), msg, true)
	if !ok {
		r.t.Fatalf("%q not taken", msg)
	}
	return got
}

// W3-forget (UX F6, security C2): FORGET lists the last five tasks,
// newest first; only a task the owner texted is shown by its text, and
// FORGET n and FORGET LAST pick from the list the owner was sent.
func TestForgetListsRecentTasksAndShowsOnlyTextedOnes(t *testing.T) {
	r := newForgetRig(t)
	if got := r.say("forget"); got != "No recent tasks to forget." {
		t.Fatalf("empty: %q", got)
	}
	day := r.now
	r.task("owner:a", "book a table for friday at the usual place", day.Add(-2*time.Hour), viaSMS)
	r.task("owner:b", "CANARY-page task", day.Add(-time.Hour), "")
	r.task("owner:c", "pay the gas bill", day.Add(-26*time.Hour), viaSMS)
	want := `Reply FORGET 1-3 to forget a task: 1 (a task, today 13:02) 2 "book a table for friday…" (today 12:02) 3 "pay the gas bill" (yesterday 12:02)`
	if got := r.say("Forget."); got != want {
		t.Fatalf("list:\n got %q\nwant %q", got, want)
	}
	for i := range 4 {
		r.task("owner:x"+string(rune('0'+i)), "older", day.Add(-time.Duration(30+i)*time.Hour), viaSMS)
	}
	if got := r.say("FORGET"); !strings.HasPrefix(got, "Reply FORGET 1-5 to forget a task: 1 ") || strings.Contains(got, " 6 ") {
		t.Fatalf("five at most: %q", got)
	}
	r.say("FORGET") // the list as sent now
	if got := r.say("FORGET 2"); got != "" {
		t.Fatalf("pick 2: %q", got)
	}
	if in := r.gate.got[0]; in.Origin != grants.OriginForget || in.Action != journal.ActionLearnForget ||
		in.Executor != grants.ForgetExecutor || in.Account != journal.BrokerAccount || grants.ForgetGoal(in.ID) != "owner:a" || len(in.Params) != 0 {
		t.Fatalf("forget intent: %+v", in)
	}
	if got := r.say("forget last"); got != "" {
		t.Fatalf("LAST: %q", got)
	}
	if g := grants.ForgetGoal(r.gate.got[1].ID); g != "owner:b" {
		t.Fatalf("LAST picked %q", g)
	}
	r.now = r.now.Add(11 * time.Minute)
	if got := r.say("FORGET 1"); got != "Send FORGET to see your recent tasks." {
		t.Fatalf("stale list: %q", got)
	}
	if got := r.say("FORGET 6"); got != "Send FORGET to see your recent tasks." {
		t.Fatalf("out of range: %q", got)
	}
	for _, m := range []string{"forget it", "FORGET 1 2", "please forget"} {
		if _, ok := r.f.Text(context.Background(), m, true); ok {
			t.Fatalf("%q taken", m)
		}
	}
	if len(r.gate.got) != 2 {
		t.Fatalf("intents: %d", len(r.gate.got))
	}
}

// CH-21: in a locked session FORGET is not taken, so the owner channel
// asks for the unlock; nothing is listed or asked.
func TestForgetNeedsAnUnlockedSession(t *testing.T) {
	r := newForgetRig(t)
	r.task("owner:a", "book a table", r.now, viaSMS)
	for _, m := range []string{"FORGET", "FORGET LAST"} {
		if got, ok := r.f.Text(context.Background(), m, false); ok || got != "" {
			t.Fatalf("%q in a locked session: %q %v", m, got, ok)
		}
	}
	if len(r.gate.got) != 0 {
		t.Fatal("asked in a locked session")
	}
}

// UX F2, U-F8, potency R1: the request is the notice. FORGET n gets no
// reply of its own; the approval line, the box's by goal, says what the
// forget undoes before anything is deleted, as an upper bound.
func TestForgetNoticeAndApprovalLine(t *testing.T) {
	r := newForgetRig(t)
	r.task("owner:a", "book a table for friday at the usual place", r.now, viaSMS)
	r.learned["owner:a"] = 2
	r.say("FORGET")
	if got := r.say("FORGET 1"); got != "" || len(r.gate.got) != 1 {
		t.Fatalf("FORGET 1: %q, asked %d", got, len(r.gate.got))
	}
	if obj, detail, ok := r.f.Item("owner:a"); !ok || obj != "'book a table for friday..'" || detail != "undoes 2 things I learned" {
		t.Fatalf("item: %q %q %v", obj, detail, ok)
	}
	r.learned["owner:a"] = 1
	if _, detail, _ := r.f.Item("owner:a"); detail != "undoes 1 thing I learned" {
		t.Fatalf("one: %q", detail)
	}
	r.learned["owner:a"] = 0
	if got := r.say("FORGET LAST"); got != "" {
		t.Fatalf("nothing learned: %q", got)
	}
	if _, detail, _ := r.f.Item("owner:a"); detail != "" {
		t.Fatalf("zero: %q", detail)
	}
	if _, _, ok := r.f.Item("owner:none"); ok {
		t.Fatal("an unknown task has an item")
	}
	r.gate.state = journal.Denied
	if got := r.say("FORGET LAST"); got != "I couldn't ask to forget that task. Try again." {
		t.Fatalf("refused: %q", got)
	}
}

// The carried #160 ruling and UX F1: the reply comes only after every
// save, with the cascade as a count; a failing save is retried until it
// holds, the owner hears "not yet" once after two minutes, and never
// "forgotten" before.
func TestForgetRepliesOnlyAfterEverySave(t *testing.T) {
	r := newForgetRig(t)
	r.learned["owner:a"] = 2
	in := journal.Intent{ID: grants.ForgetID("1", "owner:a"), Origin: grants.OriginForget, Account: journal.BrokerAccount,
		Action: journal.ActionLearnForget, Executor: grants.ForgetExecutor}
	if out := r.f.Execute(context.Background(), in, 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("execute: %+v", out)
	}
	if want := []string{"Forgotten. I also undid 2 things I learned from it; I'll relearn what I can without it."}; strings.Join(r.texts, "|") != want[0] {
		t.Fatalf("texts %q", r.texts)
	}
	r.texts = nil
	r.learned["owner:b"] = 0
	r.fail = 7 // the eighth try holds, past two minutes of backoff
	var waited time.Duration
	done := make(chan struct{})
	r.f.sleep = func(_ context.Context, d time.Duration) bool {
		r.mu.Lock()
		waited += d
		r.now = r.now.Add(d)
		r.mu.Unlock()
		return true
	}
	r.f.retried = func() { close(done) }
	in.ID = grants.ForgetID("2", "owner:b")
	if out := r.f.Execute(context.Background(), in, 1); out.Result != journal.ResultSucceeded {
		t.Fatalf("execute: %+v", out)
	}
	<-done
	r.mu.Lock()
	defer r.mu.Unlock()
	want := "Not forgotten yet: I couldn't save it. I keep trying and will text you when it's done.|Forgotten."
	if strings.Join(r.texts, "|") != want || waited < 2*time.Minute {
		t.Fatalf("texts %q after %v", r.texts, waited)
	}
	if strings.Join(r.forgot, ",") != "owner:a,owner:b" {
		t.Fatalf("forgot %v", r.forgot)
	}
}

// Only the broker's own forget intent runs; anything else is refused.
func TestForgetExecutesOnlyItsOwnIntent(t *testing.T) {
	r := newForgetRig(t)
	for _, in := range []journal.Intent{
		{ID: grants.ForgetID("x1", "owner:a"), Origin: "guest:m1", Account: journal.BrokerAccount, Action: journal.ActionLearnForget},
		{ID: grants.ForgetID("x2", "owner:a"), Origin: grants.OriginForget, Account: journal.BrokerAccount, Action: journal.ActionRecallRollback},
		{ID: "forget/x3", Origin: grants.OriginForget, Account: journal.BrokerAccount, Action: journal.ActionLearnForget},
	} {
		if out := r.f.Execute(context.Background(), in, 1); out.Result != journal.ResultNotApplied {
			t.Fatalf("%s: %+v", in.ID, out)
		}
	}
	if len(r.forgot) != 0 || len(r.texts) != 0 {
		t.Fatalf("forgot %v, texts %q", r.forgot, r.texts)
	}
}

// W3-forget end to end, through the gate and the owner channel: the
// approval is the channel's own request, on its code tier (security C1);
// a YES without the code, or with another request's, forgets nothing;
// the YES with it forgets the task, and the owner is told after.
func TestForgetEndToEnd(t *testing.T) {
	dir := t.TempDir()
	carrier := modem.NewCarrier()
	box, phone := carrier.Line("+15550000100"), carrier.Line(ownerNum)
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"), Modem: box,
	}
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	attachForTest(t, lp, ctx, cancel, d)
	text := func() string {
		t.Helper()
		select {
		case m := <-phone.Inbox():
			return m.Text
		case <-time.After(3 * time.Second):
			t.Fatal("no text to the owner")
		}
		return ""
	}
	say := func(msg string) string { return strings.Join(d.Owner().Handle(ctx, ownerNum, msg), " | ") }
	lp.tasks.put("owner:a", "book a table for friday CANARY-forget", false, viaSMS)
	if got, ok := cfg.Settings(ctx, "FORGET", true); !ok || !strings.Contains(got, `1 "book a table for friday…"`) {
		t.Fatalf("list: %q", got)
	}
	if got, ok := cfg.Settings(ctx, "FORGET 1", true); !ok || got != "" {
		t.Fatalf("FORGET 1: %q", got)
	}
	d.Gate().Flush()
	req := text()
	m := regexp.MustCompile(`^([A-Z][0-9]{1,2}): forget 'book a table for friday\.\.', cannot be undone\. Expires [0-9]{2}:[0-9]{2}\. Reply YES ([A-Z][0-9]{1,2}) ([0-9]{6,8}) or NO ([A-Z][0-9]{1,2})\.$`).FindStringSubmatch(req)
	if m == nil || m[1] != m[2] || m[1] != m[4] {
		t.Fatalf("request: %q", req)
	}
	id, code := m[1], m[3]
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for _, msg := range []string{"YES " + id, "YES " + id + " " + wrong} {
		say(msg)
		d.Gate().Wait()
		if _, ok := lp.tasks.get("owner:a"); !ok || lp.forgotten.has("owner:a") {
			t.Fatalf("%q forgot the task", msg)
		}
	}
	if got := say("YES " + id + " " + code); !strings.HasPrefix(got, "Approved") {
		t.Fatalf("YES: %q", got)
	}
	d.Gate().Wait()
	for {
		if got := text(); got == "Forgotten." {
			break
		}
	}
	if _, ok := lp.tasks.get("owner:a"); ok || !lp.forgotten.has("owner:a") {
		t.Fatal("not forgotten after YES")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "journal.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "CANARY") || strings.Contains(string(raw), "book a table") {
		t.Fatal("the journal holds the task's text")
	}
}
