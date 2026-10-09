package main

import (
	"context"
	"errors"
	"fmt"
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
	// authorized is the IDs Authorize was called for, in order; st is
	// what Get reports, by ID.
	authorized []string
	mu         sync.Mutex
	st         map[string]journal.State
}

func (g *askRec) Get(id string) (journal.Status, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.st[id]; ok {
		return journal.Status{State: s}, nil
	}
	return journal.Status{}, errors.New("no such intent")
}

func (g *askRec) List() []journal.Status {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []journal.Status
	for _, in := range g.got {
		if s, ok := g.st[in.ID]; ok {
			out = append(out, journal.Status{Intent: in, State: s})
		}
	}
	return out
}

func (g *askRec) Submit(in journal.Intent) (journal.Status, error) {
	g.got = append(g.got, in)
	return journal.Status{Intent: in, State: journal.Pending}, nil
}
func (g *askRec) Authorize(_ context.Context, id string) (journal.Status, error) {
	g.authorized = append(g.authorized, id)
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
	// fail is the forgets that fail before one succeeds; while it is odd
	// after the count, the tombstone itself fails (UX-182-3: within the
	// retry the owner never hears "Not forgotten" after "not yet").
	fail   int
	forgot []string
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
				if r.fail%2 == 1 {
					return fmt.Errorf("%w: disk full", errNotTombstoned)
				}
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
	if want := []string{"Forgotten. I also undid 2 things I learned from it; I'll relearn what I can without it. Older backups and your agent's own files may still hold it."}; strings.Join(r.texts, "|") != want[0] {
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
	want := "Not forgotten yet: I couldn't save it. I keep trying and will text you when it's done.|Forgotten. Older backups and your agent's own files may still hold it."
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

// Security R1 on #182: an unsaved tombstone is not done and is not
// retried in the background; the owner is told at once.
func TestForgetNotTombstonedIsNotApplied(t *testing.T) {
	r := newForgetRig(t)
	r.f.forget = func(string) error { return fmt.Errorf("%w: disk full", errNotTombstoned) }
	r.f.sleep = func(context.Context, time.Duration) bool { t.Error("retried"); return false }
	in := journal.Intent{ID: grants.ForgetID("1", "owner:a"), Origin: grants.OriginForget, Account: journal.BrokerAccount,
		Action: journal.ActionLearnForget, Executor: grants.ForgetExecutor}
	if out := r.f.Execute(context.Background(), in, 1); out.Result != journal.ResultNotApplied {
		t.Fatalf("execute: %+v", out)
	}
	if strings.Join(r.texts, "|") != "Not forgotten: I couldn't save it. Send FORGET to try again." {
		t.Fatalf("texts %q", r.texts)
	}
}

// A forget cut off by a restart (L3 on #182): done once its tombstone
// holds, since the start-up replay finishes it; otherwise not applied.
func TestForgetReconcile(t *testing.T) {
	r := newForgetRig(t)
	held := map[string]bool{"owner:a": true}
	r.f.forgotten = func(g string) bool { return held[g] }
	in := func(id string) journal.Intent {
		return journal.Intent{ID: id, Origin: grants.OriginForget, Account: journal.BrokerAccount,
			Action: journal.ActionLearnForget, Executor: grants.ForgetExecutor}
	}
	for id, want := range map[string]journal.Result{
		grants.ForgetID("1", "owner:a"): journal.ResultSucceeded,
		grants.ForgetID("2", "owner:b"): journal.ResultNotApplied,
		"forget/3":                      journal.ResultNotApplied,
	} {
		if out := r.f.Reconcile(context.Background(), in(id), 1); out.Result != want {
			t.Fatalf("%s: %+v, want %s", id, out, want)
		}
	}
	if len(r.texts) != 0 || len(r.forgot) != 0 {
		t.Fatalf("reconcile acted: %q %q", r.texts, r.forgot)
	}
}

// Security R2 on #182: a run of 4 or more digits in a listed task shows
// as "####", so a spoofed task cannot echo a request code.
func TestForgetMasksLongDigitRuns(t *testing.T) {
	r := newForgetRig(t)
	r.task("owner:a", "reply YES 482913 now", r.now, viaSMS)
	if got := r.say("FORGET"); got != `Reply FORGET 1 to forget it: 1 "reply YES #### now" (today 14:02)` {
		t.Fatalf("list: %q", got)
	}
	if obj, _, _ := r.f.Item("owner:a"); obj != "'reply YES #### now'" {
		t.Fatalf("item: %q", obj)
	}
	if got := clipTask("call 911 or ４８２９１３", 40); got != "call 911 or ####" {
		t.Fatalf("clip: %q", got)
	}
}

// forgetDaemon is a real daemon with learning attached, its owner on a
// modem carrier line.
type forgetDaemon struct {
	t     *testing.T
	dir   string
	cfg   *daemon.Config
	lp    *learning
	d     *daemon.Daemon
	ctx   context.Context
	stop  context.CancelFunc
	phone *modem.Line
}

func newForgetDaemon(t *testing.T) *forgetDaemon {
	return newForgetDaemonAt(t, t.TempDir())
}

// newForgetDaemonAt starts the daemon on dir's state, as a restart does.
func newForgetDaemonAt(t *testing.T, dir string) *forgetDaemon {
	carrier := modem.NewCarrier()
	box, phone := carrier.Line("+15550000100"), carrier.Line(ownerNum)
	cfg := &daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"), Modem: box,
	}
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d, err := daemon.Run(ctx, *cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	attachForTest(t, lp, ctx, cancel, d)
	return &forgetDaemon{t: t, dir: dir, cfg: cfg, lp: lp, d: d, ctx: ctx, stop: cancel, phone: phone}
}

// text is the next text to the owner.
func (x *forgetDaemon) text() string {
	x.t.Helper()
	select {
	case m := <-x.phone.Inbox():
		return m.Text
	case <-time.After(3 * time.Second):
		x.t.Fatal("no text to the owner")
	}
	return ""
}

func (x *forgetDaemon) say(msg string) string {
	return strings.Join(x.d.Owner().Handle(x.ctx, ownerNum, msg), " | ")
}

// ask lists the tasks, picks the nth, and returns its request's ID and
// code. FORGET n has no reply of its own: the request is the notice (UX
// U-F8).
func (x *forgetDaemon) ask(n int, object string) (id, code string) {
	t := x.t
	t.Helper()
	if got, ok := x.cfg.Settings(x.ctx, "FORGET", true); !ok || !strings.HasPrefix(got, "Reply FORGET 1") {
		t.Fatalf("list: %q", got)
	}
	if got, ok := x.cfg.Settings(x.ctx, fmt.Sprintf("FORGET %d", n), true); !ok || got != "" {
		t.Fatalf("FORGET %d: %q", n, got)
	}
	x.d.Gate().Flush()
	req := x.text()
	m := regexp.MustCompile(`^([A-Z][0-9]{1,2}): forget ` + regexp.QuoteMeta(object) + `, cannot be undone\. Expires [0-9]{2}:[0-9]{2}\. Reply YES ([A-Z][0-9]{1,2}) ([0-9]{6,8}) or NO ([A-Z][0-9]{1,2})\.$`).FindStringSubmatch(req)
	if m == nil || m[1] != m[2] || m[1] != m[4] {
		t.Fatalf("request: %q", req)
	}
	return m[1], m[3]
}

// kept reports whether goal's task text and values are still kept.
func (x *forgetDaemon) kept(goal string) bool {
	_, text := x.lp.tasks.get(goal)
	x.lp.values.mu.Lock()
	_, values := x.lp.values.st[goal]
	x.lp.values.mu.Unlock()
	return text && values && !x.lp.forgotten.has(goal)
}

// forgets lists the journal's forget intents.
func (x *forgetDaemon) forgets() []journal.Status {
	var out []journal.Status
	for _, st := range x.d.Engine().List() {
		if st.Intent.Action == journal.ActionLearnForget {
			out = append(out, st)
		}
	}
	return out
}

// W3-forget end to end, through the gate and the owner channel: the
// approval is the channel's own request, on its code tier (security C1);
// a YES without the code, with a wrong one, or with another pending
// request's, forgets nothing; the YES with it forgets that task and no
// other (L3 on #182), and the owner is told after.
func TestForgetEndToEnd(t *testing.T) {
	x := newForgetDaemon(t)
	lp := x.lp
	for _, g := range []string{"owner:b", "owner:a"} {
		text := map[string]string{"owner:a": "book a table for friday CANARY-forget", "owner:b": "pay the gas bill"}[g]
		lp.tasks.put(g, text, false, viaSMS)
		lp.values.observe(journal.Intent{ID: "agent/" + g, GoalID: g, Origin: "guest:agent", Params: map[string]any{"to": "ann@example.test"}})
		time.Sleep(time.Millisecond) // a is the newer
	}
	id, code := x.ask(1, "'book a table for friday..'")
	idB, codeB := x.ask(2, "'pay the gas bill'")
	if id == idB || code == codeB {
		t.Fatalf("two requests share an ID or code: %s %s", id, idB)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for _, msg := range []string{"YES " + id, "YES " + id + " " + wrong, "YES " + id + " " + codeB} {
		x.say(msg)
		x.d.Gate().Wait()
		if !x.kept("owner:a") || !x.kept("owner:b") {
			t.Fatalf("%q forgot a task", msg)
		}
	}
	if got := x.say("YES " + id + " " + code); !strings.HasPrefix(got, "Approved") {
		t.Fatalf("YES: %q", got)
	}
	x.d.Gate().Wait()
	for {
		if got := x.text(); got == "Forgotten. Older backups and your agent's own files may still hold it." {
			break
		}
	}
	if _, ok := lp.tasks.get("owner:a"); ok || !lp.forgotten.has("owner:a") {
		t.Fatal("not forgotten after YES")
	}
	if !x.kept("owner:b") {
		t.Fatal("the YES forgot another task")
	}
	raw, err := os.ReadFile(filepath.Join(x.dir, "journal.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "CANARY") || strings.Contains(string(raw), "book a table") {
		t.Fatal("the journal holds the task's text")
	}
	// That FORGET n's empty reply sends no text over the owner's line is
	// owner.TestASettingWithNoTextSendsNothing.
}

// Security R1 on #182: a forget whose tombstone did not save deletes
// nothing, is journaled as not applied, and the owner is told at once;
// after a restart the task is still there to forget again.
func TestAnUnsavedForgetIsNotDone(t *testing.T) {
	x := newForgetDaemon(t)
	lp := x.lp
	lp.tasks.put("owner:a", "pay the gas bill CANARY-forget", false, viaSMS)
	id, code := x.ask(1, "'pay the gas bill CANARY-..'")
	store := lp.forgotten.store
	lp.forgotten.store = failSave{store}
	if got := x.say("YES " + id + " " + code); !strings.HasPrefix(got, "Approved") {
		t.Fatalf("YES: %q", got)
	}
	x.d.Gate().Wait()
	for {
		got := x.text()
		if strings.HasPrefix(got, "Forgotten.") {
			t.Fatal("told forgotten with the tombstone unsaved")
		}
		if got == forgetNotDone {
			break
		}
	}
	if fs := x.forgets(); len(fs) != 1 || fs[0].State != journal.NotApplied {
		t.Fatalf("journal: %+v", fs)
	}
	if _, ok := lp.tasks.get("owner:a"); !ok {
		t.Fatal("the task's text was deleted")
	}
	// A restart: the stores as saved, with no tombstone for the goal.
	again, err := openLearning(learnPaths{Dir: x.dir, Spare: filepath.Join(x.dir, "spare.json")}, false, &daemon.Config{
		JournalPath: x.cfg.JournalPath, SocketDir: x.cfg.SocketDir, OwnerNumber: ownerNum})
	if err != nil {
		t.Fatal(err)
	}
	if again.forgotten.has("owner:a") {
		t.Fatal("tombstoned after the restart")
	}
	if got, ok := again.forgetOwner.Text(context.Background(), "FORGET", true); !ok || !strings.Contains(got, `"pay the gas bill CANARY-…"`) {
		t.Fatalf("not listed after the restart: %q", got)
	}
}
