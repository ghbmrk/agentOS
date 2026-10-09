package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recalltool"
)

// REQ: CAP-3, OP-5

// fakeWork is recall's Reach as FORGET's item 2 sees it.
type fakeWork struct {
	mu      sync.Mutex
	worked  bool
	ok      bool
	err     error
	lineage []string
	backs   []time.Time
	asked   []bool // approved, per take-back
	actions int
	noCount bool          // the count is not known
	closed  bool          // recall is not open: Handled is not known
	slow    time.Duration // Handled answers after this long
	// recorded: recall holds a take-back as owed, not done, so Handled
	// is true though nothing was taken back.
	recorded bool
	// state, if set, is TakeBackOf's answer for a take-back from that
	// time (RCH-1); unset, one taken back is done and one recorded owed.
	state map[time.Time]recalltool.TakeBackState
}

func (w *fakeWork) TakeBackOf(since time.Time) (recalltool.TakeBackState, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return recalltool.TakeBackNone, false
	}
	for t, st := range w.state {
		if t.Equal(since) {
			return st, true
		}
	}
	for _, b := range w.backs {
		if b.Equal(since) {
			return recalltool.TakeBackDone, true
		}
	}
	if w.recorded {
		return recalltool.TakeBackOwed, true
	}
	return recalltool.TakeBackNone, true
}

// setState sets TakeBackOf's answer for since.
func (w *fakeWork) setState(since time.Time, st recalltool.TakeBackState) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state == nil {
		w.state = map[time.Time]recalltool.TakeBackState{}
	}
	w.state[since] = st
}

// Handled answers, then waits slow before returning, so runs that overlap
// all read the answer before any of them takes back.
func (w *fakeWork) Handled(since time.Time) (bool, bool) {
	w.mu.Lock()
	handled, ok, slow := w.recorded, !w.closed, w.slow
	for _, b := range w.backs {
		if b.Equal(since) {
			handled = true
		}
	}
	w.mu.Unlock()
	time.Sleep(slow)
	return handled, ok
}

func (w *fakeWork) Actions(lineage string, since time.Time) (int, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.actions, !w.noCount
}

func (w *fakeWork) Work(lineage string, since time.Time) (bool, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.worked, w.ok
}

func (w *fakeWork) TakeBack(_ context.Context, lineage string, since time.Time, approved bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	w.lineage, w.backs = append(w.lineage, lineage), append(w.backs, since)
	w.asked = append(w.asked, approved)
	return nil
}

func (r *forgetRig) withAgent(w *fakeWork) {
	r.f.agent.Store(&forgetAgent{work: w, lineage: func() (string, error) { return "agent.l1", nil }})
}

// W3-forget-b2b: the agent's work since the task is the request's item
// 2 only when the agent worked since it (the ask-first rule), with the
// notice before the request; otherwise the request is item 1 alone.
func TestForgetAsksItem2OnlyWhenTheAgentWorked(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	for _, c := range []struct {
		name       string
		work       *fakeWork
		wantItem2  bool
		wantNotice bool
	}{
		{"worked", &fakeWork{worked: true, ok: true}, true, true},
		{"no work", &fakeWork{ok: true}, false, false},
		{"not known", &fakeWork{worked: true}, false, false},
		{"no agent", nil, false, false},
	} {
		r := newForgetRig(t)
		if c.work != nil {
			r.withAgent(c.work)
		}
		r.task("owner:a", "pay the gas bill", at, viaSMS)
		if got := r.say("FORGET LAST"); got != "" {
			t.Fatalf("%s: reply %q", c.name, got)
		}
		ids := []string{}
		for _, in := range r.gate.got {
			ids = append(ids, in.ID)
		}
		if !c.wantItem2 {
			if len(ids) != 1 || grants.ForgetGoal(ids[0]) != "owner:a" || len(r.texts) != 0 {
				t.Fatalf("%s: %v %q", c.name, ids, r.texts)
			}
			continue
		}
		if len(ids) != 2 || grants.ForgetGoal(ids[0]) != "owner:a" || ids[1] != grants.ForgetSibling(ids[0]) {
			t.Fatalf("%s: intents %v", c.name, ids)
		}
		in := r.gate.got[1]
		if in.Origin != grants.OriginForget || in.Executor != grants.ForgetExecutor || in.Action != journal.ActionLearnForget || in.Params["agent"] != true || len(in.Params) != 2 || in.Params["actions"] != 0 {
			t.Fatalf("%s: item 2 %+v", c.name, in)
		}
		if strings.Join(r.gate.authorized, " ") != strings.Join(ids, " ") {
			t.Fatalf("%s: authorized %v", c.name, r.gate.authorized)
		}
		if len(r.texts) != 1 || r.texts[0] != forgetAgentNotice ||
			!strings.Contains(r.texts[0], "Approve only item 1 to keep that work; your agent then still holds the task.") {
			t.Fatalf("%s: notice %q", c.name, r.texts)
		}
		if since, ok := forgetSince(ids[1]); !ok || !since.Equal(at) {
			t.Fatalf("%s: since %v", c.name, since)
		}
		if obj, _, ok := r.f.AgentItem(ids[1]); !ok || obj != "your agent's work since Mon 5 Oct 13:02" {
			t.Fatalf("%s: item 2 line %q", c.name, obj)
		}
	}
}

// Item 2 is never asked without item 1: when item 1 is not left
// pending for the owner, item 2 is not authorized.
func TestForgetNeverAsksItem2Alone(t *testing.T) {
	r := newForgetRig(t)
	r.withAgent(&fakeWork{worked: true, ok: true})
	r.gate.state = journal.Denied
	r.task("owner:a", "pay the gas bill", r.now.Add(-time.Hour), viaSMS)
	if got := r.say("FORGET LAST"); got != forgetRefused {
		t.Fatalf("reply %q", got)
	}
	if len(r.gate.authorized) != 1 || grants.ForgetGoal(r.gate.authorized[0]) != "owner:a" {
		t.Fatalf("authorized %v", r.gate.authorized)
	}
}

// Item 2 takes the agent back to the task's time only when item 1 is
// approved too; approved without item 1 it takes nothing back and the
// owner gets a plain reply.
func TestForgetItem2RunsOnlyWithItem1(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	for _, c := range []struct {
		name  string
		item1 journal.State // "" : no item 1 in the journal
		want  journal.Result
		text  string
	}{
		{"with item 1", journal.Succeeded, journal.ResultSucceeded, forgetAgentDone},
		{"item 1 not chosen", journal.Denied, journal.ResultNotApplied, forgetAgentAlone},
		{"item 1 approved, not run yet", journal.Authorized, journal.ResultSucceeded, forgetAgentDone},
		{"item 1 approved, not saved", journal.NotApplied, journal.ResultNotApplied, forgetAgentAlone},
		{"item 1 never settles", journal.Pending, journal.ResultNotApplied, forgetAgentAlone},
		{"no item 1", "", journal.ResultNotApplied, forgetAgentAlone},
	} {
		r := newForgetRig(t)
		w := &fakeWork{worked: true, ok: true}
		r.withAgent(w)
		r.task("owner:a", "pay the gas bill", at, viaSMS)
		r.say("FORGET LAST")
		id1 := r.gate.got[0].ID
		r.texts = nil
		if c.item1 != "" {
			r.gate.st = map[string]journal.State{id1: c.item1}
		}
		out := r.f.Execute(context.Background(), r.gate.got[1], 1)
		if out.Result != c.want || len(r.texts) != 1 || r.texts[0] != c.text {
			t.Fatalf("%s: %+v %q", c.name, out, r.texts)
		}
		if c.want == journal.ResultSucceeded {
			if len(w.backs) != 1 || !w.backs[0].Equal(at) || w.lineage[0] != "agent.l1" || !w.asked[0] {
				t.Fatalf("%s: took back %v %v", c.name, w.lineage, w.backs)
			}
		} else if len(w.backs) != 0 {
			t.Fatalf("%s: took back without item 1", c.name)
		}
		if len(r.forgot) != 0 {
			t.Fatalf("%s: item 2 forgot the task", c.name)
		}
	}
}

// #327 L3 1, 2: item 2 never repeats its take-back. One that fails after
// recall recorded it owed is left to recall's Retry, which tells the owner
// when it is done; one that fails before is carried by the forget
// (forget_owed_test.go, W3-forget-b2c).
func TestForgetItem2LeavesAFailedTakeBackToRecall(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want journal.Result
		text string
	}{
		{"owed", fmt.Errorf("%w: machine busy", recalltool.ErrCarried), journal.ResultSucceeded, forgetAgentNotYet},
		// W3-forget-b2c-f1 F1-4 (L3 on #427, release 2): recall not open
		// is owed to its next open, never retried here.
		{"recall not open", recalltool.ErrNotOpen, journal.ResultSucceeded, forgetAgentNotOpen},
	} {
		r := newForgetRig(t)
		w := &fakeWork{worked: true, ok: true, err: c.err}
		r.withAgent(w)
		r.task("owner:a", "pay the gas bill", r.now.Add(-time.Hour), viaSMS)
		r.say("FORGET LAST")
		r.gate.st = map[string]journal.State{r.gate.got[0].ID: journal.Succeeded}
		r.texts = nil
		r.f.sleep = func(context.Context, time.Duration) bool { t.Fatalf("%s: retried", c.name); return false }
		if out := r.f.Execute(context.Background(), r.gate.got[1], 1); out.Result != c.want || len(r.texts) != 1 || r.texts[0] != c.text {
			t.Fatalf("%s: %+v %q", c.name, out, r.texts)
		}
	}
}

// #327 L3 2: an approved item 2 interrupted by a restart is taken back
// once recall opens (recall does not repeat one already done), and only
// with item 1 approved.
func TestForgetItem2ResumesAfterARestart(t *testing.T) {
	for _, c := range []struct {
		name  string
		item1 journal.State
		text  string
		backs int
	}{
		{"with item 1", journal.Succeeded, forgetAgentDone, 1},
		{"item 1 not chosen", journal.Denied, forgetAgentAlone, 0},
	} {
		r := newForgetRig(t)
		w := &fakeWork{worked: true, ok: true}
		r.withAgent(w)
		r.task("owner:a", "pay the gas bill", r.now.Add(-time.Hour), viaSMS)
		r.say("FORGET LAST")
		r.gate.st = map[string]journal.State{r.gate.got[0].ID: c.item1}
		r.texts = nil
		if out := r.f.Reconcile(context.Background(), r.gate.got[1], 1); out.Result != journal.ResultSucceeded {
			t.Fatalf("%s: %+v", c.name, out)
		}
		if len(w.backs) != 0 || len(r.texts) != 0 {
			t.Fatalf("%s: taken back before recall opened", c.name)
		}
		r.f.resumeAgent(context.Background())
		r.f.resumeAgent(context.Background()) // once only
		if len(w.backs) != c.backs || len(r.texts) != 1 || r.texts[0] != c.text || (c.backs > 0 && !w.asked[0]) {
			t.Fatalf("%s: took back %v asked %v, told %q", c.name, w.backs, w.asked, r.texts)
		}
	}
}

// With no item 2 (the agent had not worked since the task), item 1's YES
// also takes the agent back, without asking, if it still has not worked;
// work since the ask is kept and the done text says the agent may hold
// the task.
func TestForgetItem1TakesBackAnIdleAgent(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	for _, c := range []struct {
		name      string
		laterWork bool
		sibling   bool
		back      bool
	}{
		{"still idle", false, false, true},
		{"worked since the ask", true, false, false},
		{"item 2 asked", false, true, false},
	} {
		r := newForgetRig(t)
		w := &fakeWork{ok: true}
		r.withAgent(w)
		r.task("owner:a", "pay the gas bill", at, viaSMS)
		r.say("FORGET LAST")
		if len(r.gate.got) != 1 {
			t.Fatalf("%s: %d intents", c.name, len(r.gate.got))
		}
		in := r.gate.got[0]
		if c.sibling {
			r.gate.st = map[string]journal.State{grants.ForgetSibling(in.ID): journal.Pending}
		}
		w.worked = c.laterWork
		out := r.f.Execute(context.Background(), in, 1)
		want := "Forgotten. Older backups and your agent's own files may still hold it."
		if c.back {
			want = "Forgotten. Older backups may still hold it."
		}
		if out.Result != journal.ResultSucceeded || len(r.texts) != 1 || r.texts[0] != want {
			t.Fatalf("%s: %+v %q", c.name, out, r.texts)
		}
		if (len(w.backs) == 1) != c.back || c.back && !w.backs[0].Equal(at) {
			t.Fatalf("%s: took back %v", c.name, w.backs)
		}
	}
}

// End to end through the gate and the owner channel: the notice comes
// first, then one request with the forget as item 1 and the take-back as
// item 2; YES for item 2 alone takes nothing back and says so plainly,
// and YES for both forgets the task and takes the agent back to it.
func TestForgetItem2EndToEnd(t *testing.T) {
	x := newForgetDaemon(t)
	w := &fakeWork{worked: true, ok: true}
	x.lp.forgetOwner.agent.Store(&forgetAgent{work: w, lineage: func() (string, error) { return "agent.l1", nil }})
	x.lp.tasks.put("owner:a", "pay the gas bill", false, viaSMS)
	if got, ok := x.cfg.Settings(x.ctx, "FORGET", true); !ok || !strings.HasPrefix(got, "Reply FORGET 1") {
		t.Fatalf("list: %q", got)
	}
	ask := func() (id, code string) {
		t.Helper()
		if got, ok := x.cfg.Settings(x.ctx, "FORGET 1", true); !ok || got != "" {
			t.Fatalf("FORGET 1: %q", got)
		}
		if got := x.text(); got != forgetAgentNotice {
			t.Fatalf("notice: %q", got)
		}
		x.d.Gate().Flush()
		req := x.text()
		m := regexp.MustCompile(`^([A-Z][0-9]{1,2}): 2 items\. 1 forget 'pay the gas bill', cannot be undone\. 2 forget your agent's work since [A-Z][a-z]{2} [0-9]{1,2} [A-Z][a-z]{2} [0-9]{2}:[0-9]{2}, no actions yet, cannot be undone\. Expires [0-9]{2}:[0-9]{2}\. Reply YES ([A-Z][0-9]{1,2}) ([0-9]{6,8}) for all`).FindStringSubmatch(req)
		if m == nil || m[1] != m[2] {
			t.Fatalf("request: %q", req)
		}
		return m[1], m[3]
	}
	id, code := ask()
	if got := x.say("YES " + id + " 2 " + code); !strings.HasPrefix(got, "Approved") {
		t.Fatalf("YES 2: %q", got)
	}
	x.d.Gate().Wait()
	if got := x.text(); got != forgetAgentAlone {
		t.Fatalf("item 2 alone: %q", got)
	}
	if _, ok := x.lp.tasks.get("owner:a"); !ok || len(w.backs) != 0 {
		t.Fatal("item 2 alone forgot or took back")
	}
	id, code = ask()
	if got := x.say("YES " + id + " " + code); !strings.HasPrefix(got, "Approved") {
		t.Fatalf("YES: %q", got)
	}
	x.d.Gate().Wait()
	got := map[string]bool{x.text(): true, x.text(): true}
	if !got[forgetAgentDone] || !got["Forgotten. Older backups and your agent's own files may still hold it."] {
		t.Fatalf("done texts: %v", got)
	}
	if _, ok := x.lp.tasks.get("owner:a"); ok || len(w.backs) != 1 {
		t.Fatalf("after YES: took back %v", w.backs)
	}
}

// #327 UX lens B1 (CAP-3, DECISIONS 2026-10-05): item 2 names the work so
// far, and that actions taken stay done; no text claims they are undone.
// The count is fixed when asked, in item 2's params, so a re-issue asks
// what was asked (#327 L3 B-1); one not known is not named.
func TestForgetItem2NamesTheActionsThatStayDone(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	for _, c := range []struct {
		n       int
		noCount bool
		want    any
	}{
		{0, false, "no actions yet"},
		{1, false, "1 action so far stays done"},
		{3, false, "3 actions so far stay done"},
		{0, true, ""},
	} {
		r := newForgetRig(t)
		w := &fakeWork{worked: true, ok: true, actions: c.n, noCount: c.noCount}
		r.withAgent(w)
		r.task("owner:a", "pay the gas bill", at, viaSMS)
		r.say("FORGET LAST")
		if len(r.gate.got) != 2 || grants.ForgetAgentActions(r.gate.got[1].Params) != c.want {
			t.Fatalf("%+v: item 2 %+v", c, r.gate.got)
		}
		w.actions, w.noCount = 7, false // the agent acts while the owner reads
		if _, d, ok := r.f.AgentItem(r.gate.got[1].ID); !ok || d != "" {
			t.Fatalf("%+v: live detail %q", c, d)
		}
	}
	for _, s := range []string{forgetAgentNotice, forgetAgentDone, forgetAgentNotYet} {
		if strings.Contains(s, "undone") || !strings.Contains(s, "stay done") && s != forgetAgentNotYet {
			t.Fatalf("claims the work is undone, or not that actions stay done: %q", s)
		}
	}
}

// #327 UX lens B2 (CH-12): item 1 has forgotten the task, so a text about
// item 2 never offers FORGET again, a step that cannot fix it.
func TestForgetItem2NeverOffersAFruitlessForget(t *testing.T) {
	for _, s := range []string{forgetAgentNoAgent, forgetAgentNotTaken, forgetAgentNotOpen, forgetAgentWhenOpen} {
		if strings.Contains(s, "FORGET") {
			t.Fatalf("offers FORGET again: %q", s)
		}
	}
}

// #327 L3 B-3 (CH-12): an approved item 2 that finds memory not open yet
// (a request re-issued after a restart, answered before the vault is
// unlocked) is taken back once recall opens, and the owner is told so;
// with recall off it is owed to a later boot (W3-forget-b2c), and the
// owner is told that.
func TestForgetItem2WaitsForMemoryToOpen(t *testing.T) {
	for _, off := range []bool{false, true} {
		r := newForgetRig(t)
		w := &fakeWork{worked: true, ok: true, err: recalltool.ErrNotOpen}
		r.withAgent(w)
		opens := 0
		if !off {
			r.f.whenOpen = func() { opens++ }
		}
		r.task("owner:a", "pay the gas bill", r.now.Add(-time.Hour), viaSMS)
		r.say("FORGET LAST")
		r.gate.st = map[string]journal.State{r.gate.got[0].ID: journal.Succeeded}
		r.texts = nil
		out := r.f.Execute(context.Background(), r.gate.got[1], 1)
		want, res := forgetAgentWhenOpen, journal.ResultSucceeded
		if off {
			want = forgetAgentNotOpen
		}
		if out.Result != res || len(r.texts) != 1 || r.texts[0] != want || opens != map[bool]int{false: 1, true: 0}[off] {
			t.Fatalf("off %v: %+v %q, %d opens", off, out, r.texts, opens)
		}
		w.err = nil
		r.texts = nil
		r.f.resumeAgent(context.Background())
		if wantBacks := map[bool]int{false: 1, true: 0}[off]; len(w.backs) != wantBacks || wantBacks == 1 && (len(r.texts) != 1 || r.texts[0] != forgetAgentDone) {
			t.Fatalf("off %v: once open, took back %v, told %q", off, w.backs, r.texts)
		}
	}
}

// REQ: CAP-3, OP-5
// YES for both items settles them concurrently: item 1 may forget the
// task before item 2 is authorized, and item 2's line must still stand,
// from its own ID, or the take-back is denied unasked (#327 CI on c61b293).
func TestForgetItem2LineOutlivesItem1(t *testing.T) {
	r := newForgetRig(t)
	at := r.now.Add(-time.Hour)
	r.withAgent(&fakeWork{worked: true, ok: true})
	r.task("owner:a", "pay the gas bill", at, viaSMS)
	r.say("FORGET LAST")
	if len(r.gate.got) != 2 {
		t.Fatalf("intents %+v", r.gate.got)
	}
	id := r.gate.got[1].ID
	before, _, ok := r.f.AgentItem(id)
	if !ok || before != "your agent's work since "+r.f.date(at) {
		t.Fatalf("line %q", before)
	}
	if ok, err := r.tasks.forget("owner:a"); !ok || err != nil {
		t.Fatalf("forget: %v %v", ok, err)
	}
	if after, _, ok := r.f.AgentItem(id); !ok || after != before {
		t.Fatalf("after item 1: %q %v", after, ok)
	}
	if _, _, ok := r.f.AgentItem(grants.ForgetSibling(id)); ok {
		t.Fatal("item 1's ID gave an item 2 line")
	}
}

// REQ: CAP-3, OP-3
// The request's lines name the task's time as a date, not "today": a
// re-issue after midnight keeps both items' lines, so item 2 is never
// closed while item 1 is asked again alone (#327 L3 re-review 1).
func TestForgetItemLinesHoldAcrossMidnight(t *testing.T) {
	for _, via := range []string{viaSMS, "loop"} {
		r := newForgetRig(t)
		at := r.now.Add(-time.Hour)
		r.task("owner:a", "pay the gas bill", at, via)
		id2 := grants.ForgetAgentID(fmt.Sprintf("1.1.%d", at.UnixNano()), "owner:a")
		o1, d1, _ := r.f.Item("owner:a")
		o2, d2, _ := r.f.AgentItem(id2)
		r.now = r.now.Add(12 * time.Hour) // past midnight
		n1, e1, _ := r.f.Item("owner:a")
		n2, e2, _ := r.f.AgentItem(id2)
		if o1 != n1 || d1 != e1 || o2 != n2 || d2 != e2 {
			t.Fatalf("via %s: %q %q / %q %q became %q %q / %q %q", via, o1, d1, o2, d2, n1, e1, n2, e2)
		}
		if strings.Contains(o1+o2, "today") || !strings.Contains(o2, "Mon 5 Oct 13:02") {
			t.Fatalf("via %s: lines %q, %q", via, o1, o2)
		}
	}
}

// REQ: CAP-3, OP-5
// An approved item 2 queued until memory opens is kept by the journal,
// not only in memory: after a restart, or when memory did not open in
// the boot that queued it, it is taken back once memory opens, once
// (#327 L3 re-review 2). With recall off, the journal's item 2s are left
// alone: nothing can take them back.
func TestForgetItem2QueuedOutlivesARestart(t *testing.T) {
	for _, off := range []bool{false, true} {
		r := newForgetRig(t)
		w := &fakeWork{worked: true, ok: true, err: recalltool.ErrNotOpen}
		r.withAgent(w)
		r.f.whenOpen = func() {}
		r.task("owner:a", "pay the gas bill", r.now.Add(-time.Hour), viaSMS)
		r.say("FORGET LAST")
		r.gate.st = map[string]journal.State{r.gate.got[0].ID: journal.Succeeded}
		if out := r.f.Execute(context.Background(), r.gate.got[1], 1); out.Result != journal.ResultSucceeded {
			t.Fatalf("queued: %+v", out)
		}
		r.gate.st[r.gate.got[1].ID] = journal.Succeeded
		// A restart: the queue in memory is gone, the journal holds item 2.
		r.f.mu.Lock()
		r.f.interrupted = nil
		r.f.mu.Unlock()
		w.err, w.closed = nil, off
		if off {
			r.f.whenOpen = nil
		}
		for i := 0; i < 2; i++ {
			r.texts = nil
			r.f.resumeAgent(context.Background())
			want := map[bool]int{false: 1, true: 0}[off]
			if len(w.backs) != want {
				t.Fatalf("off %v, open %d: took back %v", off, i, w.backs)
			}
			if told := i == 0 && !off; told && (len(r.texts) != 1 || r.texts[0] != forgetAgentDone) || !told && len(r.texts) != 0 {
				t.Fatalf("off %v, open %d: told %q", off, i, r.texts)
			}
		}
	}
}

// REQ: CAP-3, OP-5
// Recall's open runs every resume registered for it at once (the one at
// start and one per queued item 2): the journal's item 2 is taken back
// once and the owner told once (#327 L3 round 4 B1).
func TestForgetItem2ResumesOnceWhenRunsOverlap(t *testing.T) {
	r := newForgetRig(t)
	w := &fakeWork{worked: true, ok: true}
	r.withAgent(w)
	r.f.whenOpen = func() {}
	r.task("owner:a", "pay the gas bill", r.now.Add(-time.Hour), viaSMS)
	r.say("FORGET LAST")
	r.gate.st = map[string]journal.State{r.gate.got[0].ID: journal.Succeeded, r.gate.got[1].ID: journal.Succeeded}
	w.slow = 20 * time.Millisecond
	r.texts = nil
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.f.resumeAgent(context.Background()) }()
	}
	wg.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(w.backs) != 1 || len(r.texts) != 1 || r.texts[0] != forgetAgentDone {
		t.Fatalf("took back %v, told %q", w.backs, r.texts)
	}
}

// W3-forget-reach RCH-5 (brief ID).
// REQ: CAP-3

// W3-forget-reach: item 1's idle take-back drops the tail's caveat only
// once recall says it is done; one whose reset is unfinished or not
// recorded keeps "your agent's own files may still hold it".
func TestForgetItem1TailKeepsTheCaveatUntilTheTakeBackIsDone(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 2, 0, 0, time.UTC)
	for _, st := range []recalltool.TakeBackState{recalltool.TakeBackOwed, recalltool.TakeBackNone} {
		r := newForgetRig(t)
		w := &fakeWork{ok: true}
		w.setState(at, st)
		r.withAgent(w)
		r.task("owner:a", "pay the gas bill", at, viaSMS)
		r.say("FORGET LAST")
		out := r.f.Execute(context.Background(), r.gate.got[0], 1)
		want := "Forgotten. Older backups and your agent's own files may still hold it."
		if out.Result != journal.ResultSucceeded || len(w.backs) != 1 || len(r.texts) != 1 || r.texts[0] != want {
			t.Fatalf("%v: %+v took back %v told %q", st, out, w.backs, r.texts)
		}
	}
}
