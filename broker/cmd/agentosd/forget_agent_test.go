package main

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
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
}

func (w *fakeWork) Work(lineage string, since time.Time) (bool, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.worked, w.ok
}

func (w *fakeWork) TakeBack(_ context.Context, lineage string, since time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	w.lineage, w.backs = append(w.lineage, lineage), append(w.backs, since)
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
		if in.Origin != grants.OriginForget || in.Executor != grants.ForgetExecutor || in.Action != journal.ActionLearnForget || len(in.Params) != 1 || in.Params["agent"] != true {
			t.Fatalf("%s: item 2 %+v", c.name, in)
		}
		if strings.Join(r.gate.authorized, " ") != strings.Join(ids, " ") {
			t.Fatalf("%s: authorized %v", c.name, r.gate.authorized)
		}
		if len(r.texts) != 1 || r.texts[0] != forgetAgentNotice ||
			!strings.Contains(r.texts[0], "Approve only item 1 to keep that work; your agent then still holds the task until that work is undone.") {
			t.Fatalf("%s: notice %q", c.name, r.texts)
		}
		if since, ok := forgetSince(ids[1]); !ok || !since.Equal(at) {
			t.Fatalf("%s: since %v", c.name, since)
		}
		if obj, _, ok := r.f.AgentItem("owner:a"); !ok || obj != "your agent's work since today 13:02" {
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
		{"item 1 approved, not saved", journal.NotApplied, journal.ResultSucceeded, forgetAgentDone},
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
			if len(w.backs) != 1 || !w.backs[0].Equal(at) || w.lineage[0] != "agent.l1" {
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

// A take-back that fails is retried until it holds, and the owner hears
// it is done only then; a restart reports the approved item 2 as recall
// reports its own rollbacks.
func TestForgetItem2RetriesItsTakeBack(t *testing.T) {
	r := newForgetRig(t)
	w := &fakeWork{worked: true, ok: true, err: errors.New("machine busy")}
	r.withAgent(w)
	r.task("owner:a", "pay the gas bill", r.now.Add(-time.Hour), viaSMS)
	r.say("FORGET LAST")
	r.gate.st = map[string]journal.State{r.gate.got[0].ID: journal.Succeeded}
	r.texts = nil
	done := make(chan struct{})
	r.f.retried = func() { close(done) }
	tries := 0
	r.f.sleep = func(context.Context, time.Duration) bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		if tries++; tries == 3 {
			w.err = nil
		}
		return true
	}
	if out := r.f.Execute(context.Background(), r.gate.got[1], 1); out.Result != journal.ResultSucceeded {
		t.Fatal(out)
	}
	<-done
	if len(w.backs) != 1 || len(r.texts) != 1 || r.texts[0] != forgetAgentDone {
		t.Fatalf("retry: %v %q", w.backs, r.texts)
	}
	if out := r.f.Reconcile(context.Background(), r.gate.got[1], 1); out.Result != journal.ResultSucceeded {
		t.Fatal(out)
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
		m := regexp.MustCompile(`^([A-Z][0-9]{1,2}): 2 items\. 1 forget 'pay the gas bill', cannot be undone\. 2 forget your agent's work since today [0-9]{2}:[0-9]{2}, cannot be undone\. Expires [0-9]{2}:[0-9]{2}\. Reply YES ([A-Z][0-9]{1,2}) ([0-9]{6,8}) for all`).FindStringSubmatch(req)
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
