package recalltool

// REQ: CAP-3

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recall"
)

type fakeJournal struct {
	submitted map[string]time.Time // intent -> when, from guest:root unless in origin
	origin    map[string]string
	erased    map[string]bool
	inFlight  map[string]bool
	denied    map[string]bool
}

func (j *fakeJournal) Get(id string) (journal.Status, error) {
	if _, ok := j.submitted[id]; !ok {
		return journal.Status{}, errors.New("unknown")
	}
	switch {
	case j.inFlight[id]:
		return journal.Status{State: journal.InFlight}, nil
	case j.denied[id]:
		return journal.Status{State: journal.Denied}, nil
	}
	return journal.Status{State: journal.Succeeded}, nil
}

func (j *fakeJournal) Between(origin string, from, until time.Time) []string {
	var out []string
	for id, at := range j.submitted {
		o := j.origin[id]
		if o == "" {
			o = "guest:root"
		}
		if origin == o && !at.Before(from) && (until.IsZero() || at.Before(until)) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func (j *fakeJournal) Erase(ids []string) (erased, held []string, err error) {
	for _, id := range ids {
		switch {
		case j.inFlight[id]:
			held = append(held, id)
		case !j.erased[id]:
			j.erased[id] = true
			erased = append(erased, id)
		}
	}
	return erased, held, nil
}

type fakeMachines struct {
	calls   []string
	since   []time.Time
	plan    Plan
	planErr error
	fail    error
	during  func() // runs while the machines go back
}

func (m *fakeMachines) ForgetSince(_ context.Context, lineage string, since time.Time) error {
	if m.fail != nil {
		return m.fail
	}
	if m.during != nil {
		m.during()
	}
	m.calls = append(m.calls, lineage)
	m.since = append(m.since, since)
	return nil
}

func (m *fakeMachines) Plan(string, time.Time) (Plan, error) { return m.plan, m.planErr }

type fakeCases struct {
	forgot map[string]bool
	// early: tasks forgotten while their intent was not yet erased.
	early map[string]bool
	j     *fakeJournal
}

func (c *fakeCases) ForgetTasks(tasks ...string) (int, error) {
	for _, t := range tasks {
		c.forgot[t] = true
		if c.j != nil && !c.j.erased[t] {
			c.early[t] = true
		}
	}
	return len(tasks), nil
}

// fakeAsk stands in for the grants gate: it records rollback intents and
// lets the test answer them.
type fakeAsk struct {
	st    map[string]journal.Status
	asked []string
	reach *Reach
	j     *fakeJournal // the broker's questions are journal intents too
}

func (a *fakeAsk) Submit(in journal.Intent) (journal.Status, error) {
	if st, ok := a.st[in.ID]; ok {
		return st, nil
	}
	st := journal.Status{Intent: in, State: journal.Pending}
	a.st[in.ID] = st
	if a.j != nil {
		a.j.submitted[in.ID], a.j.origin[in.ID] = a.reach.now(), in.Origin
	}
	return st, nil
}

func (a *fakeAsk) Authorize(_ context.Context, id string) (journal.Status, error) {
	a.asked = append(a.asked, id)
	return a.st[id], nil
}

func (a *fakeAsk) Withdraw(id string) error {
	st := a.st[id]
	if st.State == journal.Pending {
		st.State, st.Permission = journal.Denied, journal.Permission{Decision: "denied", Reason: "not approved: superseded"}
		a.st[id] = st
	}
	return nil
}

func (a *fakeAsk) Get(id string) (journal.Status, error) {
	st, ok := a.st[id]
	if !ok {
		return st, errors.New("unknown")
	}
	return st, nil
}

// answer settles every open question as the gate would: YES runs it,
// NO denies it as the owner's, and no answer denies it as expired.
func (a *fakeAsk) answer(how string) {
	for id, st := range a.st {
		if st.State == journal.Pending {
			a.settle(id, how)
		}
	}
}

func (a *fakeAsk) settle(id, how string) {
	st := a.st[id]
	switch how {
	case "yes":
		out := a.reach.Execute(context.Background(), st.Intent, 1)
		st.State = journal.Succeeded
		if out.Result != journal.ResultSucceeded {
			st.State = journal.NotApplied
		}
		st.Attempts = []journal.Attempt{{N: 1, Result: out.Result, Evidence: out.Evidence}}
	case "no":
		st.State, st.Permission = journal.Denied, journal.Permission{Decision: "denied", Reason: "not approved: owner"}
	default:
		st.State, st.Permission = journal.Denied, journal.Permission{Decision: "denied", Reason: "not approved: expired"}
	}
	a.st[id] = st
}

type reachRig struct {
	r      *rig
	j      *fakeJournal
	vm     *fakeMachines
	cs     *fakeCases
	ask    *fakeAsk
	reach  *Reach
	told   []string
	clock  time.Time
	mail   string
	before time.Time // a restore point before the read
}

// newReachRig: lineage "root" reads public items, then the owner's mail at
// read; "bystander" reads only public items. The machines' restore point
// is 08:12 the same day.
func newReachRig(t *testing.T) (*reachRig, time.Time) {
	r := newRig(t)
	x := &reachRig{r: r, clock: time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)} // notes refuse future receipt
	r.tl.cfg.Now = func() time.Time { return x.clock }
	x.j = &fakeJournal{submitted: map[string]time.Time{}, origin: map[string]string{}, erased: map[string]bool{}, inFlight: map[string]bool{}, denied: map[string]bool{}}
	x.before = x.clock.Add(-10 * time.Minute)
	x.vm = &fakeMachines{plan: Plan{To: x.before}}
	x.cs = &fakeCases{forgot: map[string]bool{}, early: map[string]bool{}, j: x.j}
	x.ask = &fakeAsk{st: map[string]journal.Status{}}
	x.reach = &Reach{Prov: r.prov, Journal: x.j, Machines: x.vm, Cases: x.cs, Ask: x.ask, Deleted: r.ix.Deleted,
		Now: func() time.Time { return x.clock }, Location: time.UTC,
		Notify: func(s string) error { x.told = append(x.told, s); return nil }}
	x.ask.reach, x.ask.j = x.reach, x.j
	r.ix.KeepTombstones(x.reach.Needed)
	if err := r.ix.OnDelete(x.reach.OnDelete); err != nil {
		t.Fatal(err)
	}
	r.call("root", "root", "recall_search", map[string]any{"query": "shed", "scope": "public"})
	x.j.submitted["early"] = x.clock.Add(-time.Minute)
	x.clock = x.clock.Add(time.Minute)
	r.call("root", "root", "recall_search", map[string]any{"query": "invoice", "scope": "owner"})
	read := x.clock
	x.clock = x.clock.Add(time.Minute)
	r.call("bystander", "bystander", "recall_search", map[string]any{"query": "shed", "scope": "public"})
	x.mail = r.ix.SourceID("mail", "owner@example.test", "<m1@x>")
	return x, read
}

func (x *reachRig) del(t *testing.T, id string) {
	t.Helper()
	if _, err := x.r.ix.Delete(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// W10 (Mark, 2026-10-05): a lineage that has done nothing since it read a
// deleted record is taken back at once, with no question: machines back
// to before the read, what it was given since forgotten. Other lineages
// and earlier intents are untouched.
func TestCAP3NoWorkSinceTheReadRollsBackWithoutAsking(t *testing.T) {
	x, read := newReachRig(t)
	x.del(t, x.mail)
	if len(x.ask.asked) != 0 || len(x.vm.calls) != 1 || x.vm.calls[0] != "root" || !x.vm.since[0].Equal(read) {
		t.Fatalf("asked %v, reset %v %v", x.ask.asked, x.vm.calls, x.vm.since)
	}
	if x.j.erased["early"] || x.reach.Pending() != 0 || len(x.r.prov.Holders(x.mail)) != 0 || len(x.told) != 0 {
		t.Fatal("wrong reach")
	}
	for _, id := range x.r.prov.Of("root") {
		if g := x.r.prov.Holders(id)["root"]; !g.Before(read) {
			t.Fatalf("item given at %v kept", g)
		}
	}
	if len(x.r.prov.Of("root")) == 0 || len(x.r.prov.Of("bystander")) == 0 || len(x.r.prov.Resets("root")) != 0 {
		t.Fatal("reading from before, or another lineage's, was forgotten; or the reset left open")
	}
}

// #59 arbitrator (Potency 3): files changed in the machine since its
// restore point are work too, so the owner is asked even when no action
// was taken.
func TestCAP3InMachineWorkIsAskedAbout(t *testing.T) {
	x, _ := newReachRig(t)
	x.vm.plan.Changes = 4
	x.del(t, x.mail)
	if len(x.ask.asked) != 1 || len(x.vm.calls) != 0 {
		t.Fatalf("asked %v, reset %v", x.ask.asked, x.vm.calls)
	}
	in := x.ask.st[x.ask.asked[0]].Intent
	if in.Params["detail"] != "back to "+x.before.Format("15:04 Jan 2")+"; no actions yet" {
		t.Fatalf("detail %q", in.Params["detail"])
	}
}

// A reset that fails must not put the host path from the error into the
// journal evidence the owner can later be shown.
func TestCAP3AFailedResetRecordsNoHostPath(t *testing.T) {
	x, _ := newReachRig(t)
	x.vm.plan.Changes = 4
	canary := "/var/lib/agentos/machines/root/upper"
	x.vm.fail = errors.New("rename " + canary + ": permission denied")
	x.del(t, x.mail)
	if len(x.ask.asked) != 1 {
		t.Fatalf("asked %v", x.ask.asked)
	}
	x.ask.answer("yes")
	ev := ""
	if st := x.ask.st[x.ask.asked[0]]; len(st.Attempts) > 0 {
		ev = st.Attempts[0].Evidence
	}
	if strings.Contains(ev, canary) || strings.Contains(ev, "/var/") || ev == "" || ev == "rolled back" {
		t.Fatalf("evidence %q", ev)
	}
	for _, told := range x.told {
		if strings.Contains(told, canary) {
			t.Fatalf("told %q", told)
		}
	}
}

// W10: a lineage that has worked since the read is asked about first,
// naming the item by kind, the real restore point and the actions so far.
// The item is gone from recall at once; nothing of the lineage is undone
// until the owner says YES. Then its machines go back, its intents since
// are erased with their cases, the owner is told the real count, and an
// intent in flight keeps the deletion pending until it settles.
func TestCAP3WorkSinceTheReadWaitsForTheOwnersYes(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.j.submitted["running"] = read.Add(2 * time.Second)
	x.j.inFlight["running"] = true
	x.del(t, x.mail)
	if _, ok := x.r.ix.Get(x.mail); ok {
		t.Fatal("the item waited for the owner too")
	}
	if len(x.ask.asked) != 1 || len(x.vm.calls) != 0 || len(x.j.erased) != 0 || x.reach.Pending() != 1 || !x.reach.Contained("root") {
		t.Fatalf("before the answer: asked %v, reset %v, erased %v", x.ask.asked, x.vm.calls, x.j.erased)
	}
	in := x.ask.st[x.ask.asked[0]].Intent
	if in.Origin != Origin || in.Executor != ExecutorName || in.Action != journal.ActionRecallRollback ||
		in.Params["object"] != "a mail you deleted from root" ||
		in.Params["detail"] != "back to "+x.before.Format("15:04 Jan 2")+"; 2 actions stay done" {
		t.Fatalf("rollback intent: %+v", in.Params)
	}
	// Asking again (Retry) does not ask twice; more work meanwhile.
	x.j.submitted["later"] = read.Add(3 * time.Second)
	x.clock = x.clock.Add(time.Minute)
	x.reach.Retry(context.Background())
	if len(x.ask.asked) != 2 || len(x.ask.st) != 1 {
		t.Fatalf("re-asked: %v", x.ask.st)
	}
	x.ask.answer("yes")
	// The learning plane forgets an intent before the journal erases it,
	// so one in flight cannot settle into a new case (security F1 on #59).
	if len(x.vm.calls) != 1 || !x.j.erased["late"] || x.j.erased["early"] || !x.cs.forgot["late"] || !x.cs.early["late"] {
		t.Fatalf("after YES: reset %v, erased %v, cases %v", x.vm.calls, x.j.erased, x.cs.forgot)
	}
	want := "Done: root forgot a mail you deleted and is back to " + x.before.Format("15:04 Jan 2") + ". Its 3 actions since stay done; their details are erased."
	if len(x.told) != 1 || x.told[0] != want {
		t.Fatalf("told %q", x.told)
	}
	if x.reach.Pending() != 1 || len(x.r.prov.Holders(x.mail)) != 1 {
		t.Fatal("an intent in flight, but the deletion is done")
	}
	delete(x.j.inFlight, "running")
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !x.j.erased["running"] || x.reach.Pending() != 0 || len(x.vm.calls) != 1 || len(x.r.prov.Holders(x.mail)) != 0 || x.reach.Contained("root") {
		t.Fatalf("retry: erased %v pending %d resets %v", x.j.erased, x.reach.Pending(), x.vm.calls)
	}
	if len(x.told) != 1 {
		t.Fatal("told twice")
	}
}

// #59 L3 2: what the lineage reads and does after its reset is new, not
// built on the deleted record: a reach finished later (here, after an
// intent in flight settles) keeps it.
func TestCAP3ReadAfterTheResetIsKept(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["running"] = read.Add(time.Second)
	x.j.inFlight["running"] = true
	x.del(t, x.mail)
	x.ask.answer("yes")
	if len(x.vm.calls) != 1 || x.reach.Pending() != 1 || len(x.r.prov.Resets("root")) != 1 {
		t.Fatalf("reset %v pending %d", x.vm.calls, x.reach.Pending())
	}
	// After the reset: a new search and a new action.
	x.clock = x.clock.Add(time.Minute)
	x.r.call("root", "root", "recall_search", map[string]any{"query": "shed", "scope": "public"})
	x.j.submitted["after"] = x.clock
	pub := x.r.ix.SourceID("web", "", "https://shed.example.test/")
	delete(x.j.inFlight, "running")
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !x.j.erased["running"] || x.j.erased["after"] || len(x.vm.calls) != 1 || x.reach.Pending() != 0 {
		t.Fatalf("erased %v resets %v", x.j.erased, x.vm.calls)
	}
	if g, ok := x.r.prov.Holders(pub)["root"]; !ok || !g.Before(read) {
		t.Fatalf("the earlier read of the public page: %v %v", g, ok)
	}
	if len(x.r.prov.Resets("root")) != 0 {
		t.Fatal("reset mark left")
	}
}

// #59 L3 4 and re-review 2: one question per lineage, at its earliest
// deleted item; a later one is withdrawn when an earlier one is asked. An
// approval that is stale by the time it runs undoes nothing, and the
// owner is told so.
func TestCAP3OneQuestionPerAgentAndStaleApprovals(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	// The lineage was given the public page before the mail: deleting the
	// mail asks from its read; deleting the page then asks from earlier.
	pub := x.r.ix.SourceID("web", "", "https://shed.example.test/")
	x.del(t, x.mail)
	first := x.ask.asked[0]
	stale := x.ask.st[first].Intent
	x.del(t, pub)
	open := 0
	var second string
	for id, st := range x.ask.st {
		if st.State == journal.Pending {
			open++
			second = id
		}
	}
	if open != 1 || second == first || x.ask.st[first].Permission.Reason != "not approved: superseded" {
		t.Fatalf("questions: %+v", x.ask.st)
	}
	x.ask.settle(second, "yes")
	resets := func() (n int) {
		for _, l := range x.vm.calls {
			if l == "root" {
				n++
			}
		}
		return n
	}
	if resets() != 1 || len(x.r.prov.Of("root")) != 0 {
		t.Fatalf("earlier rollback: %v %v", x.vm.calls, x.r.prov.Of("root"))
	}
	// The lineage works on; then a YES on the withdrawn question reaches
	// the executor anyway (it raced the withdrawal).
	x.clock = x.clock.Add(time.Minute)
	x.j.submitted["new"] = x.clock
	out := x.reach.Execute(context.Background(), stale, 1)
	if out.Evidence != staleEvidence || resets() != 1 || x.j.erased["new"] || len(x.told) != 2 || !strings.HasPrefix(x.told[1], "Nothing more to do: root") {
		t.Fatalf("stale approval: %+v, resets %v, erased %v, told %q", out, x.vm.calls, x.j.erased, x.told)
	}
}

// #59 L3 third review 1: the later read's question is withdrawn in every
// form, a re-ask after no answer or one naming new items after a NO, so
// the owner still has one question per agent; a YES that raced the
// withdrawal resets nothing and leaves the lineage contained.
func TestCAP3OneQuestionPerAgentInEveryForm(t *testing.T) {
	for _, form := range []string{"re-ask", "after NO"} {
		t.Run(form, func(t *testing.T) {
			x, read := newReachRig(t)
			x.j.submitted["late"] = read.Add(time.Second)
			pub := x.r.ix.SourceID("web", "", "https://shed.example.test/")
			x.del(t, x.mail)
			switch form {
			case "re-ask":
				x.ask.answer("lapse")
				x.clock = x.clock.Add(ReaskEvery)
			case "after NO":
				x.ask.answer("no")
				// A record read after the mail, then deleted: a new
				// question from the same read, naming both.
				hose, err := x.r.ix.Ingest(recall.Item{Source: recall.Source{Kind: "web", Ref: "https://hose.example.test/"}, Label: recall.Public, Text: "garden hose prices", Received: x.clock.Add(-time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				x.r.call("root", "root", "recall_search", map[string]any{"query": "hose", "scope": "public"})
				x.del(t, hose)
			}
			x.reach.Retry(context.Background())
			var later string
			for id, st := range x.ask.st {
				if st.State == journal.Pending {
					later = id
				}
			}
			if later == "" {
				t.Fatalf("no later question: %+v", x.ask.st)
			}
			stale := x.ask.st[later].Intent
			x.del(t, pub)
			var open []journal.Intent
			for _, st := range x.ask.st {
				if st.State == journal.Pending {
					open = append(open, st.Intent)
				}
			}
			if len(open) != 1 || open[0].ID == later || x.ask.st[later].Permission.Reason != "not approved: superseded" || open[0].Params["since"] == stale.Params["since"] {
				t.Fatalf("questions: %+v", x.ask.st)
			}
			out := x.reach.Execute(context.Background(), stale, 1)
			roots := 0
			for _, l := range x.vm.calls {
				if l == "root" {
					roots++
				}
			}
			if out.Evidence != supersededEvidence || roots != 0 || !x.reach.Contained("root") || !strings.HasPrefix(x.told[len(x.told)-1], "Nothing done yet: root") {
				t.Fatalf("raced YES: %+v, resets %v, told %q", out, x.vm.calls, x.told)
			}
		})
	}
}

// #59 L3 third review: intents submitted while the machines go back are
// erased with the rest; the erase runs to when the reset finished, not
// to when it started.
func TestCAP3IntentsDuringTheResetAreErased(t *testing.T) {
	x, read := newReachRig(t)
	x.vm.plan.Changes = 0
	x.vm.during = func() {
		x.clock = x.clock.Add(time.Minute)
		x.j.submitted["during"] = x.clock.Add(-30 * time.Second)
	}
	x.del(t, x.mail)
	rs := x.vm.since
	if len(rs) != 1 || !rs[0].Equal(read) || !x.j.erased["during"] || x.reach.Pending() != 0 {
		t.Fatalf("resets %v erased %v", rs, x.j.erased)
	}
}

// #59 L3 fourth review: a record read while the machines go back, and
// deleted before the approved rollback finishes, is not among what the
// owner is told was forgotten, and keeps the lineage contained.
func TestCAP3RecordReadDuringTheResetStaysHeld(t *testing.T) {
	x, read := newReachRig(t)
	hose, err := x.r.ix.Ingest(recall.Item{Source: recall.Source{Kind: "web", Ref: "https://hose.example.test/"}, Label: recall.Public, Text: "garden hose prices", Received: x.clock.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	x.j.submitted["late"] = read.Add(time.Second)
	x.del(t, x.mail)
	q := x.ask.st[x.ask.asked[0]].Intent
	gone := make(chan struct{})
	x.vm.during = func() {
		x.clock = x.clock.Add(time.Minute)
		x.r.call("root", "root", "recall_search", map[string]any{"query": "hose", "scope": "public"})
		x.j.submitted["after"] = x.clock.Add(30 * time.Second) // work since that read
		// The deletion's reach waits for the rollback running now.
		go func() {
			defer close(gone)
			x.r.ix.Delete(hose)
		}()
		for !x.r.ix.Deleted(hose) {
			time.Sleep(time.Millisecond)
		}
	}
	if out := x.reach.Execute(context.Background(), q, 1); out.Evidence != "rolled back" {
		t.Fatalf("execute: %+v", out)
	}
	<-gone
	if len(x.told) != 1 || !strings.HasPrefix(x.told[0], "Done: root forgot a mail you deleted") || !x.reach.Contained("root") {
		t.Fatalf("told %q, contained %v", x.told, x.reach.Contained("root"))
	}
}

// #59 L3 third review: after a restart, a question left unanswered is not
// asked again at once; the day starts at the first sighting.
func TestCAP3ReaskClockStartsAgainAfterARestart(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.del(t, x.mail)
	x.ask.answer("lapse")
	x.clock = x.clock.Add(2 * ReaskEvery)
	// The broker restarts: a new Reach over the same records.
	again := &Reach{Prov: x.reach.Prov, Journal: x.j, Machines: x.vm, Ask: x.ask, Deleted: x.reach.Deleted, Now: x.reach.Now, Location: time.UTC}
	x.ask.reach = again
	if err := again.settle(context.Background(), "root"); !errors.Is(err, errWaiting) || len(x.ask.st) != 1 || !again.Contained("root") {
		t.Fatalf("asked at once after a restart: %v, %d", err, len(x.ask.st))
	}
	x.clock = x.clock.Add(ReaskEvery)
	again.settle(context.Background(), "root")
	if len(x.ask.st) != 2 {
		t.Fatalf("not asked a day after the restart: %d", len(x.ask.st))
	}
}

// #59 L3 re-review 1: a record read in the window between the read of
// the deleted one and the reset, and read again after the reset, is held
// again: a later deletion of it still reaches the lineage.
func TestCAP3ReReadAfterTheResetIsHeld(t *testing.T) {
	x, read := newReachRig(t)
	hose, err := x.r.ix.Ingest(recall.Item{Source: recall.Source{Kind: "web", Ref: "https://hose.example.test/"}, Label: recall.Public, Text: "garden hose prices", Received: x.clock.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	x.r.call("root", "root", "recall_search", map[string]any{"query": "hose", "scope": "public"})
	x.clock = x.clock.Add(time.Minute) // the reset comes after that read
	x.j.submitted["running"] = read.Add(time.Second)
	x.j.inFlight["running"] = true
	x.del(t, x.mail)
	x.ask.answer("yes")
	if len(x.r.prov.Resets("root")) != 1 {
		t.Fatal("no reset recorded")
	}
	x.clock = x.clock.Add(time.Minute)
	reread := x.clock
	x.r.call("root", "root", "recall_search", map[string]any{"query": "hose", "scope": "public"})
	delete(x.j.inFlight, "running")
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if g, ok := x.r.prov.Holders(hose)["root"]; !ok || g.Before(reread) {
		t.Fatalf("re-read after the reset: given %v, held %v", g, ok)
	}
}

// W10 (arbitrator), #59 L3 re-review 3: a question that closes without
// an answer is asked again, as a new question, a day later; the lineage
// stays contained meanwhile, and a YES then takes it back.
func TestCAP3UnansweredQuestionIsAskedAgain(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.del(t, x.mail)
	x.ask.answer("lapse")
	x.reach.Retry(context.Background())
	if len(x.ask.st) != 1 || !x.reach.Contained("root") || x.reach.Pending() != 1 {
		t.Fatalf("asked again at once: %d", len(x.ask.st))
	}
	x.clock = x.clock.Add(ReaskEvery)
	x.reach.Retry(context.Background())
	if len(x.ask.st) != 2 {
		t.Fatalf("not asked again after a day: %d", len(x.ask.st))
	}
	x.ask.answer("yes")
	x.reach.Retry(context.Background())
	if len(x.vm.calls) != 1 || x.reach.Contained("root") || x.reach.Pending() != 0 {
		t.Fatalf("after YES to the second ask: %v", x.vm.calls)
	}
}

// #59 L3 re-review 7: a restore point that could not be measured is not
// named.
func TestCAP3UnmeasuredRestorePointIsNotNamed(t *testing.T) {
	x, read := newReachRig(t)
	x.vm.planErr = errors.New("layer unreadable")
	x.j.submitted["late"] = read.Add(time.Second)
	x.del(t, x.mail)
	in := x.ask.st[x.ask.asked[0]].Intent
	if in.Params["detail"] != "back before "+read.Format("15:04")+"; 1 action stays done" {
		t.Fatalf("detail %q", in.Params["detail"])
	}
}

// #59 L3 re-review 4: until recall opens after a restart, every lineage is
// contained; once it opens, the replay settles which are; with recall
// off, none is.
func TestCAP3ContainedUntilRecallOpens(t *testing.T) {
	var l LateExecutor
	if !l.Contained("agent") {
		t.Fatal("not contained before recall opens")
	}
	l.Set(&Reach{})
	if l.Contained("agent") {
		t.Fatal("contained after open with nothing held")
	}
	var off LateExecutor
	off.Off()
	if off.Contained("agent") || off.Status() != "" {
		t.Fatal("contained with recall off")
	}
	// Configured but failed to open: still contained, and STATUS says so
	// (#59 L3 third review).
	var failed LateExecutor
	failed.Failed()
	if !failed.Contained("agent") || failed.Status() == "" {
		t.Fatalf("recall failed to open: contained %v, status %q", failed.Contained("agent"), failed.Status())
	}
}

// W10 (arbitrator): the owner's NO keeps the lineage's work and what it
// read, lifts the containment, and is not asked again; the item stays
// deleted, and the lineage still makes no note derived from it.
func TestCAP3OwnersNoKeepsTheWork(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.del(t, x.mail)
	x.ask.answer("no")
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x.vm.calls) != 0 || len(x.j.erased) != 0 || x.reach.Pending() != 0 || len(x.ask.asked) != 1 || x.reach.Contained("root") {
		t.Fatalf("after NO: reset %v erased %v pending %d asked %v", x.vm.calls, x.j.erased, x.reach.Pending(), x.ask.asked)
	}
	if _, ok := x.r.ix.Get(x.mail); ok {
		t.Fatal("item back after NO")
	}
	if got := x.reach.Status(); got != "root still holds a record you deleted" {
		t.Fatalf("status %q", got)
	}
	_, err := x.r.call("root", "root", "recall_note", map[string]any{"key": "n", "text": "a summary"})
	if err == nil || !strings.Contains(err.Error(), "notes are off") {
		t.Fatalf("note after NO: %v", err)
	}
	if !x.reach.Needed(x.mail) {
		t.Fatal("tombstone of a kept record not kept")
	}
	// A record deleted after the NO is a new question, asked once.
	x.r.call("root", "root", "recall_search", map[string]any{"query": "shed", "scope": "public"})
	pub := x.r.ix.SourceID("web", "", "https://shed.example.test/")
	x.del(t, pub)
	x.reach.Retry(context.Background())
	if n := len(x.ask.st); n != 2 || !x.reach.Contained("root") {
		t.Fatalf("questions after a new deletion: %d", n)
	}
}

// W10 (arbitrator): no answer is not a decline. The deletion stays
// pending and the lineage contained until the owner answers.
func TestCAP3NoAnswerStaysContained(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.del(t, x.mail)
	x.ask.answer("lapse")
	x.reach.Retry(context.Background())
	if x.reach.Pending() != 1 || !x.reach.Contained("root") || len(x.vm.calls) != 0 || len(x.ask.st) != 1 {
		t.Fatalf("after no answer: pending %d contained %v", x.reach.Pending(), x.reach.Contained("root"))
	}
	if x.reach.Status() == "" {
		t.Fatal("no status line while held")
	}
}

// W10: an approved rollback whose machine reset failed is carried through
// by Retry, reading the journal's record of the approval.
func TestCAP3ApprovedRollbackFinishesAfterAFailedReset(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.del(t, x.mail)
	x.vm.fail = errors.New("disk budget")
	x.ask.answer("yes")
	if len(x.j.erased) != 0 || x.reach.Pending() != 1 || len(x.told) != 0 {
		t.Fatal("went past a failed reset")
	}
	x.vm.fail = nil
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x.vm.calls) != 1 || !x.j.erased["late"] || x.reach.Pending() != 0 || len(x.told) != 1 {
		t.Fatalf("retry after approval: %v %v %v", x.vm.calls, x.j.erased, x.told)
	}
}

// A machine reset that fails keeps the deletion pending and the
// provenance, so the retry (or the replay at the next start) reaches it.
func TestCAP3DeletionReachRetriesAfterFailure(t *testing.T) {
	r := newRig(t)
	vm := &fakeMachines{fail: errors.New("disk budget")}
	reach := &Reach{Prov: r.prov, Machines: vm, Deleted: r.ix.Deleted}
	r.ix.OnDelete(reach.OnDelete)
	r.call("root", "root", "recall_search", map[string]any{"query": "invoice", "scope": "owner"})
	mail := r.ix.SourceID("mail", "owner@example.test", "<m1@x>")
	if _, err := r.ix.Delete(mail); err == nil {
		t.Fatal("failure not reported")
	}
	if reach.Pending() != 1 || len(r.prov.Holders(mail)) != 1 {
		t.Fatal("failed reach not pending")
	}
	vm.fail = nil
	if err := reach.Retry(context.Background()); err != nil || reach.Pending() != 0 || len(r.prov.Holders(mail)) != 0 {
		t.Fatalf("retry: %v", err)
	}
}

// The service replays tombstones through the reach at start, so a reach a
// crash cut short (provenance not yet forgotten) runs again; a recorded
// reset is finished without resetting the machines again.
func TestCAP3ServiceReplaysReachAtStart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "recall")
	s, err := OpenService(ServiceConfig{Dir: dir, Key: key(), Labeler: newLabels()})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, ref := range []string{"<c@x>", "<d@x>"} {
		id, err := s.Index.Ingest(recall.Item{Source: recall.Source{Kind: "mail", Account: "a", Ref: ref}, Text: "synthetic canary", Received: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	t0 := time.Now().UTC()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Prov.Given("root", ids[:1], t0))
	must(s.Prov.Given("other", ids[1:], t0))
	// "other" was reset before a crash; its reach was not finished.
	must(s.Prov.MarkReset("other", Reset{Since: t0, At: t0.Add(time.Second), Until: t0.Add(2 * time.Second)}))
	// Not wired to machines: the index deletes, the lineages keep their
	// record of what they were given.
	if _, err := s.Index.Delete(ids...); err != nil {
		t.Fatal(err)
	}
	s.Close()
	vm := &fakeMachines{}
	s2, err := OpenService(ServiceConfig{Dir: dir, Key: key(), Machines: vm})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if len(vm.calls) != 1 || vm.calls[0] != "root" || len(s2.Prov.Holders(ids[0])) != 0 || len(s2.Prov.Holders(ids[1])) != 0 {
		t.Fatalf("not replayed at start: %v", vm.calls)
	}
}

// The gate admits rollback intents only by these names.
func TestRollbackNamesMatchTheGate(t *testing.T) {
	if Origin != grants.OriginRecall || ExecutorName != grants.RecallExecutor {
		t.Fatal("recalltool and grants disagree on the rollback intent's names")
	}
}

// #59 security B2: an intent that never took effect (denied) is not work,
// so it does not force a question.
func TestCAP3DeniedIntentIsNotWork(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["junk"] = read.Add(time.Second)
	x.j.denied["junk"] = true
	x.del(t, x.mail)
	if len(x.ask.asked) != 0 || len(x.vm.calls) != 1 || x.reach.Pending() != 0 {
		t.Fatalf("asked %v, reset %v", x.ask.asked, x.vm.calls)
	}
}

// #59 security B1, C2: a lineage being asked about is contained: it can
// make no note derived from the record, and its tombstone is kept past
// the prune policy. Other lineages are not.
func TestCAP3AskedLineageIsContained(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.del(t, x.mail)
	if !x.reach.Contained("root") || x.reach.Contained("bystander") {
		t.Fatal("not contained while asked")
	}
	note := map[string]any{"key": "n", "text": "a summary"}
	if _, err := x.r.call("root", "root", "recall_note", note); err == nil {
		t.Fatal("note derived from a deleted record stored")
	}
	if !x.reach.Needed(x.mail) {
		t.Fatal("tombstone of a held record not kept")
	}
	if _, err := x.r.call("bystander", "bystander", "recall_note", note); err != nil {
		t.Fatalf("an unrelated lineage's note refused: %v", err)
	}
}

// After YES the lineage is no longer contained.
func TestCAP3ApprovedLineageIsReleased(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.del(t, x.mail)
	x.ask.answer("yes")
	x.reach.Retry(context.Background())
	if x.reach.Contained("root") || x.reach.Status() != "" {
		t.Fatal("still contained after the rollback")
	}
	if _, err := x.r.call("root", "root", "recall_note", map[string]any{"key": "n", "text": "fresh"}); err != nil {
		t.Fatalf("note after the rollback: %v", err)
	}
}

// #59 L3: Execute runs only the broker's own rollback intents.
func TestRollbackExecuteChecksTheIntent(t *testing.T) {
	x, read := newReachRig(t)
	in := journal.Intent{ID: "x", Origin: "guest:root", Account: journal.BrokerAccount, Action: journal.ActionRecallRollback,
		Params: map[string]any{"lineage": "root", "since": read.Format(time.RFC3339Nano)}}
	for _, mod := range []func(*journal.Intent){
		func(in *journal.Intent) {},
		func(in *journal.Intent) { in.Origin, in.Account = Origin, "mail" },
	} {
		c := in
		mod(&c)
		if out := x.reach.Execute(context.Background(), c, 1); out.Result != journal.ResultNotApplied {
			t.Fatalf("ran %+v", c)
		}
	}
	if len(x.vm.calls) != 0 {
		t.Fatal("reset")
	}
}

// #59 UX-59-1: the question fits the owner text's caps (no field is cut),
// names the item by kind only, and never uses UNDO's words.
func TestRollbackLineFitsTheCaps(t *testing.T) {
	r := &Reach{Location: time.UTC, Now: func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) },
		kinds: map[string]string{"a": "mail", "b": "mail", "c": "calendar"}}
	restore := []time.Time{{}, time.Date(2026, 10, 5, 8, 12, 0, 0, time.UTC), time.Date(2026, 10, 4, 23, 59, 0, 0, time.UTC)}
	for _, lineage := range []string{"agent.0123456789ab", "a-very-long-machine-name-for-a-test.0123"} {
		for _, ids := range [][]string{{"a"}, {"a", "b"}, {"a", "c"}, {"c"}, {"zz"}} {
			for _, to := range restore {
				for _, n := range []int{0, 1, 9, 12, 1234} {
					for _, known := range []bool{true, false} {
						obj, det := r.line(lineage, ids, to, known, n)
						for _, f := range []string{obj, det} {
							if len(f) > fieldCap || f == "" || strings.Contains(strings.ToLower(f), "undo") {
								t.Fatalf("field %q (%d chars)", f, len(f))
							}
						}
						if !strings.HasPrefix(det, "back ") || !strings.Contains(obj, "you deleted") {
							t.Fatalf("line %q / %q", obj, det)
						}
						// A single action is named as one (#59 L3 third review).
						if n == 1 && !strings.Contains(det, "1 action") {
							t.Fatalf("one action not named: %q", det)
						}
					}
				}
			}
		}
	}
	if obj, det := r.line("agent.x", []string{"a"}, restore[1], true, 2); obj != "a mail you deleted from agent" || det != "back to 08:12 Oct 5; 2 actions stay done" {
		t.Fatalf("%q / %q", obj, det)
	}
}

// The reset mark is durable and survives a compaction; finishing it
// forgets only what was given between the read and the reset.
func TestProvenanceResetMarks(t *testing.T) {
	st := &recall.MemStore{}
	p, err := OpenProvenance(st)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	p.Given("l", []string{"before"}, t0.Add(-time.Minute))
	p.Given("l", []string{"between"}, t0.Add(time.Minute))
	p.Given("l", []string{"after"}, t0.Add(3*time.Minute))
	if err := p.MarkReset("l", Reset{Since: t0, At: t0.Add(2 * time.Minute), Until: t0.Add(150 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	p.compact()
	p2, _ := OpenProvenance(st)
	rs := p2.Resets("l")
	if len(rs) != 1 || !rs[0].Since.Equal(t0) || !rs[0].At.Equal(t0.Add(2*time.Minute)) || !rs[0].Until.Equal(t0.Add(150*time.Second)) {
		t.Fatalf("resets after reopen: %+v", rs)
	}
	if err := p2.Finish("l", rs[0]); err != nil {
		t.Fatal(err)
	}
	p3, _ := OpenProvenance(st)
	if got := strings.Join(p3.Of("l"), ","); got != "after,before" || len(p3.Resets("l")) != 0 {
		t.Fatalf("after finish: %s %v", got, p3.Resets("l"))
	}
}
