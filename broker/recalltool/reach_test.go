package recalltool

// REQ: CAP-3

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recall"
)

type fakeJournal struct {
	submitted map[string]time.Time // intent -> when, all from guest:root
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

func (j *fakeJournal) Since(origin string, since time.Time) []string {
	var out []string
	for id, at := range j.submitted {
		if origin == "guest:root" && !at.Before(since) {
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
	calls []string
	fail  error
}

func (m *fakeMachines) ForgetSince(_ context.Context, lineage string, since time.Time) error {
	if m.fail != nil {
		return m.fail
	}
	m.calls = append(m.calls, lineage)
	return nil
}

type fakeCases struct{ forgot map[string]bool }

func (c *fakeCases) ForgetTasks(tasks ...string) (int, error) {
	for _, t := range tasks {
		c.forgot[t] = true
	}
	return len(tasks), nil
}

// fakeAsk stands in for the grants gate: it records rollback intents and
// lets the test answer them.
type fakeAsk struct {
	st    map[string]journal.Status
	asked []string
	reach *Reach
}

func (a *fakeAsk) Submit(in journal.Intent) (journal.Status, error) {
	if st, ok := a.st[in.ID]; ok {
		return st, nil
	}
	st := journal.Status{Intent: in, State: journal.Pending}
	a.st[in.ID] = st
	return st, nil
}

func (a *fakeAsk) Authorize(_ context.Context, id string) (journal.Status, error) {
	a.asked = append(a.asked, id)
	return a.st[id], nil
}

func (a *fakeAsk) Get(id string) (journal.Status, error) {
	st, ok := a.st[id]
	if !ok {
		return st, errors.New("unknown")
	}
	return st, nil
}

// answer settles every asked intent: YES runs it as the journal would.
func (a *fakeAsk) answer(yes bool) {
	for id, st := range a.st {
		if st.State != journal.Pending {
			continue
		}
		if !yes {
			st.State = journal.Denied
		} else {
			out := a.reach.Execute(context.Background(), st.Intent, 1)
			st.State = journal.Succeeded
			if out.Result != journal.ResultSucceeded {
				st.State = journal.NotApplied
			}
			st.Attempts = []journal.Attempt{{N: 1, Result: out.Result, Evidence: out.Evidence}}
		}
		a.st[id] = st
	}
}

type reachRig struct {
	r     *rig
	j     *fakeJournal
	vm    *fakeMachines
	cs    *fakeCases
	ask   *fakeAsk
	reach *Reach
	clock time.Time
	mail  string
}

// newReachRig: lineage "root" reads public items, then the owner's mail at
// read; "bystander" reads only public items.
func newReachRig(t *testing.T) (*reachRig, time.Time) {
	r := newRig(t)
	x := &reachRig{r: r, clock: time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)} // notes refuse future receipt
	r.tl.cfg.Now = func() time.Time { return x.clock }
	x.j = &fakeJournal{submitted: map[string]time.Time{}, erased: map[string]bool{}, inFlight: map[string]bool{}, denied: map[string]bool{}}
	x.vm = &fakeMachines{}
	x.cs = &fakeCases{forgot: map[string]bool{}}
	x.ask = &fakeAsk{st: map[string]journal.Status{}}
	x.reach = &Reach{Prov: r.prov, Journal: x.j, Machines: x.vm, Cases: x.cs, Ask: x.ask}
	x.ask.reach = x.reach
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

// W10 (Mark, 2026-10-05): a lineage that has done nothing since it read a
// deleted record is taken back at once, with no question: machines back
// to before the read, what it was given since forgotten. Other lineages
// and earlier intents are untouched.
func TestCAP3NoWorkSinceTheReadRollsBackWithoutAsking(t *testing.T) {
	x, read := newReachRig(t)
	if _, err := x.r.ix.Delete(x.mail); err != nil {
		t.Fatal(err)
	}
	if len(x.ask.asked) != 0 || len(x.vm.calls) != 1 || x.vm.calls[0] != "root" {
		t.Fatalf("asked %v, reset %v", x.ask.asked, x.vm.calls)
	}
	if x.j.erased["early"] || x.reach.Pending() != 0 || len(x.r.prov.Holders(x.mail)) != 0 {
		t.Fatal("wrong reach")
	}
	for _, id := range x.r.prov.Of("root") {
		if g := x.r.prov.Holders(id)["root"]; !g.Before(read) {
			t.Fatalf("item given at %v kept", g)
		}
	}
	if len(x.r.prov.Of("root")) == 0 || len(x.r.prov.Of("bystander")) == 0 {
		t.Fatal("reading from before, or another lineage's, was forgotten")
	}
}

// W10: a lineage that has worked since the read is asked about first, with
// what would be undone. The item is gone from recall at once; nothing of
// the lineage is undone until the owner says YES. Then its machines go
// back, its intents since are erased with their cases, and an intent in
// flight keeps the deletion pending until it settles.
func TestCAP3WorkSinceTheReadWaitsForTheOwnersYes(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.j.submitted["running"] = read.Add(2 * time.Second)
	x.j.inFlight["running"] = true
	x.reach.Location = time.FixedZone("owner", -4*3600)
	if _, err := x.r.ix.Delete(x.mail); err != nil {
		t.Fatalf("a deletion waiting for the owner is an error: %v", err)
	}
	if _, ok := x.r.ix.Get(x.mail); ok {
		t.Fatal("the item waited for the owner too")
	}
	if len(x.ask.asked) != 1 || len(x.vm.calls) != 0 || len(x.j.erased) != 0 || x.reach.Pending() != 1 {
		t.Fatalf("before the answer: asked %v, reset %v, erased %v", x.ask.asked, x.vm.calls, x.j.erased)
	}
	in := x.ask.st[x.ask.asked[0]].Intent
	if in.Origin != Origin || in.Executor != ExecutorName || in.Action != journal.ActionRecallRollback ||
		in.Params["object"] != "root to "+read.In(x.reach.Location).Format("15:04 Jan 2") || in.Params["detail"] != "its 2 actions since stay done; their details are erased" {
		t.Fatalf("rollback intent: %+v", in)
	}
	// Asking again (Retry) does not ask twice.
	x.reach.Retry(context.Background())
	if len(x.ask.asked) != 2 || len(x.ask.st) != 1 {
		t.Fatalf("re-asked: %v", x.ask.st)
	}
	x.ask.answer(true)
	if len(x.vm.calls) != 1 || !x.j.erased["late"] || x.j.erased["early"] || !x.cs.forgot["late"] {
		t.Fatalf("after YES: reset %v, erased %v, cases %v", x.vm.calls, x.j.erased, x.cs.forgot)
	}
	if x.reach.Pending() != 1 || len(x.r.prov.Holders(x.mail)) != 1 {
		t.Fatal("an intent in flight, but the deletion is done")
	}
	delete(x.j.inFlight, "running")
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !x.j.erased["running"] || x.reach.Pending() != 0 || len(x.vm.calls) != 1 || len(x.r.prov.Holders(x.mail)) != 0 {
		t.Fatalf("retry: erased %v pending %d resets %v", x.j.erased, x.reach.Pending(), x.vm.calls)
	}
}

// W10: on NO (or no answer) the lineage keeps its work and what it read,
// and is not asked again; the item stays deleted.
func TestCAP3OwnersNoKeepsTheWork(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.r.ix.Delete(x.mail)
	x.ask.answer(false)
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x.vm.calls) != 0 || len(x.j.erased) != 0 || x.reach.Pending() != 0 || len(x.ask.asked) != 1 {
		t.Fatalf("after NO: reset %v erased %v pending %d asked %v", x.vm.calls, x.j.erased, x.reach.Pending(), x.ask.asked)
	}
	if _, ok := x.r.ix.Get(x.mail); ok {
		t.Fatal("item back after NO")
	}
}

// W10: an approved rollback whose machine reset failed is carried through
// by Retry, reading the journal's record of the approval.
func TestCAP3ApprovedRollbackFinishesAfterAFailedReset(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.r.ix.Delete(x.mail)
	x.vm.fail = errors.New("disk budget")
	x.ask.answer(true)
	if len(x.j.erased) != 0 || x.reach.Pending() != 1 {
		t.Fatal("went past a failed reset")
	}
	x.vm.fail = nil
	if err := x.reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x.vm.calls) != 1 || !x.j.erased["late"] || x.reach.Pending() != 0 {
		t.Fatalf("retry after approval: %v %v", x.vm.calls, x.j.erased)
	}
}

// A machine reset that fails keeps the deletion pending and the
// provenance, so the retry (or the replay at the next start) reaches it.
func TestCAP3DeletionReachRetriesAfterFailure(t *testing.T) {
	r := newRig(t)
	vm := &fakeMachines{fail: errors.New("disk budget")}
	reach := &Reach{Prov: r.prov, Machines: vm}
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
// crash cut short (provenance not yet forgotten) runs again.
func TestCAP3ServiceReplaysReachAtStart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "recall")
	s, err := OpenService(ServiceConfig{Dir: dir, Key: key(), Labeler: newLabels()})
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Index.Ingest(recall.Item{Source: recall.Source{Kind: "mail", Account: "a", Ref: "<c@x>"}, Text: "synthetic canary", Received: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Prov.Given("root", []string{id}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Not wired to machines: the index deletes, the lineage keeps its
	// record of what it was given.
	if _, err := s.Index.Delete(id); err != nil {
		t.Fatal(err)
	}
	s.Close()
	vm := &fakeMachines{}
	s2, err := OpenService(ServiceConfig{Dir: dir, Key: key(), Machines: vm})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if len(vm.calls) != 1 || len(s2.Prov.Holders(id)) != 0 {
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
	x.r.ix.Delete(x.mail)
	if len(x.ask.asked) != 0 || len(x.vm.calls) != 1 || x.reach.Pending() != 0 {
		t.Fatalf("asked %v, reset %v", x.ask.asked, x.vm.calls)
	}
}

// #59 security B1, C2: a lineage that keeps a deleted record (asked, then
// NO) is contained: it can make no note derived from it, its tombstone is
// kept past the prune policy, and the gate gives it no pre-allowance.
func TestCAP3DeclinedLineageIsContained(t *testing.T) {
	x, read := newReachRig(t)
	x.j.submitted["late"] = read.Add(time.Second)
	x.r.ix.Delete(x.mail)
	if !x.reach.Contained("root") || x.reach.Contained("bystander") {
		t.Fatal("not contained while asked")
	}
	x.ask.answer(false)
	x.reach.Retry(context.Background())
	if !x.reach.Contained("root") {
		t.Fatal("not contained after NO")
	}
	note := map[string]any{"key": "n", "text": "a summary"}
	if _, err := x.r.call("root", "root", "recall_note", note); err == nil {
		t.Fatal("note derived from a deleted record stored")
	}
	// Its tombstone outlives the prune policy (recall's
	// TestDerivedFromDeletedIsRefused covers the prune itself).
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
	x.r.ix.Delete(x.mail)
	x.ask.answer(true)
	x.reach.Retry(context.Background())
	if x.reach.Contained("root") {
		t.Fatal("still contained after the rollback")
	}
	if _, err := x.r.call("root", "root", "recall_note", map[string]any{"key": "n", "text": "fresh"}); err != nil {
		t.Fatalf("note after the rollback: %v", err)
	}
}
