package recalltool

// REQ: CAP-3

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/recall"
)

type fakeJournal struct {
	submitted map[string]time.Time // intent -> when, all from guest:root
	erased    map[string]bool
	inFlight  map[string]bool
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

// Deleting a record a lineage was given resets the lineage's machines to
// before it was given, erases the intents it submitted since and the cases
// built on them, and forgets what it was given since. Other lineages and
// earlier intents are untouched; an intent in flight keeps the deletion
// pending until it settles.
func TestCAP3DeletionReachesMachinesJournalAndCases(t *testing.T) {
	r := newRig(t)
	clock := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	r.tl.cfg.Now = func() time.Time { return clock }
	j := &fakeJournal{submitted: map[string]time.Time{}, erased: map[string]bool{}, inFlight: map[string]bool{}}
	vm := &fakeMachines{}
	cs := &fakeCases{forgot: map[string]bool{}}
	reach := &Reach{Prov: r.prov, Journal: j, Machines: vm, Cases: cs}
	if err := r.ix.OnDelete(reach.OnDelete); err != nil {
		t.Fatal(err)
	}

	// Before reading the mail: public reading and an intent.
	r.call("root", "root", "recall_search", map[string]any{"query": "shed", "scope": "public"})
	j.submitted["early"] = clock.Add(-time.Minute)
	clock = clock.Add(time.Minute)
	r.call("root", "root", "recall_search", map[string]any{"query": "invoice", "scope": "owner"})
	read := clock
	j.submitted["late"] = clock.Add(time.Second)
	j.submitted["running"] = clock.Add(2 * time.Second)
	j.inFlight["running"] = true
	clock = clock.Add(time.Minute)
	r.call("bystander", "bystander", "recall_search", map[string]any{"query": "shed", "scope": "public"})

	mail := r.ix.SourceID("mail", "owner@example.test", "<m1@x>")
	if _, err := r.ix.Delete(mail); err == nil {
		t.Fatal("an intent in flight, but the deletion reported reached")
	}
	if len(vm.calls) != 1 || vm.calls[0] != "root" {
		t.Fatalf("machines reset: %v", vm.calls)
	}
	if !j.erased["late"] || j.erased["early"] || !cs.forgot["late"] || cs.forgot["early"] {
		t.Fatalf("journal %v, cases %v", j.erased, cs.forgot)
	}
	if reach.Pending() != 1 || len(r.prov.Holders(mail)) != 1 {
		t.Fatal("deletion not kept pending while an intent is in flight")
	}
	// It settles; the retry erases it and does not reset the machines again.
	delete(j.inFlight, "running")
	if err := reach.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !j.erased["running"] || reach.Pending() != 0 || len(vm.calls) != 1 {
		t.Fatalf("retry: erased %v pending %d resets %v", j.erased, reach.Pending(), vm.calls)
	}
	// The lineage no longer holds the mail; what it read before stays.
	if len(r.prov.Holders(mail)) != 0 {
		t.Fatal("provenance still names the lineage")
	}
	for _, id := range r.prov.Of("root") {
		if g := r.prov.Holders(id)["root"]; !g.Before(read) {
			t.Fatalf("item given at %v kept", g)
		}
	}
	if len(r.prov.Of("root")) == 0 || len(r.prov.Of("bystander")) == 0 {
		t.Fatal("reading from before, or another lineage's, was forgotten")
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
