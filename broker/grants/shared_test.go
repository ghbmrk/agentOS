package grants

// REQ: CH-15, CAP-10, OP-4

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// TestQuestionsReserveOnTheRequestBudget (W9, question Q3, UX-71-1):
// owner questions and approval request texts share RequestsPerHour. A
// question reserves its text under the gate's lock, so the check and the
// count are one step; approval requests go first, so no question is
// reserved while a batch waits; and a paced flush checks the budget per
// request text, keeping the rest batched for the next hour.
func TestQuestionsReserveOnTheRequestBudget(t *testing.T) {
	r := newRig(t, func(c *Config) { c.RequestsPerHour = 3 })
	r.grant(mailGrant()) // the grant's request: one text
	base := r.own.count()
	if !r.g.Reserve(false) || !r.g.Reserve(false) {
		t.Fatal("two questions refused with two texts left")
	}
	if r.g.Reserve(false) {
		t.Fatal("a fourth text in the hour")
	}

	r.advance(time.Hour)
	ask := func(id string) {
		t.Helper()
		x := sam()
		x.Record = id
		r.ver.set(id, x)
		r.effect("agent/"+id, "invoice.send", map[string]any{"record": id}, "sam@example.com")
	}
	ask("a")
	if r.g.Reserve(false) {
		t.Fatal("a question went ahead of a waiting approval request")
	}
	r.advance(2 * time.Minute)
	r.g.Tick()
	if r.own.count() != base+1 {
		t.Fatalf("batch not sent: %d", r.own.count()-base)
	}
	if !r.g.Reserve(false) {
		t.Fatal("refused with the batch sent and a text left")
	}

	// One text left this hour; a batch that needs two (MaxBatch+1 items)
	// sends one request and keeps the rest.
	for i := range MaxBatch + 1 {
		ask(fmt.Sprintf("b%d", i))
	}
	r.advance(2 * time.Minute)
	r.g.Tick()
	if r.own.count() != base+2 {
		t.Fatalf("paced flush sent %d texts, want 1", r.own.count()-base-1)
	}
	if r.g.Reserve(false) {
		t.Fatal("reserved with items still batched")
	}
	r.advance(time.Hour)
	r.g.Tick()
	if r.own.count() != base+3 {
		t.Fatal("the kept items were not sent in the next hour")
	}
	if _, items := r.own.last(t); len(items) != 1 {
		t.Fatalf("next hour's request carries %d items, want 1", len(items))
	}
}

// TestReissuedIntentsGoOutsideTheBudget (W9a, security R3 on #95): an
// intent re-issued after a restart (GR10) runs on its original expiry, so
// a spent budget must not hold it until it lapses unseen. Its texts go
// unpaced, but still count on RequestsPerHour, so questions see them.
func TestReissuedIntentsGoOutsideTheBudget(t *testing.T) {
	r := newRig(t, func(c *Config) { c.RequestsPerHour = 2 })
	r.grant(mailGrant())
	var refs []string
	for _, rec := range []string{"inv-1", "inv-2"} {
		x := sam()
		x.Record = rec
		r.ver.set(rec, x)
		r.effect("agent/"+rec, "invoice.send", map[string]any{"record": rec}, "sam@example.com")
		refs = append(refs, "agent/"+rec)
	}
	r.g.Flush()
	req, items := r.own.last(t)
	for _, it := range items {
		r.boot = append(r.boot, owner.Carried{Ref: it.Ref, Request: req, Asked: r.now(), Expires: r.now().Add(10 * time.Minute), Sum: owner.ItemSum(it)})
	}
	if _, err := r.eng.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.open() // restart under STOP: nothing is re-issued yet
	if !r.g.Reserve(false) || !r.g.Reserve(false) {
		t.Fatal("questions refused on a fresh budget")
	}
	base := r.own.count()
	r.eng.Resume()
	r.g.Tick()
	r.advance(2 * time.Minute)
	r.g.Tick()
	if got := r.own.count() - base; got != 2 || len(r.own.each) != 2 {
		t.Fatalf("re-issued %d texts with the budget spent, want 2", got)
	}
	for _, ref := range refs {
		if st := r.state(ref); st.State != journal.Pending {
			t.Fatalf("%s: %s %q", ref, st.State, st.Permission.Reason)
		}
	}
	r.advance(30 * time.Minute)
	if r.g.Reserve(false) {
		t.Fatal("re-issued texts were not counted: a question went out over the budget")
	}
}

// REQ: CH-15, CAP-10
//
// W9a PQ5 (potency on #95): a question that has waited AgedAfter unsent
// goes ahead of a waiting approval batch, at most once an hour, and never
// past the hour's budget, so steady approval traffic cannot hold it
// indefinitely and approvals keep the rest of the budget.
func TestAnAgedQuestionGoesAheadOfABatchOnceAnHour(t *testing.T) {
	r := newRig(t, func(c *Config) { c.RequestsPerHour = 3 })
	r.grant(mailGrant()) // the grant's request: one text
	ask := func(id string) {
		t.Helper()
		x := sam()
		x.Record = id
		r.ver.set(id, x)
		r.effect("agent/"+id, "invoice.send", map[string]any{"record": id}, "sam@example.com")
	}
	ask("a")
	if r.g.Reserve(false) {
		t.Fatal("a question went ahead of a waiting batch")
	}
	if !r.g.Reserve(true) {
		t.Fatal("an aged question was held behind the batch")
	}
	if r.g.Reserve(true) {
		t.Fatal("a second aged question went ahead in the same hour")
	}
	r.advance(59 * time.Minute)
	if r.g.Reserve(true) {
		t.Fatal("went ahead again within the hour")
	}
	r.advance(time.Minute)
	if !r.g.Reserve(true) {
		t.Fatal("refused an hour after the last one went ahead")
	}

	// The budget still bounds it.
	r.advance(2 * time.Hour)
	r.g.Tick()
	for n := 0; r.g.Reserve(false); n++ { // spend what the batch left
		if n == 3 {
			t.Fatal("more than the hour's budget")
		}
	}
	ask("b")
	if r.g.Reserve(true) {
		t.Fatal("went ahead with the hour's budget spent")
	}

	// With no batch waiting, an aged question is an ordinary reservation
	// and spends no turn ahead.
	r.advance(2 * time.Hour)
	r.g.Tick()
	if !r.g.Reserve(true) {
		t.Fatal("refused with no batch and the budget free")
	}
	ask("c")
	if !r.g.Reserve(true) {
		t.Fatal("an ordinary reservation used the hour's turn ahead")
	}
}
