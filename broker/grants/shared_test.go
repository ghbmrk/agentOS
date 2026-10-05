package grants

// REQ: CH-15, CAP-10

import (
	"fmt"
	"testing"
	"time"
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
	if !r.g.Reserve(r.now()) || !r.g.Reserve(r.now()) {
		t.Fatal("two questions refused with two texts left")
	}
	if r.g.Reserve(r.now()) {
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
	if r.g.Reserve(r.now()) {
		t.Fatal("a question went ahead of a waiting approval request")
	}
	r.advance(2 * time.Minute)
	r.g.Tick()
	if r.own.count() != base+1 {
		t.Fatalf("batch not sent: %d", r.own.count()-base)
	}
	if !r.g.Reserve(r.now()) {
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
	if r.g.Reserve(r.now()) {
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
