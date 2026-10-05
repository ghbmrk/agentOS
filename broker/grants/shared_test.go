package grants

// REQ: CH-15

import (
	"testing"
	"time"
)

// TestQuestionTextsShareTheRequestBudget (W9, question Q3, UX-71-1):
// owner-question texts count toward RequestsPerHour, and Pacing tells the
// question book how many request texts went and whether a batch waits.
func TestQuestionTextsShareTheRequestBudget(t *testing.T) {
	others := 2
	r := newRig(t, func(c *Config) {
		c.RequestsPerHour = 3 // the grant's request uses one
		c.OtherTexts = func(time.Time) int { return others }
	})
	r.grant(mailGrant())
	base := r.own.count()
	if n, waiting := r.g.Pacing(r.now()); n != 1 || waiting {
		t.Fatalf("Pacing after the grant's request: %d %v", n, waiting)
	}
	x := sam()
	x.Record = "a"
	r.ver.set("a", x)
	r.effect("agent/a", "invoice.send", map[string]any{"record": "a"}, "sam@example.com")
	if _, waiting := r.g.Pacing(r.now()); !waiting {
		t.Fatal("a batched item is not reported waiting")
	}
	r.advance(2 * time.Minute)
	r.g.Tick()
	if r.own.count() != base {
		t.Fatal("sent with 1 request and 2 question texts in the hour")
	}
	others = 1
	r.g.Tick()
	if r.own.count() != base+1 {
		t.Fatal("not sent once the shared budget had room")
	}
	if n, waiting := r.g.Pacing(r.now()); n != 2 || waiting {
		t.Fatalf("Pacing after sending: %d %v", n, waiting)
	}
}
