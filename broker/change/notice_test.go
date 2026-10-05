package change

import (
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/route"
)

// REQ: CH-15, CHG-6

// W3-route (UX-108-1): a broker notice is a digest line, never a text of
// its own. Notice keeps it once per key, across a restart; the digest
// lists it once; the kept keys are bounded.
func TestNoticesAreDigestLinesOncePerKey(t *testing.T) {
	e := newEnv(t, nil)
	e.p.Digest()
	if err := e.p.Notice("routing:a", "Line A."); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Notice("routing:a", "Line A."); err != nil {
		t.Fatal(err)
	}
	if got := e.p.Digest(); len(got) != 1 || got[0] != "Line A." {
		t.Fatalf("digest: %q", got)
	}
	if got := e.p.Digest(); len(got) != 0 {
		t.Fatalf("listed twice: %q", got)
	}
	// After a restart the same key is still known: no second line.
	p, err := New(Config{Store: e.store, Evaluator: e.ev})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Notice("routing:a", "Line A."); err != nil {
		t.Fatal(err)
	}
	if got := p.Digest(); len(got) != 0 {
		t.Fatalf("a restart repeated a notice: %q", got)
	}
	// A notice not yet listed survives a restart.
	if err := p.Notice("routing:b", "Line B."); err != nil {
		t.Fatal(err)
	}
	p, err = New(Config{Store: e.store, Evaluator: e.ev})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Digest(); len(got) != 1 || got[0] != "Line B." {
		t.Fatalf("after a restart: %q", got)
	}
	for i := 0; i < 2*MaxNotices; i++ {
		if err := p.Notice(fmt.Sprintf("k%d", i), "x"); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(p.st.Notices); n > MaxNotices {
		t.Fatalf("%d notices kept", n)
	}
}

// W3-route-a (L3 MUST-1 on #110): when the owner's own configuration
// replaced a namespace's adopted state outside the pipeline, Superseded
// records the owner's configuration (the empty tree) as active, so the
// next evaluation's base is what actually runs; the adoption that set the
// old state is marked undone by the owner's settings, without UNDO or a
// line of its own. A stale call changes nothing.
func TestSupersededRecordsTheOwnersConfiguration(t *testing.T) {
	cur := route.Rule{"mail": {{Provider: "openai", Model: "m"}, {Provider: "anthropic", Model: "c"}}}
	e := newEnv(t, func(c *Config) {
		c.Initial[RoutingPath] = canonicalJSON(cur)
		c.RouteGranted = func(string) bool { return true }
	})
	next := route.Rule{"mail": {{Provider: "anthropic", Model: "c"}, {Provider: "openai", Model: "m"}}}
	ruleCase(e, next, 12)
	if rep := e.propose(Candidate{Source: Local, Files: Tree{RoutingPath: canonicalJSON(next)}}); rep.State != StateAdopted {
		t.Fatal(rep)
	}
	e.p.Digest()
	was := e.p.Files("routing")
	if ok, err := e.p.Superseded("routing", Tree{RoutingPath: canonicalJSON(cur)}); err != nil || ok {
		t.Fatalf("a stale tree superseded the active one: %v %v", ok, err)
	}
	ok, err := e.p.Superseded("routing", was)
	if err != nil || !ok {
		t.Fatalf("superseded: %v %v", ok, err)
	}
	if f := e.p.Files("routing"); len(f) != 0 {
		t.Fatalf("active routing after the owner's settings: %v", f)
	}
	if f := e.p.Files("skills"); len(f) == 0 {
		t.Fatal("another namespace was dropped")
	}
	for _, a := range e.p.Adoptions() {
		if a.Reverted != WhySettings {
			t.Fatalf("adoption %s: reverted %q", a.Short, a.Reverted)
		}
	}
	if d := e.p.Digest(); len(d) != 0 {
		t.Fatalf("superseding wrote its own lines: %q", d)
	}
	p, err := New(Config{Store: e.store, Evaluator: e.ev, Initial: Tree{RoutingPath: canonicalJSON(cur)}})
	if err != nil {
		t.Fatal(err)
	}
	if f := p.Files("routing"); len(f) != 0 {
		t.Fatalf("after a restart: %v", f)
	}
}
