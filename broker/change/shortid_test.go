package change

// REQ: CH-12, CHG-6

import (
	"testing"
)

// C11: adoption IDs come from the owner channel's allocator, and the
// channel can ask, without taking the pipeline's lock, which IDs the
// pipeline still uses, so an UNDO K3 never names both an adoption and an
// approval request. The answer survives a restart.
func TestShortIDsSharedWithTheOwnerChannel(t *testing.T) {
	var lent []string
	e := newEnv(t, func(c *Config) {
		c.ShortID = func(taken func(string) bool) (string, error) {
			for _, id := range []string{"Q7", "Q8", "Q9"} {
				if !taken(id) {
					lent = append(lent, id)
					return id, nil
				}
			}
			t.Fatal("allocator ran out")
			return "", nil
		}
	})
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Origin: "loop1", Files: Tree{"skills/greet": []byte("hello")}})
	if a.State != StateAdopted || a.Short != "Q7" {
		t.Fatalf("adoption %+v", a)
	}
	if !e.p.ShortInUse("Q7") || e.p.ShortInUse("Q8") || e.p.ShortInUse("") {
		t.Fatal("ShortInUse does not match the adoptions")
	}
	// Undone, Q7 is still one the owner may quote: it stays taken.
	if err := e.p.Revert(bg, "Q7", OriginOwner); err != nil {
		t.Fatal(err)
	}
	if !e.p.ShortInUse("Q7") {
		t.Fatal("an undone adoption's ID was freed at once")
	}
	b := e.propose(Candidate{Source: Local, Origin: "loop1", Files: Tree{"skills/greet": []byte("hello")}})
	if b.State != StateAdopted || b.Short != "Q8" {
		t.Fatalf("second adoption reused an ID: %+v (lent %v)", b, lent)
	}
	// After a restart the pipeline still reports its IDs before anything
	// else touches it.
	p2, err := New(Config{Store: e.store, Evaluator: e.ev, MinHeldOut: 3, DevPercent: 30, MinSecurity: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !p2.ShortInUse("Q7") || !p2.ShortInUse("Q8") {
		t.Fatal("ShortInUse forgot the adoptions after a restart")
	}
}

// An allocator with nothing to give (the owner channel not up yet) returns
// "": the pipeline's own sequence is used, still clear of its other IDs.
func TestEmptyShortIDFallsBackToThePipelinesOwn(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.ShortID = func(func(string) bool) (string, error) { return "", nil }
	})
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Origin: "loop1", Files: Tree{"skills/greet": []byte("hello")}})
	if a.State != StateAdopted || !shortOK(a.Short) || !e.p.ShortInUse(a.Short) {
		t.Fatalf("fallback adoption %+v", a)
	}
}
