package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/routerule"
)

// REQ: ADP-4, CH-12, CH-15

// openNoted opens routing as openRouting does, with the digest line queued
// on the pipeline as openLearning wires it.
func openNoted(t *testing.T, store change.Store, f *fakeRouting) (*syncedRouting, *change.Pipeline) {
	t.Helper()
	s, p := openRouting(t, store, f)
	fs, _ := store.(change.FileStore)
	s.wire(p, fs.Path+".learned")
	return s, p
}

// W3-route (L3 S1 on #96; UX-108-1 on #108): when the owner's -rule stands
// in for an adopted rule the vault process refuses, the owner's digest
// says so in one fixed line, not a text of its own (CH-15: it is not
// urgent). One line per refused rule, kept by the pipeline across a
// restart; a line that could not be queued is tried at the next check.
func TestTheDigestSaysWhenTheOwnersRuleStandsIn(t *testing.T) {
	if n, gsm := modem.Segments(routingStandsInText); !gsm || n != 1 {
		t.Fatalf("the line is %d segments (GSM-7 %v): %q", n, gsm, routingStandsInText)
	}
	dir := t.TempDir()
	store := change.FileStore{Path: filepath.Join(dir, "change.json")}
	s, p := openNoted(t, store, &fakeRouting{base: owners, rule: reordered})
	if !s.check(context.Background()) {
		t.Fatal("not in step")
	}
	if got := p.Digest(); len(got) != 0 {
		t.Fatalf("digest with nothing refused: %q", got)
	}

	// The owner changes -rule, so the adopted order is refused at restart.
	// Queuing fails once; the next check queues it.
	changed := routerule.Rule{"chat": {ra, rc}}
	vault := &fakeRouting{base: changed, rule: changed}
	s, p = openNoted(t, store, vault)
	fail := true
	s.note = func(k, l string) error {
		if fail {
			return errors.New("store full")
		}
		return p.Notice(k, l)
	}
	s.check(context.Background())
	if got := p.Digest(); len(got) != 0 {
		t.Fatalf("a line counted as queued when it failed: %q", got)
	}
	fail = false
	settleChecks(s, 3)
	if got := p.Digest(); len(got) != 1 || got[0] != routingStandsInText {
		t.Fatalf("digest: %q", got)
	}
	if rule, _ := vault.now(); !sameRule(rule, changed) {
		t.Fatalf("vault process routes by %v", rule)
	}

	// A restart refuses the same rule again: no second line.
	s, p = openNoted(t, store, vault)
	settleChecks(s, 3)
	if got := p.Digest(); len(got) != 0 {
		t.Fatalf("a restart repeated the line: %q", got)
	}

	// While agentosd runs, the owner changes -rule under another adopted
	// order: the checks refuse it, and the digest says so once more.
	learned := routerule.Rule{"chat": {rc, ra}}
	vault3 := &fakeRouting{base: changed, rule: learned}
	s, p = openNoted(t, change.FileStore{Path: filepath.Join(dir, "change3.json")}, vault3)
	settleChecks(s, 3)
	vault3.set(func(f *fakeRouting) { f.base, f.rule = owners, owners })
	settleChecks(s, 3)
	settleChecks(s, 3)
	if got := p.Digest(); len(got) != 1 || got[0] != routingStandsInText {
		t.Fatalf("digest after a refusal while running: %q", got)
	}
	if rule, _ := vault3.now(); !sameRule(rule, owners) {
		t.Fatalf("vault process routes by %v", rule)
	}
}

func settleChecks(s *syncedRouting, n int) {
	for i := 0; i < n; i++ {
		s.check(context.Background())
	}
}

// W3-route-a (potency PR1 on #108): a refused learned order is carried
// onto the owner's new rule: routes still there keep their learned
// relative order, new routes keep the owner's places, gone routes drop.
func TestProjectKeepsTheLearnedOrderWithinTheOwnersRule(t *testing.T) {
	rd := routerule.Route{Provider: "anthropic", Model: "claude-new"}
	for _, c := range []struct {
		learned, owner, want routerule.Rule
	}{
		// rb was preferred to ra; rc is gone; rd is new in the owner's second place.
		{routerule.Rule{"chat": {rb, rc, ra}}, routerule.Rule{"chat": {ra, rd, rb}}, routerule.Rule{"chat": {rb, rd, ra}}},
		// A class the box never learned keeps the owner's order.
		{routerule.Rule{"chat": {rb, ra}}, routerule.Rule{"chat": {ra, rb}, "code": {rc, ra}}, routerule.Rule{"chat": {rb, ra}, "code": {rc, ra}}},
		// Nothing learned survives: the owner's rule.
		{routerule.Rule{"chat": {rc}}, routerule.Rule{"chat": {ra, rb}}, routerule.Rule{"chat": {ra, rb}}},
	} {
		got := project(c.learned, c.owner)
		if !sameRule(got, c.want) {
			t.Errorf("project(%v, %v) = %v, want %v", c.learned, c.owner, got, c.want)
		}
		if !reorders(got, c.owner) {
			t.Errorf("%v is not a reordering of %v", got, c.owner)
		}
	}
}

// reorders reports whether r has exactly base's routes in each class.
func reorders(r, base routerule.Rule) bool {
	if len(r) != len(base) {
		return false
	}
	for c, rs := range base {
		if len(r[c]) != len(rs) {
			return false
		}
		for _, x := range rs {
			found := false
			for _, y := range r[c] {
				found = found || x == y
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// W3-route-a: while the owner's rule stands in, Loop 1's routing candidate
// is the projection, so the pipeline evaluates it (CHG-6) and never
// adopts it directly. It gives way to the router's own measured proposal
// once there is one, and ends once something else is adopted. The digest
// line says the box will check the learned order.
func TestARefusedOrderIsProposedProjected(t *testing.T) {
	store := change.FileStore{Path: filepath.Join(t.TempDir(), "change.json")}
	learned := routerule.Rule{"chat": {rb, ra}}
	openNoted(t, store, &fakeRouting{base: owners, rule: learned})
	changed := routerule.Rule{"chat": {ra, rc, rb}}
	vault := &fakeRouting{base: changed, rule: changed}
	s, p := openNoted(t, store, vault)
	settleChecks(s, 3)
	r := routerOf{s, p}
	want := routerule.Rule{"chat": {rb, rc, ra}}
	if got := r.Candidate(); !sameRule(got, want) {
		t.Fatalf("candidate %v, want %v", got, want)
	}
	if got := p.Digest(); len(got) != 1 || got[0] != routingProjectedText {
		t.Fatalf("digest: %q", got)
	}
	// L3 MUST-1 on #110: the pipeline records the owner's rule (the empty
	// tree), so evaluating the projection compares it with what runs.
	if f := p.Files("routing"); len(f) != 0 {
		t.Fatalf("the evaluation's base is still the refused order: %v", f)
	}
	// A restart still proposes it, and adds no second line.
	s, p = openNoted(t, store, vault)
	settleChecks(s, 2)
	r = routerOf{s, p}
	if got := r.Candidate(); !sameRule(got, want) {
		t.Fatalf("candidate after a restart %v", got)
	}
	if got := p.Digest(); len(got) != 0 {
		t.Fatalf("digest after a restart: %q", got)
	}
	if n, gsm := modem.Segments(routingProjectedText); !gsm || n != 1 {
		t.Fatalf("the line is %d segments: %q", n, routingProjectedText)
	}
	if rule, _ := vault.now(); !sameRule(rule, changed) {
		t.Fatalf("the projection was applied without evaluation: %v", rule)
	}
	// The router's own measurement on the new rule supersedes it.
	measured := routerule.Rule{"chat": {rc, ra, rb}}
	vault.set(func(f *fakeRouting) { f.cand = measured })
	if got := r.Candidate(); !sameRule(got, measured) {
		t.Fatalf("candidate with a measurement %v", got)
	}
	// Once something else is adopted (the pipeline's rule is no longer
	// the refused one), there is no projection.
	if _, ok := projected(want, learned, changed); ok {
		t.Fatal("projection offered after an adoption")
	}
	if got, ok := projected(nil, learned, changed); !ok || !sameRule(got, want) {
		t.Fatalf("projection while standing in: %v %v", got, ok)
	}
	// The pipeline adopting anything ends the kept order, across restarts.
	s.active = func() routerule.Rule { return want }
	s.check(context.Background())
	if l := s.learnedRule(); l != nil {
		t.Fatalf("learned order kept after an adoption: %v", l)
	}
	if b, _ := s.learnedStore.Load(); len(b) != 0 {
		t.Fatalf("learned order still saved: %s", b)
	}
}
