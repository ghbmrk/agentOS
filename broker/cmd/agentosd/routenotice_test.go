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
	s.note = p.Notice
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
