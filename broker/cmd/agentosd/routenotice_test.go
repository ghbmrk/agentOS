package main

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/routerule"
)

// REQ: ADP-4, CH-12

// informs records the owner texts the box sends; fail makes sending fail.
type informs struct {
	mu   sync.Mutex
	sent []string
	fail bool
}

func (i *informs) inform(text string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.fail {
		return errors.New("no owner channel")
	}
	i.sent = append(i.sent, text)
	return nil
}

func (i *informs) texts() []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]string(nil), i.sent...)
}

// W3-route (L3 S1 on #96): when the owner's -rule stands in for an adopted
// rule the vault process refuses, the owner is told once, in one fixed
// text, not only the log. Telling is kept on disk per refused rule, so a
// restart does not repeat it; a text that could not be sent is tried
// again at the next check.
func TestTheOwnerIsToldWhenTheirRuleStandsIn(t *testing.T) {
	if n, gsm := modem.Segments(routingStandsInText); !gsm || n != 1 {
		t.Fatalf("the notice is %d segments (GSM-7 %v): %q", n, gsm, routingStandsInText)
	}
	dir := t.TempDir()
	store := change.FileStore{Path: filepath.Join(dir, "change.json")}
	told := change.FileStore{Path: filepath.Join(dir, "routing-told.json")}
	s, _ := openRouting(t, store, &fakeRouting{base: owners, rule: reordered})
	if !s.check(context.Background()) {
		t.Fatal("not in step")
	}

	// The owner changes -rule, so the adopted order is refused at restart.
	// The channel is not up yet: nothing is lost, it is sent next check.
	changed := routerule.Rule{"chat": {ra, rc}}
	in := &informs{fail: true}
	vault := &fakeRouting{base: changed, rule: changed}
	s, _ = openRouting(t, store, vault)
	s.inform, s.told = in.inform, told
	s.check(context.Background())
	if len(in.texts()) != 0 {
		t.Fatal("a text counted as sent with no channel")
	}
	in.fail = false
	for i := 0; i < 3; i++ {
		s.check(context.Background())
	}
	if got := in.texts(); len(got) != 1 || got[0] != routingStandsInText {
		t.Fatalf("owner texts: %q", got)
	}
	if rule, _ := vault.now(); !sameRule(rule, changed) {
		t.Fatalf("vault process routes by %v", rule)
	}

	// A restart refuses the same rule again: no second text.
	in2 := &informs{}
	s, _ = openRouting(t, store, vault)
	s.inform, s.told = in2.inform, told
	settleChecks(s, 3)
	if got := in2.texts(); len(got) != 0 {
		t.Fatalf("told again after a restart: %q", got)
	}

	// While agentosd runs, the owner changes -rule under another adopted
	// order: the checks refuse it, and the owner is told once more.
	learned := routerule.Rule{"chat": {rc, ra}}
	vault3 := &fakeRouting{base: changed, rule: learned}
	in3 := &informs{}
	s, _ = openRouting(t, change.FileStore{Path: filepath.Join(dir, "change3.json")}, vault3)
	s.inform, s.told = in3.inform, told
	settleChecks(s, 3)
	vault3.set(func(f *fakeRouting) { f.base, f.rule = owners, owners })
	settleChecks(s, 3)
	settleChecks(s, 3)
	if got := in3.texts(); len(got) != 1 || got[0] != routingStandsInText {
		t.Fatalf("owner texts after a refusal while running: %q", got)
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
