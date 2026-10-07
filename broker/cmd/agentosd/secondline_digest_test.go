package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modelroute"
)

// REQ: CH-15, CH-12, ADP-12

// W5 (potency on #142, UX-159-1): the digest repeats each second-line
// line daily for 7 days, then weekly, and at once when it changes. The key
// counts from when the line was first seen, starting with the first
// digest; the line is the STATUS line verbatim.
func TestW5SecondLineDigestCadence(t *testing.T) {
	shown := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	if _, ok := secondLineDigestKey("", shown, shown); ok {
		t.Fatal("a key with no line")
	}
	keys := map[string]bool{}
	for h := 0; h <= 24*29; h++ {
		k, ok := secondLineDigestKey(secondLineConfirmLine, shown, shown.Add(time.Duration(h)*time.Hour))
		if !ok || !strings.HasSuffix(k, secondLineConfirmLine) {
			t.Fatalf("hour %d: key %q", h, k)
		}
		keys[k] = true
	}
	// Days 0 to 7 daily, then weeks from day 8: 8-14, 15-21, 22-28, 29.
	if len(keys) != 8+4 {
		t.Fatalf("%d digest lines in 29 days, want 12", len(keys))
	}
	a, _ := secondLineDigestKey(secondLineConfirmLine, shown, shown.Add(30*time.Hour))
	b, _ := secondLineDigestKey(secondLineUnreachedLine, shown, shown.Add(30*time.Hour))
	if a == b {
		t.Fatal("a changed line kept the old key")
	}
	if k, _ := secondLineDigestKey(secondLineConfirmLine, shown, shown); strings.HasPrefix(k, "sr2-3s:") {
		t.Fatalf("key %q shares the rollback line's namespace", k)
	}
}

// The tick queues each current line under its cadence key, remembers when
// each was first seen, and forgets a line once it clears, so a line that
// comes back starts again at day 0 (it changed).
func TestW5SecondLineDigestTick(t *testing.T) {
	st, tx := modelroute.SecondLineConfirm, modelroute.TextsOK
	sl := &secondLine{
		get:   func(context.Context) (modelroute.SecondLineState, error) { return st, nil },
		texts: func(context.Context) (modelroute.TextsState, error) { return tx, nil },
	}
	d := &secondLineDigest{line: sl}
	got := map[string]string{}
	notice := func(key, line string) error { got[key] = line; return nil }
	ctx := context.Background()
	t0 := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	tick := func(at time.Time) {
		t.Helper()
		sl.refresh(ctx)
		sl.refreshTexts(ctx)
		if err := d.tick(at, notice); err != nil {
			t.Fatal(err)
		}
	}
	tick(t0)
	if len(got) != 1 {
		t.Fatalf("first tick queued %d lines: %v", len(got), got)
	}
	tick(t0.Add(time.Hour))
	if len(got) != 1 {
		t.Fatalf("same day queued again: %v", got)
	}
	tx = modelroute.TextsSignIn
	tick(t0.Add(2 * time.Hour))
	if len(got) != 2 {
		t.Fatalf("a new texting line was not queued at once: %v", got)
	}
	tick(t0.Add(26 * time.Hour))
	if len(got) != 4 {
		t.Fatalf("day 1 queued %d keys in all, want 4: %v", len(got), got)
	}
	for k, l := range got {
		if l != secondLineConfirmLine && l != textsSignInLine {
			t.Fatalf("key %q carries %q, not a STATUS line", k, l)
		}
	}
	// The calling line clears, then comes back: day 0 again.
	st = modelroute.SecondLineOK
	tick(t0.Add(27 * time.Hour))
	st = modelroute.SecondLineConfirm
	before := len(got)
	tick(t0.Add(28 * time.Hour))
	if len(got) != before+1 {
		t.Fatalf("a returning line was not queued at once (%d -> %d)", before, len(got))
	}
	if d.shown[secondLineConfirmLine] != t0.Add(28*time.Hour) {
		t.Fatalf("returning line counts from %v", d.shown[secondLineConfirmLine])
	}
	if _, ok := d.shown[secondLineUnreachedLine]; ok {
		t.Fatal("a line never shown is remembered")
	}
}
