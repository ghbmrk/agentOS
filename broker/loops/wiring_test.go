package loops

import (
	"context"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/loops/loopstest"
)

// REQ: HLD-4, CH-14
//
// What the owner channel uses: the owner text hook, what a locked session
// takes, the replies when a setting fails, and old saved state.

func TestOwnerTextChangesSettingsAndLeavesTaskChatAlone(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, ok := r.s.Text(ctx, "learning is off, right?", true); ok {
		t.Fatal("task chat taken as a setting")
	}
	if got, ok := r.s.Text(ctx, "learning off", true); !ok || got != "Learning is off until you reply LEARNING ON." {
		t.Fatalf("%q %v", got, ok)
	}
	if !r.s.Settings().Paused[Improve] {
		t.Fatal("LEARNING OFF did not pause Loop 1")
	}
	if got, ok := r.s.Text(ctx, "SPARE BUDGET 100", true); !ok || r.s.Settings().SpareCalls != 100 {
		t.Fatalf("setting a budget from none: %q %v", got, ok)
	}
	if got, ok := r.s.Text(ctx, "help loops", true); !ok || got != HelpText {
		t.Fatalf("%q %v", got, ok)
	}
}

func TestPluralLoopNamesReadAsPlural(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.s.Text(ctx, "SECURITY TESTS OFF", true)
	found := false
	for _, l := range r.s.Digest() {
		found = found || l == "Security tests are off. Reply SECURITY TESTS ON to restart them."
	}
	if !found {
		t.Fatalf("%q", r.s.Digest())
	}
}

// UX-57-1, CH-14: a session not unlocked with an approval code takes only
// settings whose worst case is a pause. Turning work on, a raise and
// faster updates wait for the unlock, on Text and on Set alike.
func TestALockedSessionTakesOnlyPauses(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if got, ok := r.s.Text(ctx, "LEARNING OFF", false); !ok || got != "Learning is off until you reply LEARNING ON." {
		t.Fatalf("%q %v", got, ok)
	}
	if got, ok := r.s.Text(ctx, "LOOPS OFF", false); !ok || !r.s.Settings().Off {
		t.Fatalf("LOOPS OFF while locked: %q %v", got, ok)
	}
	if got, ok := r.s.Text(ctx, "spare budget 50", false); !ok || r.s.Settings().SpareCalls != 50 {
		t.Fatalf("lowering while locked: %q %v", got, ok)
	}
	refused := []string{"LEARNING ON", "LOOPS ON", "SPARE BUDGET 60", "START SHARING", "UPDATES FAST", "UPDATE SOAK 7"}
	must(t, r.s.Set(ctx, Request{Kind: KindSoak, Days: 14}, true))
	for _, msg := range refused {
		if _, ok := r.s.Text(ctx, msg, false); ok {
			t.Fatalf("%s taken in a locked session", msg)
		}
		req, _ := ParseText(msg)
		if err := r.s.Set(ctx, req, false); err == nil {
			t.Fatalf("Set took %s in a locked session", msg)
		}
	}
	set := r.s.Settings()
	if !set.Off || !set.Paused[Improve] || set.SpareCalls != 50 || set.Updates.ChannelName() != ChannelStable || set.Updates.Soak() != 14 {
		t.Fatalf("%+v", set)
	}
	if r.widened() != 0 || len(r.sharing.calls()) != 0 {
		t.Fatalf("a locked session reached the passkey (%d) or sharing (%v)", r.widened(), r.sharing.calls())
	}
	if got, ok := r.s.Text(ctx, "HELP LOOPS", false); !ok || got != HelpText {
		t.Fatalf("%q %v", got, ok)
	}
	// Narrows is the owner channel's test for the same line, run before
	// it holds a locked session's message for the unlock (W3).
	for msg, want := range map[string]bool{"LOOPS OFF": true, "spare budget 40": true, "HELP LOOPS": true,
		"LOOPS ON": false, "SPARE BUDGET 60": false, "START SHARING": false, "book a table": false} {
		if r.s.Narrows(msg) != want {
			t.Fatalf("Narrows(%q) != %v", msg, want)
		}
	}
}

// UX-57-2: a failed setting says why when the box knows.
func TestAFailedSettingSaysWhy(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if got, _ := r.s.Text(ctx, "SPARE BUDGET 6000", true); got != "The most is 5000 calls a day." {
		t.Fatalf("%q", got)
	}
	r.s.cfg.Sharing = nil
	if got, _ := r.s.Text(ctx, "STOP SHARING", true); got != "Sharing is not available yet." {
		t.Fatalf("%q", got)
	}
	r.s.cfg.Store = &saveFails{MemStore: r.store, early: true}
	if got, _ := r.s.Text(ctx, "UPDATES FAST", true); got != "I could not save that setting. Try again later." {
		t.Fatalf("%q", got)
	}
}

// State saved while settings went through the journal still has seq,
// applied and order; it loads its settings (HLD-4).
func TestOldSavedStateLoads(t *testing.T) {
	r := newRig(t)
	must(t, r.store.Save([]byte(`{"seq":301,"settings":{"off":true,"paused":{"secure":true},"spare_calls":100,"updates":{"channel":"pinned"}},`+
		`"applied":{"loops:n300:off:all":true,"bad":true},"order":["bad","loops:n300:off:all"]}`)))
	r.restart()
	set := r.s.Settings()
	if !set.Off || !set.Paused[Secure] || set.SpareCalls != 100 || set.Updates.ChannelName() != ChannelPinned {
		t.Fatalf("old state loaded as %+v", set)
	}
	if r.spare.Cap() != SpareCap(100, loopstest.OutPerM) {
		t.Fatalf("old budget not applied to the spare key: %d", r.spare.Cap())
	}
	// The next save writes the settings only.
	if _, ok := r.s.Text(context.Background(), "LOOP 1 OFF", true); !ok {
		t.Fatal("LOOP 1 OFF")
	}
	b, err := r.store.Load()
	must(t, err)
	if strings.Contains(string(b), "applied") || strings.Contains(string(b), "seq") {
		t.Fatalf("saved %s", b)
	}
}
