package owner

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// REQ: CH-14, D-087
// mutgate on #5194: each line of the hold is pinned by a test that fails
// when it changes.

// countStore counts saves.
type countStore struct {
	MemStore
	saves int
}

func (c *countStore) Save(s State) error { c.saves++; return c.MemStore.Save(s) }

// An overflow is counted and marks the locked period told: the first one
// gets the full-hold reply, later ones and later held messages none.
func TestAnOverflowIsCountedAndRepliedOnce(t *testing.T) {
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.HoldSegments = 1 }
	r.ch = r.open()
	long := strings.Repeat("x", 200)
	if got := r.say(long); !strings.Contains(got, "fill it, so this one was dropped") {
		t.Fatalf("first overflow: %q", got)
	}
	if got := r.say(long); got != "" {
		t.Fatalf("second overflow in the period: %q", got)
	}
	if got := r.say("short"); got != "" {
		t.Fatalf("held after an overflow in the period: %q", got)
	}
	if msgs, dropped, _ := r.ch.LocalHeld(); len(msgs) != 1 || dropped != 2 {
		t.Fatalf("held %+v, dropped %d", msgs, dropped)
	}
}

// A message that cannot be saved is not kept, and the owner is told.
func TestAHeldMessageThatCannotBeSavedIsRefused(t *testing.T) {
	fs := &failStore{}
	r := newRig(t, fs)
	fs.fail = true
	if got := r.say("keep me"); !strings.Contains(got, "could not keep your message") {
		t.Fatalf("reply: %q", got)
	}
	if msgs, _, _ := r.ch.LocalHeld(); len(msgs) != 0 {
		t.Fatalf("held %+v", msgs)
	}
}

// Nothing to expire saves nothing.
func TestExpiringNothingSavesNothing(t *testing.T) {
	cs := &countStore{}
	r := newRig(t, cs)
	r.say("keep me")
	before := cs.saves
	r.ch.LocalHeld()
	r.ch.heldNote()
	if cs.saves != before {
		t.Fatalf("%d saves with nothing to expire", cs.saves-before)
	}
}

// STATUS's note, exactly: one message, and only an expired one.
func TestTheHeldNoteWordsEachCount(t *testing.T) {
	r := newRig(t, nil)
	r.say("one")
	if got := r.ch.heldNote(); got != "1 message waits for you on my Wi-Fi page." {
		t.Fatalf("one held: %q", got)
	}
	r.advance(DefaultUnlockFor)
	if got := r.ch.heldNote(); got != "1 expired unread." {
		t.Fatalf("expired: %q", got)
	}
}

// The approvals sweep expires held messages too.
func TestTheSweepExpiresHeldMessages(t *testing.T) {
	r := newRig(t, nil)
	r.say("one")
	r.advance(DefaultUnlockFor)
	r.ch.mu.Lock()
	r.ch.expireLocked(r.clock())
	n := len(r.ch.codes.st.Waiting)
	r.ch.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d held after the sweep", n)
	}
}

// A page drawn before a message expired cannot run it; a refused mark
// leaves the channel usable; a run resets the counts; a failed save runs
// nothing.
func TestThePageRunRefusesExpiredAndResetsCounts(t *testing.T) {
	fs := &failStore{}
	r := newRig(t, fs)
	r.edit = func(c *Config) { c.HoldSegments = 1 }
	r.ch = r.open()
	r.say("old")
	r.say(strings.Repeat("x", 200)) // dropped
	r.advance(DefaultUnlockFor - time.Hour)
	r.edit = nil
	r.ch = r.open() // the same state, with room for one more
	r.say("new")
	r.unlock()
	msgs, _, _ := r.ch.LocalHeld()
	r.advance(2 * time.Hour)
	if _, err := r.ch.LocalRunHeld([]string{msgs[0].ID, msgs[1].ID}, []string{msgs[0].ID}); !errors.Is(err, ErrHeldChanged) {
		t.Fatalf("expired run: %v", err)
	}
	msgs, _, _ = r.ch.LocalHeld()
	if _, err := r.ch.LocalRunHeld([]string{msgs[0].ID}, []string{"99"}); !errors.Is(err, ErrHeldChanged) {
		t.Fatalf("unshown mark: %v", err)
	}
	done := make(chan struct{})
	go func() { r.ch.LocalHeld(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a refused mark left the channel locked")
	}
	fs.fail = true
	if n, err := r.ch.LocalRunHeld([]string{msgs[0].ID}, []string{msgs[0].ID}); err == nil || n != 0 || len(r.agent.got()) != 0 {
		t.Fatalf("failed save: ran %d, %v", n, err)
	}
	fs.fail = false
	if _, err := r.ch.LocalRunHeld([]string{msgs[0].ID}, nil); err != nil {
		t.Fatal(err)
	}
	if _, dropped, expired := r.ch.LocalHeld(); dropped != 0 || expired != 0 {
		t.Fatalf("counts after a run: dropped %d, expired %d", dropped, expired)
	}
}

// A held message's reply is recorded as a text to the owner, and a run
// with no modem sends nothing and does not fail.
func TestAHeldRunRecordsItsRepliesWithOrWithoutAModem(t *testing.T) {
	for _, modem := range []bool{true, false} {
		r := newRig(t, nil)
		if !modem {
			r.edit = func(c *Config) { c.Modem = nil }
			r.ch = r.open()
		}
		r.say("NAME Ada")
		msgs, _, _ := r.ch.LocalHeld()
		r.unlock()
		if _, err := r.ch.LocalRunHeld([]string{msgs[0].ID}, []string{msgs[0].ID}); err != nil {
			t.Fatal(err)
		}
		r.ch.WaitSends()
		if _, ok := r.ch.recent.match(`Change my name to "Ada"?`, r.clock()); !ok {
			t.Fatalf("modem %v: the rename prompt is not in the recent texts", modem)
		}
	}
}

// A loaded state shares no held message with the store.
func TestALoadedStateSharesNoHeldMessage(t *testing.T) {
	var m MemStore
	if err := m.Save(State{Waiting: []WaitingMsg{{ID: "1", Text: "a"}}}); err != nil {
		t.Fatal(err)
	}
	s, _ := m.Load()
	s.Waiting[0].Text = "b"
	if again, _ := m.Load(); again.Waiting[0].Text != "a" {
		t.Fatalf("store changed through a loaded state: %q", again.Waiting[0].Text)
	}
}
