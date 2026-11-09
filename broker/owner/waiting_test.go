package owner

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// REQ: CH-14, CH-3, CH-11, D-080, D-087

// Sessions open on the page (D-311): no code by text, in any of the forms
// that used to unlock, opens a session.
func TestNoCodeByTextOpensASession(t *testing.T) {
	r := newRig(t, nil)
	for _, msg := range []func() string{
		func() string { return r.totp() },                   // a code alone
		func() string { return "book a table " + r.totp() }, // a code appended
		func() string { return "NAME Ada " + r.totp() },     // a rename with a code
		func() string { return "YES " + r.totp() },          // a bare YES with a code
		func() string { return "RUN" },                      // the old confirmation
		func() string { return "UNLOCK" },                   // outside challenge mode
	} {
		text := msg()
		r.say(text)
		if r.ch.SessionUnlocked(r.clock()) {
			t.Fatalf("%q opened a session", text)
		}
	}
	if n := len(r.agent.got()); n != 0 {
		t.Fatalf("locked text reached the agent: %d", n)
	}
	// A right code alone says so and names the page; it does not unlock.
	if got := r.say(r.totp()); !strings.Contains(got, "no code by text opens a session") || r.ch.SessionUnlocked(r.clock()) {
		t.Fatalf("code alone: %q", got)
	}
}

// A code appended to a locked message is stripped before the message is
// held, so it never reaches the page's run or a model.
func TestALockedMessageIsHeldWithoutItsCode(t *testing.T) {
	r := newRig(t, nil)
	code := r.totp()
	r.say("book a table " + code)
	msgs, _, _ := r.ch.LocalHeld()
	if len(msgs) != 1 || msgs[0].Text != "book a table" {
		t.Fatalf("held %+v", msgs)
	}
}

// RUN is no longer a word: in an open session it is chat like any other.
func TestRUNIsChat(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	r.say("RUN")
	if got := r.agent.got(); len(got) != 1 || got[0] != "RUN" {
		t.Fatalf("agent got %q", got)
	}
}

// Every locked message is held in arrival order, unauthenticated, and
// never passed to the agent; the locked period gets one reply.
func TestLockedMessagesWaitForThePageInOrderWithOneReply(t *testing.T) {
	r := newRig(t, nil)
	first := r.say("first")
	if !strings.Contains(first, "Wi-Fi page") {
		t.Fatalf("first reply: %q", first)
	}
	if got := r.say("second"); got != "" {
		t.Fatalf("second reply in the same locked period: %q", got)
	}
	r.say(`Liked "nothing"`)
	msgs, _, _ := r.ch.LocalHeld()
	var texts []string
	for _, m := range msgs {
		texts = append(texts, m.Text)
	}
	if !slices.Equal(texts, []string{"first", "second", `Liked "nothing"`}) {
		t.Fatalf("held %q", texts)
	}
	if n := len(r.agent.got()); n != 0 {
		t.Fatalf("held text reached the agent: %d", n)
	}
	// The next locked period gets its one reply again.
	r.unlock()
	r.advance(DefaultUnlockFor + time.Minute)
	if got := r.say("third"); !strings.Contains(got, "Wi-Fi page") {
		t.Fatalf("next locked period: %q", got)
	}
}

// The hold is bounded by size: a message that would pass the bound is
// dropped, never an earlier one, and the drop is counted (D-087).
func TestTheHoldDropsLaterArrivalsAtTheSizeBound(t *testing.T) {
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.HoldSegments = 2 }
	r.ch = r.open()
	r.say("owner's own")
	r.say("spoofed one")
	r.say("spoofed two")
	msgs, dropped, _ := r.ch.LocalHeld()
	if len(msgs) != 2 || msgs[0].Text != "owner's own" || dropped != 1 {
		t.Fatalf("held %+v, dropped %d", msgs, dropped)
	}
	if note := r.ch.heldNote(); !strings.Contains(note, "2 messages wait") || !strings.Contains(note, "1 dropped") {
		t.Fatalf("STATUS note: %q", note)
	}
	// A long message counts by its segments.
	r2 := newRig(t, nil)
	r2.say(strings.Repeat("x", 160*DefaultHoldSegments))
	if msgs, dropped, _ := r2.ch.LocalHeld(); len(msgs) != 0 || dropped != 1 {
		t.Fatalf("over-long message: held %d, dropped %d", len(msgs), dropped)
	}
}

// Each held message is discarded N after it arrives, and counted.
func TestAHeldMessageExpiresNAfterItArrives(t *testing.T) {
	r := newRig(t, nil)
	r.say("old")
	r.advance(DefaultUnlockFor - time.Hour)
	r.say("new")
	r.advance(2 * time.Hour)
	msgs, _, expired := r.ch.LocalHeld()
	if len(msgs) != 1 || msgs[0].Text != "new" || expired != 1 {
		t.Fatalf("held %+v, expired %d", msgs, expired)
	}
}

// Held messages are kept across a restart (OWN-2).
func TestHeldMessagesSurviveARestart(t *testing.T) {
	r := newRig(t, nil)
	r.say("keep me")
	r.ch = r.open()
	if msgs, _, _ := r.ch.LocalHeld(); len(msgs) != 1 || msgs[0].Text != "keep me" {
		t.Fatalf("after restart: %+v", msgs)
	}
}

// The page's tap runs the marked messages in arrival order as the
// owner's, discards the rest of those shown, and keeps one that arrived
// after the page was drawn.
func TestThePageRunsTheMarkedHeldMessagesAndDiscardsTheRest(t *testing.T) {
	r := newRig(t, nil)
	r.say("one")
	r.say("two")
	r.say("three")
	msgs, _, _ := r.ch.LocalHeld()
	shown := []string{msgs[0].ID, msgs[1].ID, msgs[2].ID}
	r.say("late") // arrives after the page was drawn
	if _, err := r.ch.LocalRunHeld(shown, []string{msgs[0].ID}); !errors.Is(err, ErrLocked) {
		t.Fatalf("run without a session: %v", err)
	}
	if _, _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal(err)
	}
	n, err := r.ch.LocalRunHeld(shown, []string{msgs[2].ID, msgs[0].ID})
	r.ch.WaitSends()
	if err != nil || n != 2 {
		t.Fatalf("run: %d, %v", n, err)
	}
	if got := r.agent.got(); !slices.Equal(got, []string{"one", "three"}) {
		t.Fatalf("agent got %q", got)
	}
	left, _, _ := r.ch.LocalHeld()
	if len(left) != 1 || left[0].Text != "late" {
		t.Fatalf("left %+v", left)
	}
	// A list that no longer matches is refused and runs nothing.
	if _, err := r.ch.LocalRunHeld(shown, nil); !errors.Is(err, ErrHeldChanged) {
		t.Fatalf("stale list: %v", err)
	}
	if _, err := r.ch.LocalRunHeld([]string{left[0].ID}, []string{"99"}); !errors.Is(err, ErrHeldChanged) {
		t.Fatalf("unshown mark: %v", err)
	}
	if len(r.agent.got()) != 2 {
		t.Fatalf("a refused run ran")
	}
}

// A held rename runs from the page as a rename in an open session: it
// still takes the texted confirmation (CH-21), never a silent change.
func TestAHeldRenameRunsAsARenameRequest(t *testing.T) {
	r := newRig(t, nil)
	r.say("NAME Ada")
	msgs, _, _ := r.ch.LocalHeld()
	r.unlock()
	if _, err := r.ch.LocalRunHeld([]string{msgs[0].ID}, []string{msgs[0].ID}); err != nil {
		t.Fatal(err)
	}
	r.ch.WaitSends()
	if got := r.inbox(); !strings.Contains(got, `Change my name to "Ada"?`) {
		t.Fatalf("held rename: %q", got)
	}
	if r.ch.codes.st.Name != "" {
		t.Fatalf("renamed without confirmation")
	}
}
