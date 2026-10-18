package question

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// REQ: CH-15, CAP-10

// TestAQuestionInAnOpenChatIsNotCounted (#2363): while the owner's task
// chat is open, a question is conversation: it goes by Converse, in
// quiet hours too, and does not count toward the hour (CH-15). Outside
// the chat the next question takes the hour's one text, and the one
// after it is held.
func TestAQuestionInAnOpenChatIsNotCounted(t *testing.T) {
	var conversed []string
	chat := true
	r := newRig(t, func(c *Config) {
		c.SendsPerHour, c.PerAsker = 1, 5
		c.Chat = func() bool { return chat }
		c.Converse = func(text string) error { conversed = append(conversed, text); return nil }
	})
	r.set(func() { r.quiet = true })
	for _, req := range []string{"a", "b"} {
		if st := r.ask("lin1", req, slot()); st.State != Waiting {
			t.Fatalf("question %s in an open chat: %+v", req, st)
		}
	}
	if len(conversed) != 2 || len(r.texts()) != 0 {
		t.Fatalf("in chat: %d conversed, %d pushed", len(conversed), len(r.texts()))
	}
	r.set(func() { r.quiet = false; chat = false })
	if st := r.ask("lin1", "c", slot()); st.State != Waiting {
		t.Fatalf("first question outside the chat was held: %+v", st)
	}
	if st := r.ask("lin1", "d", slot()); st.State != Held {
		t.Fatalf("second question outside the chat went past the hour's limit: %+v", st)
	}
	if len(r.texts()) != 1 {
		t.Fatalf("pushed %d texts, want 1", len(r.texts()))
	}
}

// TestAnUnknownSendIsBooked (#2363): a send whose outcome is unknown may
// have reached the owner, so it is counted toward the hour and its
// questions keep their ID and wait as texted, never re-sent as a second
// text (CH-15, D-116). Only a send that provably did not go is held for
// a retry.
func TestAnUnknownSendIsBooked(t *testing.T) {
	tries := 0
	r := newRig(t, func(c *Config) {
		c.SendsPerHour, c.PerAsker = 1, 5
		send := c.Send
		c.Send = func(text string) error { tries++; return send(text) }
	})
	r.set(func() { r.sendErr = errors.New("modem: outcome unknown") })
	st := r.ask("lin1", "a", slot())
	if st.State != Waiting || st.ID != "Q100" {
		t.Fatalf("unknown send not booked: %+v", st)
	}
	r.set(func() { r.sendErr = nil })
	r.b.Tick(context.Background())
	if tries != 1 {
		t.Fatalf("an unknown send was retried: %d tries", tries)
	}
	if st := r.ask("lin1", "b", slot()); st.State != Held {
		t.Fatalf("the unknown send did not count toward the hour: %+v", st)
	}
	if tries != 1 {
		t.Fatalf("texted past the hour's limit: %d tries", tries)
	}
}

// TestANotSentSendIsHeldForRetry (#2363): ErrNotSent means the text did
// not go: nothing is counted, and the retry carries the same ID.
func TestANotSentSendIsHeldForRetry(t *testing.T) {
	r := newRig(t, func(c *Config) { c.SendsPerHour = 1 })
	r.set(func() { r.sendErr = fmt.Errorf("owner: paced: %w", ErrNotSent) })
	if st := r.ask("lin1", "a", slot()); st.State != Held {
		t.Fatalf("a not-sent text was booked: %+v", st)
	}
	r.set(func() { r.sendErr = nil })
	r.b.Tick(context.Background())
	st := r.status("lin1", "a")
	if st.State != Waiting || st.ID != "Q100" || len(r.texts()) != 1 || !strings.Contains(r.texts()[0], "Q100") {
		t.Fatalf("retry: %+v, texts %q", st, r.texts())
	}
}

// TestTheUrgentPathKeepsTheHourlyLimit (#2363, D-129): an urgent
// question skips the shared reservation, but the book's own limit still
// holds it, unknown sends included, so a flooding agent stays bounded.
func TestTheUrgentPathKeepsTheHourlyLimit(t *testing.T) {
	tries := 0
	r := newRig(t, func(c *Config) {
		c.SendsPerHour, c.PerAsker = 2, 5
		c.Reserve = func(bool) bool { return true } // approval is urgent
		send := c.Send
		c.Send = func(text string) error { tries++; return send(text) }
	})
	r.set(func() { r.sendErr = errors.New("modem: outcome unknown") })
	for i, req := range []string{"a", "b", "c", "d"} {
		r.ask(fmt.Sprintf("lin%d", i), req, slot())
		r.b.Tick(context.Background())
	}
	if tries != 2 {
		t.Fatalf("urgent questions made %d send attempts in the hour, want 2", tries)
	}
	if st := r.status("lin3", "d"); st.State != Held {
		t.Fatalf("question past the limit: %+v", st)
	}
}

// TestTheLimitFollowsTexts (#2363, CH-15): the hourly limit is the
// owner's TEXTS setting as it is at each send, so raising or lowering it
// takes effect without a restart.
func TestTheLimitFollowsTexts(t *testing.T) {
	n := 1
	r := newRig(t, func(c *Config) {
		c.PerAsker = 10
		c.PerHour = func() int { return n }
	})
	r.ask("lin1", "a", slot())
	if st := r.ask("lin1", "b", slot()); st.State != Held {
		t.Fatalf("TEXTS 1: second question not held: %+v", st)
	}
	n = 3
	r.b.Tick(context.Background())
	if st := r.status("lin1", "b"); st.State != Waiting {
		t.Fatalf("TEXTS 3: held question not sent: %+v", st)
	}
	r.ask("lin1", "c", slot())
	if st := r.ask("lin1", "d", slot()); st.State != Held || len(r.texts()) != 3 {
		t.Fatalf("TEXTS 3: fourth question %+v, %d texts", st, len(r.texts()))
	}
	n = 1
	r.advance(30 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "d"); st.State != Held {
		t.Fatalf("TEXTS lowered to 1: question sent past it: %+v", st)
	}
	r.advance(31 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "d"); st.State != Waiting {
		t.Fatalf("after the hour: %+v", st)
	}
}

// fillTags texts n questions, one per burner lineage, 3m1s apart, and
// answers each at once, so each keeps its tag for Keep after the answer.
// It ticks at every step, so any pruning a shorter Keep allowed would
// free tags inside the fill.
func fillTags(t *testing.T, r *rig, n int) map[string]bool {
	t.Helper()
	seen := map[string]bool{}
	for i := range n {
		st := r.ask(fmt.Sprintf("burner%d", i), "q", slot())
		if st.State != Waiting || seen[st.ID] {
			t.Fatalf("question %d: %+v (tag reused: %v)", i, st, seen[st.ID])
		}
		seen[st.ID] = true
		if _, ok := r.answer(st.ID + " 9:00"); !ok {
			t.Fatalf("answer %s not taken", st.ID)
		}
		r.advance(3*time.Minute + time.Second)
		r.b.Tick(context.Background())
	}
	return seen
}

// tagRig is a book that texts up to TEXTS 20 an hour, the setting that
// fills the tag room fastest.
func tagRig(t *testing.T) *rig {
	return newRig(t, func(c *Config) {
		c.SendsPerHour, c.PerAsker = 1000, 1
		c.PerHour = func() int { return 20 }
		c.MaxSendsPerHour = 1000
	})
}

var textTagRE = regexp.MustCompile(`\bQ[1-9][0-9]{2}:`) // a question's lead-in in a text

// TestATagIsNotReusedWhileKept (security B2 on #2372): however many
// texts TEXTS allows, closed questions keep their tags for the whole of
// Keep (96 h, ASSUMPTIONS Q5 and Q11), so a late "Q100" answer never
// reaches another lineage's question. Once kept questions would leave no
// tag for an asker under the open cap, new questions are held, not
// texted, until the oldest age out: still held a minute before the first
// kept question is 96 h old, texted once it is past that.
func TestATagIsNotReusedWhileKept(t *testing.T) {
	r := tagRig(t)
	if r.b.cfg.Keep != 96*time.Hour {
		t.Fatalf("Keep %v, want 96h", r.b.cfg.Keep)
	}
	r.mu.Lock()
	first := r.clock // Q100 is answered, so closed, at once
	r.mu.Unlock()
	room := numTags - r.b.cfg.MaxOpen
	seen := fillTags(t, r, room)
	if reply, _ := r.answer("Q100 9:00"); !strings.Contains(reply, "already") {
		t.Fatalf("a late Q100 answer: %q", reply)
	}
	st := r.ask("late", "q", slot())
	if st.State != Held || seen[st.ID] {
		t.Fatalf("question past the tag room: %+v", st)
	}
	r.mu.Lock()
	gap := first.Add(96*time.Hour - time.Minute).Sub(r.clock)
	r.mu.Unlock()
	r.advance(gap)
	r.b.Tick(context.Background())
	if st := r.status("late", "q"); st.State != Held {
		t.Fatalf("a minute before the first kept question is 96 h old: %+v", st)
	}
	r.advance(time.Minute + time.Second)
	r.b.Tick(context.Background())
	if st := r.status("late", "q"); st.State != Waiting {
		t.Fatalf("after the kept questions aged out: %+v", st)
	}
}

// TestATextJoinsNoMoreThanTheTagRoom (potency M6 on #2372): with room
// for fewer questions than one text carries, a text takes only that many
// and the rest stay held.
func TestATextJoinsNoMoreThanTheTagRoom(t *testing.T) {
	r := tagRig(t)
	fillTags(t, r, numTags-r.b.cfg.MaxOpen-2)
	r.advance(time.Hour) // the hour's texts are clear again
	r.set(func() { r.quiet = true })
	for _, asker := range []string{"x", "y", "z"} {
		if st := r.ask(asker, "q", slot()); st.State != Held {
			t.Fatalf("%s in quiet hours: %+v", asker, st)
		}
	}
	before := len(r.texts())
	r.set(func() { r.quiet = false })
	r.b.Tick(context.Background())
	texts := r.texts()[before:]
	if len(texts) != 1 || len(textTagRE.FindAllString(texts[0], -1)) != 2 {
		t.Fatalf("with room for 2: texts %q", texts)
	}
	held := 0
	for _, asker := range []string{"x", "y", "z"} {
		if r.status(asker, "q").State == Held {
			held++
		}
	}
	if held != 1 {
		t.Fatalf("%d questions held, want 1", held)
	}
}

// TestAChatQuestionGoesWhenTheHoursTextsAreSpent (#2363, potency M7 on
// #2372): the owner's pushes for the hour are spent, then the owner
// starts task chat: the agent's next question goes at once as
// conversation, not after the hour.
func TestAChatQuestionGoesWhenTheHoursTextsAreSpent(t *testing.T) {
	var conversed []string
	chat := false
	r := newRig(t, func(c *Config) {
		c.PerAsker = 5
		c.PerHour = func() int { return 1 }
		c.Chat = func() bool { return chat }
		c.Converse = func(text string) error { conversed = append(conversed, text); return nil }
	})
	if st := r.ask("lin1", "a", slot()); st.State != Waiting {
		t.Fatalf("first question: %+v", st)
	}
	if st := r.ask("lin1", "b", slot()); st.State != Held {
		t.Fatalf("second question past TEXTS 1: %+v", st)
	}
	chat = true
	r.advance(time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "b"); st.State != Waiting || len(conversed) != 1 || len(r.texts()) != 1 {
		t.Fatalf("in the chat: %+v, %d conversed, %d pushed", st, len(conversed), len(r.texts()))
	}
}

// chatRig is a book whose owner chat is always open; it counts
// conversation texts and reservations of the shared budget.
func chatRig(t *testing.T, conversed, reserves *int) *rig {
	return newRig(t, func(c *Config) {
		c.PerAsker = 1
		c.Chat = func() bool { return true }
		c.Converse = func(string) error { *conversed++; return nil }
		c.Reserve = func(bool) bool { *reserves++; return true }
	})
}

// TestAChatFloodStopsAtTwentyAnHour (potency M12 on #2372): conversation
// does not count toward TEXTS, but no more than 20 question texts go in
// any hour, so a flooding agent stays bounded in an open chat.
func TestAChatFloodStopsAtTwentyAnHour(t *testing.T) {
	var conversed, reserves int
	r := chatRig(t, &conversed, &reserves)
	for i := range 20 {
		st := r.ask(fmt.Sprintf("lin%d", i), "q", slot())
		if st.State != Waiting {
			t.Fatalf("chat question %d: %+v", i, st)
		}
		if _, ok := r.answer(st.ID + " 9:00"); !ok {
			t.Fatalf("answer %s not taken", st.ID)
		}
		r.advance(time.Minute)
	}
	if st := r.ask("lin20", "q", slot()); st.State != Held || conversed != 20 {
		t.Fatalf("21st chat question in the hour: %+v, %d conversed", st, conversed)
	}
	r.advance(41 * time.Minute) // the first text is past the hour
	r.b.Tick(context.Background())
	if st := r.status("lin20", "q"); st.State != Waiting || conversed != 21 {
		t.Fatalf("after the hour: %+v, %d conversed", st, conversed)
	}
}

// TestAChatQuestionReservesNothing (ASSUMPTIONS Q17, potency M14 on
// #2372): a question in an open chat is conversation and never spends
// the shared CH-15 budget that approval requests reserve.
func TestAChatQuestionReservesNothing(t *testing.T) {
	var conversed, reserves int
	r := chatRig(t, &conversed, &reserves)
	for _, asker := range []string{"lin1", "lin2", "lin3"} {
		if st := r.ask(asker, "q", slot()); st.State != Waiting {
			t.Fatalf("%s: %+v", asker, st)
		}
	}
	if conversed != 3 || reserves != 0 || len(r.texts()) != 0 {
		t.Fatalf("%d conversed, %d reserves, %d pushed", conversed, reserves, len(r.texts()))
	}
}
