package question

import (
	"context"
	"errors"
	"fmt"
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
