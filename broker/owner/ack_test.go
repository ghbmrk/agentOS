package owner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ: OWN-4, CH-15

// ackTimers is an AfterFunc on the rig's clock: fire runs the timers due.
type ackTimers struct {
	r  *rig
	mu sync.Mutex
	ts []*ackTimer
}

type ackTimer struct {
	due           time.Time
	f             func()
	fired, halted bool
}

func (a *ackTimers) after(d time.Duration, f func()) func() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	t := &ackTimer{due: a.r.clock().Add(d), f: f}
	a.ts = append(a.ts, t)
	return func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		was := !t.fired && !t.halted
		t.halted = true
		return was
	}
}

// fire moves the rig's clock on by d and runs the timers then due.
func (a *ackTimers) fire(d time.Duration) {
	a.r.advance(d)
	now := a.r.clock()
	a.mu.Lock()
	var due []func()
	for _, t := range a.ts {
		if !t.fired && !t.halted && !t.due.After(now) {
			t.fired = true
			due = append(due, t.f)
		}
	}
	a.mu.Unlock()
	for _, f := range due {
		f()
	}
}

// ackRig is an unlocked rig whose acknowledgement timers run on its clock.
func ackRig(t *testing.T) (*rig, *ackTimers) {
	t.Helper()
	r := newRig(t, nil)
	a := &ackTimers{r: r}
	r.edit = func(c *Config) { c.AfterFunc = a.after }
	r.ch = r.open()
	r.unlock()
	r.sentTexts()
	return r, a
}

func (r *rig) acks() int {
	n := 0
	for _, s := range r.sentTexts() {
		if s == AckText {
			n++
		} else {
			r.t.Fatalf("unexpected text %q", s)
		}
	}
	return n
}

// TestOWN4AckWarmAgentAt20s: task chat a warm agent got and has not
// answered gets AckText 20 s after it reached the box, not before; chat
// no agent got gets none.
func TestOWN4AckWarmAgentAt20s(t *testing.T) {
	r, a := ackRig(t)
	r.say("book a table")
	a.fire(19 * time.Second)
	if n := r.acks(); n != 0 {
		t.Fatalf("%d acknowledgements at 19 s", n)
	}
	a.fire(time.Second)
	if n := r.acks(); n != 1 {
		t.Fatalf("%d acknowledgements at 20 s, want 1", n)
	}

	r = newRig(t, nil)
	a = &ackTimers{r: r}
	r.down = true
	r.edit = func(c *Config) { c.AfterFunc = a.after }
	r.ch = r.open()
	r.unlock()
	r.say("book a table")
	r.sentTexts()
	a.fire(time.Minute)
	if n := r.acks(); n != 0 {
		t.Fatalf("%d acknowledgements for chat no agent got", n)
	}
}

// TestOWN4AckOncePerMessage: one acknowledgement covers the messages that
// reached the box while it was due; a message after it went, still
// unanswered, gets its own, and none goes twice for one message.
func TestOWN4AckOncePerMessage(t *testing.T) {
	r, a := ackRig(t)
	r.say("book a table")
	a.fire(5 * time.Second)
	r.say("for four")
	a.fire(time.Hour)
	if n := r.acks(); n != 1 {
		t.Fatalf("%d acknowledgements for two messages in one wait, want 1", n)
	}
	r.say("at eight")
	a.fire(20 * time.Second)
	if n := r.acks(); n != 1 {
		t.Fatalf("%d acknowledgements for a later message, want 1", n)
	}
	a.fire(time.Hour)
	if n := r.acks(); n != 0 {
		t.Fatalf("%d acknowledgements repeated", n)
	}
}

// TestOWN4NoAckAfterReply: a reply that went out before 20 s stops the
// acknowledgement; a reply that was refused, so never went, does not.
func TestOWN4NoAckAfterReply(t *testing.T) {
	r, a := ackRig(t)
	r.say("book a table")
	a.fire(10 * time.Second)
	if err := r.ch.Converse("Booked for eight."); err != nil {
		t.Fatal(err)
	}
	r.sentTexts()
	a.fire(time.Hour)
	if n := r.acks(); n != 0 {
		t.Fatalf("%d acknowledgements after a reply", n)
	}

	r, a = ackRig(t)
	r.say("book a table")
	a.fire(10 * time.Second)
	if err := r.ch.Converse(`Liked “book a table”`); !errors.Is(err, ErrAgentReaction) {
		t.Fatalf("a reaction-shaped reply: %v, want ErrAgentReaction", err)
	}
	a.fire(10 * time.Second)
	if n := r.acks(); n != 1 {
		t.Fatalf("%d acknowledgements after a failed reply, want 1", n)
	}
}

// TestOWN4AckCarriesNoAgentContent: the acknowledgement is the fixed
// first-person wording, with no agent prefix and nothing of the agent's;
// it is conversation, so it goes in quiet hours and with the hour's texts
// spent, and does not count toward the hour.
func TestOWN4AckCarriesNoAgentContent(t *testing.T) {
	if AckText != "On it." {
		t.Fatalf("AckText %q", AckText)
	}
	r := pacedRig(t, Pacing{QuietFrom: 22 * 60, QuietTo: 7 * 60, PerHour: 1}, 23, 0)
	a := &ackTimers{r: r}
	edit := r.edit
	r.edit = func(c *Config) { edit(c); c.AfterFunc = a.after }
	r.ch = r.open()
	r.unlock()
	r.sentTexts()
	r.ch.mu.Lock()
	sent := len(r.ch.codes.st.Sent)
	r.ch.mu.Unlock()
	r.say("book a table")
	a.fire(20 * time.Second)
	got := r.sentTexts()
	if len(got) != 1 || got[0] != AckText || strings.HasPrefix(got[0], AgentPrefix) {
		t.Fatalf("acknowledgement in quiet hours: %q", got)
	}
	r.ch.mu.Lock()
	defer r.ch.mu.Unlock()
	if len(r.ch.codes.st.Sent) != sent {
		t.Fatal("the acknowledgement counted toward the hour")
	}
}

// TestOWN4AckWithNoModem: with no modem nothing is armed or sent.
func TestOWN4AckWithNoModem(t *testing.T) {
	r, a := ackRig(t)
	r.ch.cfg.Modem = nil
	r.say("book a table")
	a.fire(time.Minute)
	if err := r.ch.Converse("x"); !errors.Is(err, ErrNoModem) {
		t.Fatalf("Converse with no modem: %v", err)
	}
}

// replyAgent answers each delivery before Deliver returns.
type replyAgent struct{ r *rig }

func (a replyAgent) Deliver(context.Context, string, bool) error {
	return a.r.ch.Converse("Booked for eight.")
}

// TestOWN4NoAckForReactions: a reaction is an event, not task chat, so it
// arms no acknowledgement, whether it is to a reply or to "On it." itself.
func TestOWN4NoAckForReactions(t *testing.T) {
	r, a := ackRig(t)
	r.say("book a table")
	if err := r.ch.Converse("Booked for eight."); err != nil {
		t.Fatal(err)
	}
	r.sentTexts()
	r.say(`Liked “Booked for eight.”`)
	a.fire(time.Hour)
	if n := r.acks(); n != 0 {
		t.Fatalf("%d acknowledgements after a reaction to a reply", n)
	}

	r, a = ackRig(t)
	r.say("book a table")
	a.fire(20 * time.Second)
	if n := r.acks(); n != 1 {
		t.Fatalf("%d acknowledgements, want 1", n)
	}
	for i := 0; i < 3; i++ {
		r.say(`Liked “On it.”`)
		a.fire(time.Hour)
		if n := r.acks(); n != 0 {
			t.Fatalf("%d acknowledgements after a reaction to %q", n, AckText)
		}
	}
	if len(r.agent.got()) < 2 {
		t.Fatal("the reaction never reached the agent")
	}
}

// TestOWN4NoAckAfterReplyDuringDelivery: a reply that went out before
// Deliver returned is a reply to the task, so no acknowledgement follows.
func TestOWN4NoAckAfterReplyDuringDelivery(t *testing.T) {
	r := newRig(t, nil)
	a := &ackTimers{r: r}
	r.edit = func(c *Config) { c.AfterFunc = a.after; c.Agent = replyAgent{r} }
	r.ch = r.open()
	r.unlock()
	r.sentTexts()
	r.say("book a table")
	r.sentTexts()
	a.fire(time.Hour)
	if n := r.acks(); n != 0 {
		t.Fatalf("%d acknowledgements after a reply sent during delivery", n)
	}
}

// TestOWN4NoAckAfterStop: STOP, by text or from the local page, voids an
// acknowledgement due, so "On it." never follows "Stopped."; task chat
// after it arms its own.
func TestOWN4NoAckAfterStop(t *testing.T) {
	r, a := ackRig(t)
	r.say("book a table")
	a.fire(5 * time.Second)
	if got := r.say("STOP"); !strings.Contains(got, "Stopped") {
		t.Fatalf("STOP: %q", got)
	}
	a.fire(time.Hour)
	if n := r.acks(); n != 0 {
		t.Fatalf("%d acknowledgements after STOP", n)
	}
	r.say("book a table")
	a.fire(20 * time.Second)
	if n := r.acks(); n != 1 {
		t.Fatalf("%d acknowledgements for task chat after STOP, want 1", n)
	}

	r, a = ackRig(t)
	r.say("book a table")
	if err := r.ch.LocalStop(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.fire(time.Hour)
	if n := r.acks(); n != 0 {
		t.Fatalf("%d acknowledgements after a local STOP", n)
	}
}

// TestOWN4QuestionInChatStopsAck: a question asked while the chat is open
// goes through Converse, so it is a reply and stops the acknowledgement.
func TestOWN4QuestionInChatStopsAck(t *testing.T) {
	r, a := ackRig(t)
	r.say("book a table")
	if !r.ch.ChatOpen() {
		t.Fatal("chat not open after task chat")
	}
	if err := r.ch.Converse("For how many?"); err != nil {
		t.Fatal(err)
	}
	r.sentTexts()
	a.fire(time.Hour)
	if n := r.acks(); n != 0 {
		t.Fatalf("%d acknowledgements after a question in chat", n)
	}
}

// TestOWN4AckBoundsAsOwnerCommands: ACK 5 and ACK 120, the bounds, are
// taken from the owner and set the wait.
func TestOWN4AckBoundsAsOwnerCommands(t *testing.T) {
	for _, n := range []int{5, 120} {
		r, a := ackRig(t)
		if got := r.say(fmt.Sprintf("ACK %d", n)); !strings.HasPrefix(got, fmt.Sprintf("Acknowledgement set: %d seconds.", n)) {
			t.Fatalf("ACK %d: %q", n, got)
		}
		r.say("book a table")
		a.fire(time.Duration(n)*time.Second - time.Second)
		if k := r.acks(); k != 0 {
			t.Fatalf("ACK %d: %d acknowledgements early", n, k)
		}
		a.fire(time.Second)
		if k := r.acks(); k != 1 {
			t.Fatalf("ACK %d: %d acknowledgements, want 1", n, k)
		}
	}
}

// TestOWN4NoAckAfterRunEnds: an acknowledgement due when Run returns is
// stopped, so no timer outlives the channel.
func TestOWN4NoAckAfterRunEnds(t *testing.T) {
	r, a := ackRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.ch.Run(ctx) }()
	r.ch.mu.Lock()
	r.ch.armAckLocked(r.clock())
	r.ch.mu.Unlock()
	cancel()
	<-done
	a.fire(time.Hour)
	if n := r.acks(); n != 0 {
		t.Fatalf("%d acknowledgements after Run ended", n)
	}
}
