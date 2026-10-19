package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/question"
)

// REQ: CH-15, CAP-10

// TestQuestionSendMarksOnlyRefusalsAsNotSent (#2363, D-116): the owner
// channel's refusals sent nothing, so the book holds those questions
// for a retry under the same IDs; any other error may have reached the
// owner, so it is booked as sent and never texted twice.
func TestQuestionSendMarksOnlyRefusalsAsNotSent(t *testing.T) {
	for _, err := range []error{modem.ErrNotSent, owner.ErrPaced, owner.ErrAgentReaction, owner.ErrNoModem, fmt.Errorf("link: %w", modem.ErrNotSent)} {
		got := questionSend(func(string) error { return err })("Q100 synthetic")
		if !errors.Is(got, question.ErrNotSent) || !errors.Is(got, err) {
			t.Errorf("%v: got %v, want question.ErrNotSent", err, got)
		}
	}
	for _, err := range []error{nil, modem.ErrDown, errors.New("modem: timed out")} {
		if got := questionSend(func(string) error { return err })("Q100 synthetic"); errors.Is(got, question.ErrNotSent) || !errors.Is(got, err) {
			t.Errorf("%v: got %v, want it booked as sent", err, got)
		}
	}
}

// chatSource is a fake owner channel: it counts the asks and answers
// open as set.
type chatSource struct {
	asked int
	open  bool
}

func (c *chatSource) ChatOpen() bool {
	c.asked++
	return c.open
}

// TestQuestionChattingFollowsTheChannel (potency A2 on #2372): the book
// sees the chat open only when the owner channel says task chat reached
// the agent within the owner's window, never otherwise, and asks the
// channel each time rather than caching.
func TestQuestionChattingFollowsTheChannel(t *testing.T) {
	ch := &chatSource{}
	chatting := questionChatting(ch)
	if chatting() {
		t.Fatal("chat open while the channel reports none")
	}
	ch.open = true
	if !chatting() {
		t.Fatal("chat closed while the channel reports one")
	}
	ch.open = false
	if chatting() {
		t.Fatal("chat stayed open after the channel closed it")
	}
	if ch.asked != 3 {
		t.Fatalf("asked the channel %d times, want 3", ch.asked)
	}
}
