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
