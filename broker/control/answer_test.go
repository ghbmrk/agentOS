package control

import (
	"context"
	"testing"
)

// REQ: CAP-10, CH-3, CH-14
//
// W9: an owner reply to a question ("Q104 yes") is answered by the broker
// only in an unlocked session, after settings, and never reaches the
// agent; a PUBLIC task and a locked session never reach the hook.

func TestQuestionAnswersAreTakenBeforeTheAgent(t *testing.T) {
	agent := &recAgent{}
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, agent)
	var seen []string
	h.Answer = func(_ context.Context, msg string) (string, bool) {
		seen = append(seen, msg)
		if msg == "Q104 yes" {
			return "Thanks. Q104 answered: \"yes\".", true
		}
		return "", false
	}
	h.Settings = func(_ context.Context, msg string, _ bool) (string, bool) {
		return "Spare-time work is off.", msg == "loops off"
	}
	if got := one(t, h.Handle(context.Background(), owner, "Q104 yes")); got != "Thanks. Q104 answered: \"yes\"." || agent.text != "" {
		t.Fatalf("%q, agent got %q", got, agent.text)
	}
	h.Handle(context.Background(), owner, "book a table")
	if agent.text != "book a table" {
		t.Fatalf("task chat not delivered: %q", agent.text)
	}
	h.Handle(context.Background(), owner, "loops off")
	h.Handle(context.Background(), owner, "STATUS")
	h.Handle(context.Background(), owner, "PUBLIC Q104 yes")
	if len(seen) != 2 || agent.text != "Q104 yes" || !agent.public {
		t.Fatalf("hook saw %q; agent got %q", seen, agent.text)
	}
}

func TestALockedSessionAnswersNoQuestion(t *testing.T) {
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: false}, forbiddenAgent{t})
	h.Answer = func(context.Context, string) (string, bool) {
		t.Fatal("a locked session reached the answer hook")
		return "", false
	}
	if got := one(t, h.Handle(context.Background(), owner, "Q104 yes")); got != unlockText {
		t.Fatalf("%q", got)
	}
}
