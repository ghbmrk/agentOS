package owner

import (
	"context"
	"strings"
	"testing"
	"time"
)

// REQ: CAP-10, CH-3, CH-14

// W9: an owner reply to a question reaches the answer hook only from the
// owner's number, in an unlocked session, with a trailing code stripped;
// it never reaches the agent.
func TestQuestionAnswersReachTheHookUnlockedAndStripped(t *testing.T) {
	var got []string
	r := newRig(t, nil)
	r.edit = func(c *Config) {
		c.Answer = func(_ context.Context, msg string) (string, bool) {
			got = append(got, msg)
			return "Thanks. Q104 answered.", strings.HasPrefix(msg, "Q104")
		}
	}
	r.ch = r.open()
	if out := r.say("Q104 yes"); !strings.HasPrefix(out, "Locked.") || len(got) != 0 {
		t.Fatalf("locked: %q, hook got %q", out, got)
	}
	r.sayFrom(stranger, "Q104 no")
	if len(got) != 0 {
		t.Fatalf("a stranger reached the hook: %q", got)
	}
	r.unlock()
	if out := r.say("Q104 yes " + r.totp()); out != "Thanks. Q104 answered." {
		t.Fatalf("unlocked: %q", out)
	}
	if len(got) != 1 || got[0] != "Q104 yes" {
		t.Fatalf("hook got %q, want the code stripped", got)
	}
	if n := len(r.agent.got()); n != 0 {
		t.Fatalf("an answer reached the agent: %d", n)
	}
}

// W9a (UX R1 on #95): the locked path. A reply to a question sent while
// locked is held for the page (CH-14); neither RUN nor a code by text
// sends it; the owner's run on the page sends it to the answer hook, never
// to the agent.
func TestALockedQuestionAnswerRunsOnlyFromThePage(t *testing.T) {
	var got []string
	r := newRig(t, nil)
	r.edit = func(c *Config) {
		c.Answer = func(_ context.Context, msg string) (string, bool) {
			got = append(got, msg)
			return "Thanks. Q104 answered.", strings.HasPrefix(msg, "Q104")
		}
	}
	r.ch = r.open()
	if out := r.say("Q104 yes"); !strings.HasPrefix(out, "Locked.") {
		t.Fatalf("locked: %q", out)
	}
	if out := r.say("RUN"); len(got) != 0 {
		t.Fatalf("RUN while locked: %q, hook got %q", out, got)
	}
	if out := r.say(r.totp()); !strings.Contains(out, "no code by text opens a session") || len(got) != 0 {
		t.Fatalf("code by text: %q, hook got %q", out, got)
	}
	r.unlock()
	msgs, _, _ := r.ch.LocalHeld()
	var q string
	var shown []string
	for _, m := range msgs {
		shown = append(shown, m.ID)
		if m.Text == "Q104 yes" {
			q = m.ID
		}
	}
	if q == "" {
		t.Fatalf("answer not held: %+v", msgs)
	}
	if n, err := r.ch.LocalRunHeld(shown, []string{q}); n != 1 || err != nil {
		t.Fatalf("run: %d %v", n, err)
	}
	if len(got) != 1 || got[0] != "Q104 yes" {
		t.Fatalf("hook got %q", got)
	}
	if n := len(r.agent.got()); n != 0 {
		t.Fatalf("an answer reached the agent: %d", n)
	}
}

// W9 (question Q5, UX R2 on #71): ApprovalsOpen reports an open approval
// request, so an untagged reply is never taken as a question's answer
// while the owner may mean the request.
func TestApprovalsOpen(t *testing.T) {
	r := newRig(t, nil)
	if r.ch.ApprovalsOpen() {
		t.Fatal("open with no request")
	}
	if _, err := r.ch.Request([]Item{lowItem("i1")}, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	if !r.ch.ApprovalsOpen() {
		t.Fatal("a request is open")
	}
	r.advance(11 * time.Minute)
	r.ch.Tick()
	if r.ch.ApprovalsOpen() {
		t.Fatal("open after the request expired")
	}
}

// REQ: TIM-1, CH-11

// W9a (clock K7, UX-68-3): the owner channel's STATUS carries the box
// clock's time check line.
func TestStatusCarriesTheClockLine(t *testing.T) {
	r := newRig(t, nil)
	r.edit = func(c *Config) {
		c.Notes = []func() string{func() string { return "Time check: box and phone network agree." }}
	}
	r.ch = r.open()
	r.unlock()
	if out := r.say("STATUS"); !strings.HasSuffix(out, " Time check: box and phone network agree.") {
		t.Fatalf("STATUS: %q", out)
	}
}
