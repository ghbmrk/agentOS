package control

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// REQ: CH-12, CH-18

// fiveShortNotes gives h five 9-byte notes, L1 to L5, after a 70-byte
// head, so every page length below is a sum of known parts: a 25-byte
// "STATUS, more line N of 5:" or 28-byte "STATUS, more lines A-B of 5:"
// header, 10 bytes a line with its space, and a 21-byte
// " Next: MORE STATUS N." tail.
func fiveShortNotes(t *testing.T) *Handler {
	t.Helper()
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, nil)
	for i := 1; i <= 5; i++ {
		l := fmt.Sprintf("L%d xxxxx.", i)
		h.Notes = append(h.Notes, func() string { return l })
	}
	return h
}

// Each MORE STATUS page is the most whole lines that fit max, counting a
// page whose length equals max as fitting, with the singular header for
// one line, and one line when none fits.
func TestMoreStatusPageExact(t *testing.T) {
	h := fiveShortNotes(t)
	for _, c := range []struct {
		from, max int
		want      string
	}{
		{1, 78, "STATUS, more lines 1-5 of 5: L1 xxxxx. L2 xxxxx. L3 xxxxx. L4 xxxxx. L5 xxxxx."},
		{1, 77, "STATUS, more lines 1-2 of 5: L1 xxxxx. L2 xxxxx. Next: MORE STATUS 3."},
		{1, 69, "STATUS, more lines 1-2 of 5: L1 xxxxx. L2 xxxxx. Next: MORE STATUS 3."},
		{1, 68, "STATUS, more line 1 of 5: L1 xxxxx. Next: MORE STATUS 2."},
		{1, 56, "STATUS, more line 1 of 5: L1 xxxxx. Next: MORE STATUS 2."},
		{1, 40, "STATUS, more line 1 of 5: L1 xxxxx. Next: MORE STATUS 2."},
		{2, 68, "STATUS, more lines 2-5 of 5: L2 xxxxx. L3 xxxxx. L4 xxxxx. L5 xxxxx."},
		{3, 58, "STATUS, more lines 3-5 of 5: L3 xxxxx. L4 xxxxx. L5 xxxxx."},
		{4, 47, "STATUS, more line 4 of 5: L4 xxxxx. Next: MORE STATUS 5."},
		{5, 35, "STATUS, more line 5 of 5: L5 xxxxx."},
		{5, 20, "STATUS, more line 5 of 5: L5 xxxxx."},
		{6, 78, "STATUS has 5 more lines. Reply MORE STATUS."},
	} {
		if got := h.moreStatus(c.from, c.max); got != c.want {
			t.Errorf("moreStatus(%d, %d) = %q, want %q", c.from, c.max, got, c.want)
		}
	}
}

// MORE STATUS past the end names the count in the singular for one line,
// and says nothing is left when STATUS fits.
func TestMoreStatusEndWording(t *testing.T) {
	h := fiveShortNotes(t)
	big := "Big " + strings.Repeat("y", 45) + "."
	h.Notes = append(h.Notes, func() string { return big })
	// 70 + 5*10 + 51 = 171 > 170, room 142 takes the five short lines only.
	if got, want := h.moreStatus(2, 170), "STATUS has 1 more line. Reply MORE STATUS."; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got, want := h.moreStatus(1, 170), "STATUS, more line 1 of 1: "+big; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got, want := h.moreStatus(1, 171), "STATUS fits one text; nothing more to show."; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// statusFit keeps every line when the whole text is exactly max, and a
// line that exactly fills the room left for the tail.
func TestStatusFitBoundaries(t *testing.T) {
	lines := []string{"aaaa", strings.Repeat("b", moreMax+5)}
	n := 1 + 5 + 1 + len(lines[1])
	if text, left := statusFit("H", lines, n); left != nil || text != "H "+lines[0]+" "+lines[1] {
		t.Fatalf("at max = n: %q, %q", text, left)
	}
	// room = max - moreMax = 6 = len("H aaaa").
	if text, left := statusFit("H", lines, 6+moreMax); text != "H aaaa" || len(left) != 1 || left[0] != lines[1] {
		t.Fatalf("at a line filling room: %q, %q", text, left)
	}
	if text, left := statusFit("H", lines, 5+moreMax); text != "H" || len(left) != 2 {
		t.Fatalf("one byte short: %q, %q", text, left)
	}
}

// STATUS's head counts each phase and samples at most three labels, with
// the rest counted; with none, no sample.
func TestStatusHeadExact(t *testing.T) {
	eng := &fakeEngine{}
	h, _ := newHandler(t, eng, fakeAuth{unlocked: true}, nil)
	if got, want := h.Status(), "Running. 0 may have happened, 0 waiting to run, 0 awaiting a decision."; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	st := func(a string, p Phase) Status { return Status{Action: a, Account: "acct", Phase: p} }
	eng.list = []Status{st("aa", Unsettled), st("ab", Unsettled), st("ac", Unsettled), st("ha", Held), st("hb", Held), st("oa", Open)}
	if got, want := h.Status(), "Running. 3 may have happened (aa/acct, ab/acct, ac/acct), 2 waiting to run, 1 awaiting a decision."; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	eng.list = append(eng.list, st("ad", Unsettled))
	eng.stopped = true
	if got, want := h.Status(), "Stopped. 4 may have happened (aa/acct, ab/acct, ac/acct, +1 more), 2 waiting to run, 1 awaiting a decision."; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// ctxAgent keeps the context Deliver was given.
type ctxAgent struct{ ctx context.Context }

func (c *ctxAgent) Deliver(ctx context.Context, _ string, _ bool) error { c.ctx = ctx; return nil }

// deliver cancels its timeout context once Deliver returns.
func TestDeliverCancelsItsContext(t *testing.T) {
	a := &ctxAgent{}
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, a)
	if !h.deliver(context.Background(), Command{Text: "hi"}) || a.ctx == nil || a.ctx.Err() != context.Canceled {
		t.Fatalf("ctx after deliver: %v", a.ctx)
	}
}

// RESUME states the code's life in whole minutes.
func TestResumeCodeMinutes(t *testing.T) {
	h, now := newHandler(t, &fakeEngine{stopped: true}, fakeAuth{unlocked: true}, nil)
	if got, want := h.resumeCmd(nil), "To restart all actions, reply RESUME 111111 within 15 min."; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	*now = now.Add(5 * time.Minute)
	if got, want := h.resumeCmd(nil), "To restart all actions, reply RESUME 111111 within 10 min."; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The third wrong reply says the code is void, and it stays void: the
// right code after it does not resume.
func TestResumeVoidCodeStaysVoid(t *testing.T) {
	eng := &fakeEngine{stopped: true}
	h, _ := newHandler(t, eng, fakeAuth{unlocked: true}, nil)
	h.resumeCmd(nil)
	for i, want := range []string{"Wrong code. Reply RESUME <code>.", "Wrong code. Reply RESUME <code>.",
		"Wrong code 3 times; it is void. Reply RESUME for a new one."} {
		if got := h.resumeCmd([]string{"000000"}); got != want {
			t.Fatalf("wrong reply %d: %q, want %q", i+1, got, want)
		}
	}
	if got := h.resumeCmd([]string{"111111"}); got != "No valid code. Reply RESUME for a new one." || !eng.Stopped() {
		t.Fatalf("right code after void: %q", got)
	}
}

// RESUME while running voids an issued code, so it cannot lift a later
// STOP the engine recorded without this handler (another channel's).
func TestResumeWhileRunningVoidsCode(t *testing.T) {
	eng := &fakeEngine{stopped: true}
	h, _ := newHandler(t, eng, fakeAuth{unlocked: true}, nil)
	h.resumeCmd(nil)
	eng.stopped = false
	if got := h.resumeCmd([]string{"111111"}); got != "Not stopped. Nothing to resume." {
		t.Fatalf("running: %q", got)
	}
	eng.stopped = true
	if got := h.resumeCmd([]string{"111111"}); got != "No valid code. Reply RESUME for a new one." || !eng.Stopped() {
		t.Fatalf("old code after a later stop: %q", got)
	}
}

// The fifth wrong code in 24 hours voids the code it was tried against,
// so that code cannot resume once the oldest wrong code ages out and the
// lock lifts while it is still within its CodeTTL (CH-18).
func TestResumeLockVoidsCodeBeforeItLifts(t *testing.T) {
	eng := &fakeEngine{stopped: true}
	h, now := newHandler(t, eng, fakeAuth{unlocked: true}, nil)
	t0 := *now
	h.resumeCmd(nil) // 111111
	for i := 0; i < maxWrong; i++ {
		h.resumeCmd([]string{"000000"})
	}
	h.resumeCmd(nil) // 222222
	h.resumeCmd([]string{"000000"})
	*now = t0.Add(24*time.Hour - 10*time.Minute)
	if got := h.resumeCmd(nil); got != "To restart all actions, reply RESUME 333333 within 15 min." {
		t.Fatalf("new code: %q", got)
	}
	if got := h.resumeCmd([]string{"000000"}); got != "Wrong code 5 times in 24 hours. RESUME by texted code is locked. STOP still works." {
		t.Fatalf("fifth wrong code: %q", got)
	}
	*now = t0.Add(24*time.Hour + time.Minute) // the four t0 entries age out; 333333 has 4 minutes left
	if got := h.resumeCmd([]string{"333333"}); got != "No valid code. Reply RESUME for a new one." || !eng.Stopped() {
		t.Fatalf("code tried at the lock, after it lifts: %q", got)
	}
}
