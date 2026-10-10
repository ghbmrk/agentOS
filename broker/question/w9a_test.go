package question

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REQ: CAP-10, TIM-1, CH-15
//
// W9a PQ4 (potency on #95): with no quiet hours to tell, a restricted
// clock does not stop questions. The text gives the wait instead of a
// clock time, pacing and the wait run on the monotonic clock, and the
// first trusted tick dates the question from that clock.
func TestQuestionsAreTextedWhileTheClockIsChecked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "questions.json")
	r := newRig(t, func(c *Config) { c.Quiet, c.SendsPerHour, c.Path = nil, 1, path })
	r.set(func() { r.restricted = true })
	r.ask("lin1", "a", Spec{Text: "Book the 9:00 or the 9:30 dentist slot?", Default: "9:30", Wait: 90 * time.Minute})
	got := r.texts()
	if len(got) != 1 || !strings.Contains(got[0], "Reply Q100 and your answer within 1 hour 30 minutes.") {
		t.Fatalf("texts %q", got)
	}
	st := r.status("lin1", "a")
	if st.State != Waiting || !st.Deadline.IsZero() || !strings.Contains(st.Reason, "clock") {
		t.Fatalf("status %+v", st)
	}
	r.ask("lin2", "b", slot())
	r.advance(59 * time.Minute)
	r.b.Tick(context.Background())
	if n := len(r.texts()); n != 1 {
		t.Fatalf("pacing not held on the monotonic clock: %d texts", n)
	}
	r.advance(time.Minute)
	r.b.Tick(context.Background())
	if got := r.texts(); len(got) != 2 || !strings.Contains(got[1], "within 30 minutes") {
		t.Fatalf("texts %q", got)
	}

	// Trusted again 70 minutes after Q100's text: it is dated from the
	// monotonic clock, so 20 minutes are left.
	r.advance(10 * time.Minute)
	r.set(func() { r.restricted = false })
	if st := r.status("lin1", "a"); st.State != Waiting || !st.Deadline.Equal(r.clock.Add(20*time.Minute)) {
		t.Fatalf("status before the tick: %+v, now %v", st, r.clock)
	}
	r.b.Tick(context.Background())
	if st := r.status("lin1", "a"); !st.Deadline.Equal(r.clock.Add(20 * time.Minute)) {
		t.Fatalf("dated %+v, now %v", st, r.clock)
	}
	if st := r.status("lin2", "b"); !st.Deadline.Equal(r.clock.Add(20 * time.Minute)) {
		t.Fatalf("Q101 dated %+v", st)
	}

	// Restricted again, a texted question lapses on the monotonic clock;
	// one texted and lapsed while restricted gives its wait in the digest
	// and the late reply, and is closed at the next trusted tick.
	r.advance(time.Hour) // past both deadlines and the hour's text
	r.b.Tick(context.Background())
	r.set(func() { r.restricted = true })
	r.ask("lin3", "c", slot())
	r.advance(30 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin3", "c"); st.State != Defaulted {
		t.Fatalf("texted while restricted: %+v", st)
	}
	if out, _ := r.answer("Q102 9:00"); out != `Too late for Q102: I went ahead with "9:30". Your answer is passed on.` {
		t.Fatalf("late reply %q", out)
	}
	d := strings.Join(r.b.TakeDigest(), "\n")
	if !strings.Contains(d, `Q102 "Book the 9:00 or the 9:30 dentist slot?": no reply within 30 minutes, so I went ahead with "9:30".`) {
		t.Fatalf("digest %q", d)
	}
	r.set(func() { r.restricted = false })
	r.b.Tick(context.Background())
	r.set(func() { r.restricted = true })

	// A restart forgets the monotonic reading: a question texted while
	// restricted waits its whole wait again from the restart, never less.
	r.advance(time.Hour)
	r.ask("lin4", "d", slot())
	r.advance(20 * time.Minute)
	r.open()
	r.advance(20 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin4", "d"); st.State != Waiting {
		t.Fatalf("after the restart: %+v", st)
	}
	r.advance(10 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin4", "d"); st.State != Defaulted {
		t.Fatalf("not lapsed a full wait after the restart: %+v", st)
	}
}

// W9a PQ4: with quiet hours configured, a restricted clock holds texts,
// since the box cannot tell whether it is quiet.
func TestQuietHoursHoldTextsWhileTheClockIsChecked(t *testing.T) {
	r := newRig(t, nil) // the rig configures Quiet
	r.set(func() { r.restricted = true })
	if st := r.ask("lin1", "a", slot()); st.State != Held || len(r.texts()) != 0 {
		t.Fatalf("%+v, texts %q", st, r.texts())
	}
}

// W9a PQ4: a question must fit one text both ways it can be rendered, so
// a long wait's words never push it past MaxRendered.
func TestAQuestionFitsWithItsWaitInWords(t *testing.T) {
	r := newRig(t, nil)
	wait := 23*time.Hour + 59*time.Minute
	var choices []string
	for _, w := range []string{"alpha", "bravo", "charlie", "delta"} {
		choices = append(choices, strings.Repeat(w+" ", 8)[:MaxChoice])
	}
	q := &entry{ID: "Q999", Default: choices[0], Choices: choices}
	fits := func(by string) bool { return len(r.b.renderBy(q, by)) <= MaxRendered }
	for n := 1; n <= MaxText/5; n++ {
		q.Text = strings.TrimSpace(strings.Repeat("word ", n))
		if fits("by Mon 15:04") && !fits("within "+waitWords(wait)) {
			_, err := r.b.Ask(context.Background(), "lin1", "b", Spec{Text: q.Text, Default: q.Default, Choices: q.Choices, Wait: wait})
			if err == nil || !strings.Contains(err.Error(), "too long for one text") {
				t.Fatalf("a question too long with its wait in words: %v", err)
			}
			return
		}
	}
	t.Fatal("no question fits by a clock time but not with its wait in words")
}

// REQ: CAP-10, CH-15
//
// W9a PQ5 (potency on #95): a question held AgedAfter since it was asked
// leads the next text, ahead of fresher askers, and its reservation asks
// the gate to let it ahead of a waiting approval batch.
func TestAnAgedQuestionLeadsAndAsksAhead(t *testing.T) {
	var aged []bool
	ok := true
	r := newRig(t, func(c *Config) {
		c.AgedAfter = 20 * time.Minute
		c.Reserve = func(a bool) bool { aged = append(aged, a); return ok || a }
	})
	r.ask("lin1", "x", short("Lunch at noon?")) // lin1 is texted this hour
	ok = false                                  // from now on a batch waits
	r.advance(time.Minute)
	r.ask("lin1", "a", short("Taxi home?"))
	r.advance(9 * time.Minute)
	r.ask("lin2", "b", short("Wine or beer?"))
	r.b.Tick(context.Background())
	if n := len(r.texts()); n != 1 {
		t.Fatalf("%d texts while the batch waits", n)
	}
	r.advance(11 * time.Minute) // lin1's question is 20 minutes old
	r.b.Tick(context.Background())
	got := r.texts()
	if len(got) != 2 || !strings.HasPrefix(got[1], "Q101: Taxi home?") {
		t.Fatalf("texts %q", got)
	}
	if aged[len(aged)-1] != true || aged[1] != false {
		t.Fatalf("reservations %v", aged)
	}
}

// W9a PQ5: a question's age survives a restart. On trusted time it is
// counted from when it was asked; while restricted, from the restart, the
// monotonic clock's reading being gone.
func TestAQuestionsAgeSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "questions.json")
	var aged []bool
	r := newRig(t, func(c *Config) {
		c.Quiet, c.Path = nil, path
		c.Reserve = func(a bool) bool { aged = append(aged, a); return false }
	})
	r.ask("lin1", "a", slot())
	r.advance(30 * time.Minute)
	r.open()
	r.advance(30 * time.Minute)
	r.b.Tick(context.Background())
	if len(aged) != 2 || !aged[1] {
		t.Fatalf("trusted, asked an hour ago: %v", aged)
	}
	r.open()
	r.set(func() { r.restricted = true })
	r.advance(59 * time.Minute)
	r.b.Tick(context.Background())
	r.advance(time.Minute)
	r.b.Tick(context.Background())
	if len(aged) != 4 || aged[2] || !aged[3] {
		t.Fatalf("restricted, an hour after the restart: %v", aged)
	}
}
