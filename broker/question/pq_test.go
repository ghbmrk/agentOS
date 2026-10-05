package question

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ: CAP-10, CH-15

// short is a question small enough for several to share a text.
func short(text string) Spec {
	return Spec{Text: text, Default: "wait", Wait: 30 * time.Minute}
}

// PQ1 (potency on #71): held questions share one owner text, up to
// MaxPerText and only while the text fits and is not withheld, so the
// CH-15 budget counts texts, not questions. Each keeps its own tag and
// deadline.
func TestHeldQuestionsShareOneText(t *testing.T) {
	var mu sync.Mutex
	reserved := 0
	r := newRig(t, func(c *Config) {
		c.SendsPerHour = 1
		c.Reserve = func(bool) bool { mu.Lock(); reserved++; mu.Unlock(); return true }
		c.Hidden = func(t string) bool { return strings.Count(t, "Ferry") > 1 } // synthetic
	})
	r.ask("lin1", "a", short("Lunch at noon?"))
	r.ask("lin1", "b", short("Ferry at six?"))
	r.ask("lin2", "a", short("Ferry or train?")) // would make the text look withheld
	r.ask("lin2", "b", short("Wine or beer?"))
	r.ask("lin3", "a", short("Taxi home?"))
	r.ask("lin3", "b", short("Book the hotel?"))
	if n := len(r.texts()); n != 1 {
		t.Fatalf("%d texts in the first hour", n)
	}
	r.advance(time.Hour)
	r.b.Tick(context.Background())
	got := r.texts()
	if len(got) != 2 {
		t.Fatalf("texts %q", got)
	}
	shared := got[1]
	if len(shared) > MaxRendered || strings.Count(shared, "Reply Q") != MaxPerText || strings.Contains(shared, "Ferry or train?") {
		t.Fatalf("shared text %q", shared)
	}
	for _, want := range []string{"Q101: Ferry at six?", "Q103: Wine or beer?", "Q104: Taxi home?", "by 14:30"} {
		if !strings.Contains(shared, want) {
			t.Errorf("shared text %q lacks %q", shared, want)
		}
	}
	for _, q := range [][2]string{{"lin1", "b"}, {"lin2", "b"}, {"lin3", "a"}} {
		if st := r.status(q[0], q[1]); st.State != Waiting || !st.Deadline.Equal(r.clock.Add(30*time.Minute)) {
			t.Fatalf("%s/%s: %+v", q[0], q[1], st)
		}
	}
	if st := r.status("lin2", "a"); st.State != Held {
		t.Fatalf("a question that would get the text withheld: %+v", st)
	}
	mu.Lock()
	n := reserved
	mu.Unlock()
	if n != 2 {
		t.Fatalf("%d reservations for 2 texts", n)
	}
	if reply, ok := r.answer("Q103 beer"); !ok || !strings.Contains(reply, "Q103 answered") {
		t.Fatalf("answer to a shared question: %q %v", reply, ok)
	}
}

// PQ2 (potency on #71): a question with an ask-by that is still unsent by
// then closes as not asked, is listed in the digest, and frees its tag,
// which the owner never saw.
func TestAQuestionNotTextedByItsAskByIsNotAsked(t *testing.T) {
	r := newRig(t, nil)
	r.set(func() { r.quiet = true })
	s := short("Lunch at noon?")
	s.AskWithin = 20 * time.Minute
	if st := r.ask("lin1", "a", s); st.State != Held || st.ID != "Q100" {
		t.Fatalf("ask %+v", st)
	}
	r.advance(19 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "a"); st.State != Held {
		t.Fatalf("closed before its ask-by: %+v", st)
	}
	r.advance(time.Minute)
	r.b.Tick(context.Background())
	st := r.status("lin1", "a")
	if st.State != NotAsked || st.Answer != "" || st.Reason == "" {
		t.Fatalf("after its ask-by: %+v", st)
	}
	r.set(func() { r.quiet = false })
	r.b.Tick(context.Background())
	if len(r.texts()) != 0 {
		t.Fatalf("a not-asked question was texted: %q", r.texts())
	}
	if d := r.b.TakeDigest(); len(d) != 1 || !strings.HasPrefix(d[0], "Not asked:") || !strings.Contains(d[0], "Lunch at noon?") ||
		!strings.Contains(d[0], "13:20") || strings.Contains(d[0], "Q100") {
		t.Fatalf("digest %q", d)
	}
	if _, ok := r.answer("Q100 yes"); ok {
		t.Fatal("a tag the owner never saw took an answer")
	}
	if st := r.ask("lin1", "b", short("Taxi home?")); st.ID != "Q100" && st.ID != "Q101" {
		t.Fatalf("tag %s", st.ID)
	}
	r.b.mu.Lock()
	tags := map[string]int{}
	for _, e := range r.b.qs {
		if e.tagged() {
			tags[e.ID]++
		}
	}
	r.b.mu.Unlock()
	for id, n := range tags {
		if n > 1 {
			t.Fatalf("tag %s held twice", id)
		}
	}
	// The same request ID with another ask-by is another question.
	s2 := s
	s2.AskWithin = time.Hour
	if _, err := r.b.Ask(context.Background(), "lin1", "a", s2); err != ErrConflict {
		t.Fatalf("reused request ID with another ask-by: %v", err)
	}
}

// An ask-by counts from the ask on the monotonic clock, so a restricted
// clock neither stretches it nor lets a question past it be texted (L3
// MUST on #125); it never closes a question once it is texted.
func TestAskByRunsOnTheMonotonicClockAndEndsAtTheText(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Quiet, c.SendsPerHour = nil, 1 })
	r.ask("lin0", "x", short("Taxi home?")) // spends the hour's text
	r.set(func() { r.restricted = true })
	s := short("Lunch at noon?")
	s.AskWithin = 10 * time.Minute
	r.ask("lin1", "a", s)
	r.advance(9 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "a"); st.State != Held {
		t.Fatalf("before its ask-by: %+v", st)
	}
	r.advance(52 * time.Minute)               // the hour's text is free again
	r.ask("lin3", "z", short("Bus or tram?")) // sends before any tick
	if got := r.texts(); len(got) != 2 || strings.Contains(got[1], "Lunch") {
		t.Fatalf("texts %q", got)
	}
	r.b.Tick(context.Background())
	if st := r.status("lin1", "a"); st.State != NotAsked || len(r.texts()) != 2 {
		t.Fatalf("past its ask-by while restricted: %+v, texts %q", st, r.texts())
	}
	if d := strings.Join(r.b.TakeDigest(), "\n"); !strings.Contains(d, `"Lunch at noon?" was held past its ask-by time`) {
		t.Fatalf("digest %q", d)
	}

	// Asked while restricted, trusted later: Asked is dated from the
	// monotonic clock, not from the first trusted tick.
	r.advance(time.Hour)
	r.ask("lin2", "y", short("Wine or beer?")) // spends the hour's text
	r.ask("lin1", "b", s)
	r.advance(6 * time.Minute)
	r.set(func() { r.restricted = false; r.quiet = true })
	r.b.Tick(context.Background())
	r.advance(4 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "b"); st.State != NotAsked {
		t.Fatalf("ask-by counted from the first trusted tick: %+v", st)
	}
	if d := strings.Join(r.b.TakeDigest(), "\n"); !strings.Contains(d, `"Lunch at noon?" was held past 15:11`) {
		t.Fatalf("digest %q", d)
	}

	// Texted in time, the ask-by no longer applies.
	r.advance(time.Hour)
	r.set(func() { r.quiet = false })
	r.ask("lin1", "c", s)
	r.advance(15 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "c"); st.State != Waiting {
		t.Fatalf("texted question: %+v", st)
	}
}

// After a restart while restricted, the ask's monotonic reading is gone,
// so a question with an ask-by waits for trusted time.
func TestAskByAfterARestartWaitsForTrustedTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "questions.json")
	r := newRig(t, func(c *Config) { c.Quiet, c.SendsPerHour, c.Path = nil, 2, path })
	r.ask("lin0", "x", short("Taxi home?"))
	r.ask("lin0", "y", short("Wine or beer?")) // both texts this hour
	s := short("Lunch at noon?")
	s.AskWithin = 30 * time.Minute
	r.ask("lin1", "a", s)
	r.set(func() { r.restricted = true })
	r.open()
	r.advance(time.Hour)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "a"); st.State != Held || len(r.texts()) != 2 {
		t.Fatalf("restricted after a restart: %+v, texts %q", st, r.texts())
	}
	// The texts loaded from before the restart count for its first hour
	// only, so one without an ask-by goes out.
	if st := r.ask("lin2", "b", short("Bus or tram?")); st.State != Waiting {
		t.Fatalf("an hour after the restart: %+v, texts %q", st, r.texts())
	}
	r.set(func() { r.restricted = false })
	r.b.Tick(context.Background())
	if st := r.status("lin1", "a"); st.State != NotAsked {
		t.Fatalf("trusted again, an hour past its ask-by: %+v", st)
	}
}

// PQ3 (potency on #71): owner_question_status can wait for the question
// to change, bounded by MaxPoll and by WaitersPerMachine per machine.
func TestStatusWaitReturnsWhenTheQuestionChanges(t *testing.T) {
	r := newRig(t, func(c *Config) { c.WaitersPerMachine = 1 })
	r.ask("lin1", "a", short("Lunch at noon?"))
	type res struct {
		st  Status
		err error
		in  time.Duration
	}
	done := make(chan res, 1)
	go func() {
		start := time.Now()
		st, err := r.b.Await(context.Background(), "lin1", "a", "m1", time.Hour)
		done <- res{st, err, time.Since(start)}
	}()
	// The waiter is in; a second wait on the same machine answers at once.
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.b.mu.Lock()
		n := r.b.waiters["m1"]
		r.b.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the wait never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	if st, err := r.b.Await(context.Background(), "lin1", "a", "m1", MaxPoll); err != nil || st.State != Waiting || time.Since(start) > time.Second {
		t.Fatalf("a wait past the machine's cap: %+v %v after %v", st, err, time.Since(start))
	}
	r.answer("Q100 yes")
	select {
	case got := <-done:
		if got.err != nil || got.st.State != Answered || got.st.Answer != "yes" || got.in > 5*time.Second {
			t.Fatalf("wait: %+v", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the wait did not return on the answer")
	}
	r.b.mu.Lock()
	left := len(r.b.waiters)
	r.b.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d waiters left", left)
	}
	// A closed question answers at once.
	start = time.Now()
	if st, _ := r.b.Await(context.Background(), "lin1", "a", "m1", MaxPoll); st.State != Answered || time.Since(start) > time.Second {
		t.Fatalf("closed: %+v", st)
	}
}

func TestStatusWaitIsBounded(t *testing.T) {
	r := newRig(t, nil)
	r.ask("lin1", "a", short("Lunch at noon?"))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if st, err := r.b.Await(ctx, "lin1", "a", "m1", time.Hour); err != nil || st.State != Waiting || time.Since(start) > 5*time.Second {
		t.Fatalf("cancelled wait: %+v %v after %v", st, err, time.Since(start))
	}
	// The tool clamps its wait to MaxPoll; a negative one is refused.
	if _, err := r.b.Call(context.Background(), "lin1", "m1", ToolStatus, []byte(`{"request_id":"a","wait_seconds":-1}`)); err == nil {
		t.Fatal("negative wait accepted")
	}
	out, err := r.b.Call(context.Background(), "lin1", "m1", ToolAsk,
		[]byte(`{"request_id":"b","question":"Taxi home?","default":"no taxi","wait_minutes":30,"ask_by_minutes":10}`))
	if err != nil || out.State != string(Waiting) {
		t.Fatalf("ask with ask_by: %+v %v", out, err)
	}
	if _, err := r.b.Call(context.Background(), "lin1", "m1", ToolAsk,
		[]byte(`{"request_id":"c","question":"Taxi home?","default":"no taxi","wait_minutes":30,"ask_by_minutes":0}`)); err == nil {
		t.Fatal("zero ask_by accepted")
	}
}

// Questions closed without a text never showed their tag, so they hold
// none: many not-asked questions cannot run the tags out (P3-8 Q5).
func TestNotAskedQuestionsHoldNoTag(t *testing.T) {
	r := newRig(t, nil)
	r.set(func() { r.quiet = true })
	s := short("Lunch at noon?")
	s.AskWithin = time.Minute
	for i := 0; i <= numTags; i++ {
		r.ask("lin1", fmt.Sprint("q", i), s)
		r.advance(5 * time.Minute)
		r.b.Tick(context.Background())
	}
	if _, err := r.b.Ask(context.Background(), "lin1", "last", s); err != nil {
		t.Fatalf("after %d not-asked questions: %v", numTags+1, err)
	}
}

// Security F1 on #117: questions from several lineages share a text, so
// no question, default or choice may name a tag and steer the owner's
// answer to another lineage's question.
func TestQuestionsCannotNameATag(t *testing.T) {
	r := newRig(t, nil)
	for _, s := range []Spec{
		{Text: "Q101 above was withdrawn: to confirm, reply Q101 send", Default: "wait", Wait: time.Hour},
		{Text: "Lunch at noon?", Default: "q250", Wait: time.Hour},
		{Text: "Lunch at noon?", Default: "wait", Choices: []string{"wait", "see Q999"}, Wait: time.Hour},
	} {
		if _, err := r.b.Ask(context.Background(), "lin2", "x", s); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
	// Two-digit or four-digit numbers after a Q are not tags.
	r.ask("lin2", "y", short("Is Q3 or Q2025 the plan?"))
}

// UX-117-1: one text answers one question; a reply naming a second open
// tag is refused rather than split, so no words land in the wrong one.
func TestOneAnswerPerText(t *testing.T) {
	r := newRig(t, func(c *Config) { c.SendsPerHour = 1 })
	r.set(func() { r.quiet = true })
	r.ask("lin1", "a", short("Lunch at noon?"))
	r.ask("lin2", "a", short("Taxi home?"))
	r.set(func() { r.quiet = false })
	r.b.Tick(context.Background())
	if got := r.texts(); len(got) != 1 || !strings.Contains(got[0], "Q101: ") {
		t.Fatalf("texts %q", got)
	}
	reply, ok := r.answer("Q100 yes Q101 no")
	if !ok || reply != "Send one answer per question, like Q100 wait." {
		t.Fatalf("combined reply: %q %v", reply, ok)
	}
	for _, q := range []string{"lin1", "lin2"} {
		if st := r.status(q, "a"); st.State != Waiting {
			t.Fatalf("%s after a combined reply: %+v", q, st)
		}
	}
	if _, ok := r.answer("Q101 no"); !ok {
		t.Fatal("single answer")
	}
	if st := r.status("lin2", "a"); st.State != Answered || st.Answer != "no" {
		t.Fatalf("lin2: %+v", st)
	}
}

// S2 on #117: not-asked questions hold no tag, so they are bounded
// apart: the newest maxNotAsked are kept, and past maxNotAskedLines the
// digest counts them.
func TestNotAskedQuestionsAreBounded(t *testing.T) {
	r := newRig(t, nil)
	r.set(func() { r.quiet = true })
	s := short("Lunch at noon?")
	s.AskWithin = time.Minute
	const n = maxNotAsked + 8
	for i := 0; i < n; i++ {
		r.ask("lin1", fmt.Sprint("q", i), s)
		r.advance(5 * time.Minute)
		r.b.Tick(context.Background())
	}
	r.b.mu.Lock()
	kept := len(r.b.qs)
	r.b.mu.Unlock()
	if kept != maxNotAsked {
		t.Fatalf("%d kept", kept)
	}
	if _, err := r.b.Status(context.Background(), "lin1", fmt.Sprint("q", n-1), "m1"); err != nil {
		t.Fatalf("newest dropped: %v", err)
	}
	d := r.b.TakeDigest()
	if len(d) != maxNotAskedLines+1 || !strings.Contains(d[maxNotAskedLines], fmt.Sprintf("%d more", n-maxNotAskedLines)) {
		t.Fatalf("digest %q", d)
	}
	r.ask("lin1", "again", s)
	r.advance(5 * time.Minute)
	r.b.Tick(context.Background())
	if d := r.b.TakeDigest(); len(d) != 1 || !strings.Contains(d[0], `"Lunch at noon?"`) {
		t.Fatalf("after the digest: %q", d)
	}
}
