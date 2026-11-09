package question

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// QUESTION-later (#2379, #2380, #1639).

// snapRig is a rig on a book file whose Send copies the file as it is
// when the text goes out, which is what a crash right after the send and
// before the save that books it would leave on disk.
func snapRig(t *testing.T, edit func(*Config)) (r *rig, path string, snap *[]byte) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "questions.json")
	snap = new([]byte)
	r = newRig(t, func(c *Config) {
		c.Path = path
		send := c.Send
		c.Send = func(text string) error {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("snapshot at send: %v", err)
			}
			*snap = raw
			return send(text)
		}
		if edit != nil {
			edit(c)
		}
	})
	return r, path, snap
}

// crash restarts r from snap, as a crash after the send would.
func crash(t *testing.T, r *rig, path string, snap []byte) {
	t.Helper()
	if err := os.WriteFile(path, snap, 0o600); err != nil {
		t.Fatal(err)
	}
	r.open()
}

// REQ: HLD-1, CH-15
// The box dies after a question's text went out and before the book
// saved it (#2379). After the restart the question waits under its tag
// from the time it was texted, is never texted again, and its text
// counts toward the hour.
func TestACrashAfterTheSendDoesNotTextItAgain(t *testing.T) {
	r, path, snap := snapRig(t, func(c *Config) { c.SendsPerHour = 1 })
	r.advance(time.Hour) // the monotonic clock is well past the wait at the restart
	sent := r.clock
	st := r.ask("lin1", "q", slot())
	if st.State != Waiting || len(r.texts()) != 1 {
		t.Fatalf("before the crash: %+v, texts %q", st, r.texts())
	}
	if raw, err := os.ReadFile(path); err != nil || strings.Contains(string(raw), `"sending"`) {
		t.Fatalf("the book kept the sent text's record (%v): %s", err, raw)
	}
	crash(t, r, path, *snap)
	r.advance(time.Minute)
	r.b.Tick(context.Background())
	got := r.status("lin1", "q")
	if got.State != Waiting || got.ID != st.ID || !got.Deadline.Equal(sent.Add(30*time.Minute)) {
		t.Fatalf("after the restart: %+v, want waiting under %s until %v", got, st.ID, sent.Add(30*time.Minute))
	}
	// Its wait on the monotonic clock runs from the restart too (Q15).
	r.set(func() { r.restricted = true })
	r.b.Tick(context.Background())
	if got := r.status("lin1", "q"); got.State != Waiting {
		t.Fatalf("a restricted tick a minute after the restart: %+v", got)
	}
	r.set(func() { r.restricted = false })
	if other := r.ask("lin2", "q", slot()); other.State != Held {
		t.Fatalf("the hour's one text is spent, yet lin2's question is %+v", other)
	}
	if n := len(r.texts()); n != 1 {
		t.Fatalf("texted again after the restart: %q", r.texts())
	}
	if out, _ := r.answer(st.ID + " 9:00"); !strings.Contains(out, "Got it") {
		t.Fatalf("the owner's answer under the same tag: %q", out)
	}
}

// REQ: HLD-1, CH-15
// The same crash while the clock is restricted: the restart books the
// text as sent, its wait running from the restart on the monotonic clock
// (never less than the wait, Q15), and nothing is texted again.
func TestACrashAfterARestrictedSendDoesNotTextItAgain(t *testing.T) {
	r, path, snap := snapRig(t, func(c *Config) { c.Quiet = nil })
	r.set(func() { r.restricted = true })
	r.ask("lin1", "q", slot())
	crash(t, r, path, *snap)
	r.advance(29 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "q"); st.State != Waiting {
		t.Fatalf("before its wait ran from the restart: %+v", st)
	}
	r.advance(time.Minute + time.Second)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "q"); st.State != Defaulted {
		t.Fatalf("once its wait ran from the restart: %+v", st)
	}
	if n := len(r.texts()); n != 1 {
		t.Fatalf("texted again after the restart: %q", r.texts())
	}
}

// REQ: HLD-1, CH-15
// A text the channel provably did not send (ErrNotSent) clears the
// sending record, so a crash after it leaves the question held, and the
// next tick texts it under the same tag.
func TestAnUnsentTextIsRetriedAfterACrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "questions.json")
	r := newRig(t, func(c *Config) { c.Path = path })
	r.set(func() { r.sendErr = fmt.Errorf("%w: paced", ErrNotSent) })
	st := r.ask("lin1", "q", slot())
	if st.State != Held {
		t.Fatalf("after an unsent text: %+v", st)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"sending"`) {
		t.Fatalf("the book kept the unsent text's record: %s", raw)
	}
	r.set(func() { r.sendErr = nil })
	r.open() // crash and restart
	r.b.Tick(context.Background())
	got := r.status("lin1", "q")
	if got.State != Waiting || got.ID != st.ID || len(r.texts()) != 1 {
		t.Fatalf("after the restart: %+v under %s, texts %q", got, st.ID, r.texts())
	}
}

// REQ: HLD-1, CH-15
// A book that cannot save the sending record does not send: the question
// stays held, and goes once the book can save again.
func TestATextThatCannotBeRecordedIsNotSent(t *testing.T) {
	var logs []string
	r := newRig(t, func(c *Config) {
		c.Path = filepath.Join(t.TempDir(), "questions.json")
		c.Logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	})
	r.set(func() { r.quiet = true })
	r.ask("lin1", "q", slot())
	r.set(func() { r.quiet = false })
	saves := 0
	r.b.write = func([]byte) error {
		saves++
		return fmt.Errorf("disk full")
	}
	r.b.Tick(context.Background())
	if st := r.status("lin1", "q"); saves == 0 || st.State != Held || len(r.texts()) != 0 {
		t.Fatalf("an unrecorded text: saves %d, %+v, texts %q", saves, st, r.texts())
	}
	if !strings.Contains(strings.Join(logs, "\n"), "question: save before send: disk full") {
		t.Fatalf("the failed save is not logged: %q", logs)
	}
	// The record that failed to save is not kept for a later save to
	// write: a crash after one still finds the question held.
	r.b.write = nil
	r.set(func() { r.quiet = true })
	r.ask("lin2", "q", slot())
	r.open()
	if st := r.status("lin1", "q"); st.State != Held {
		t.Fatalf("after a later save and a restart: %+v", st)
	}
	r.set(func() { r.quiet = false })
	r.b.Tick(context.Background())
	if st := r.status("lin1", "q"); st.State != Waiting || len(r.texts()) != 1 {
		t.Fatalf("once the book saves again: %+v, texts %q", st, r.texts()) // lin2's question shares the text
	}
}

// REQ: HLD-1, CH-15
// A book written before the sending record loads as it did.
func TestABookFromBeforeTheSendingRecordLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "questions.json")
	old := `{"next":100,"questions":[{"id":"Q100","asker":"lin1","req":"q","text":"Book the 9:00 or the 9:30 dentist slot?","default":"9:30","wait":1800000000000,"asked":"2026-10-05T13:00:00Z","state":"waiting","texted":true,"sent":"2026-10-05T13:00:00Z","deadline":"2026-10-05T13:30:00Z"}],"digest":null,"sends":[{"at":"2026-10-05T13:00:00Z","asker":"lin1"}]}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(c *Config) { c.Path = path; c.SendsPerHour = 1 })
	var f file
	if err := json.Unmarshal([]byte(old), &f); err != nil || f.Sending != nil {
		t.Fatalf("old file: %v, sending %+v", err, f.Sending)
	}
	if st := r.status("lin1", "q"); st.ID != "Q100" || st.State != Waiting || !st.Deadline.Equal(r.clock.Add(30*time.Minute)) {
		t.Fatalf("the old book's question: %+v", st)
	}
	if st := r.ask("lin2", "q", slot()); st.State != Held || st.ID == "Q100" {
		t.Fatalf("the old book's send no longer counts: %+v", st)
	}
	if len(r.texts()) != 0 {
		t.Fatalf("loading the old book texted %q", r.texts())
	}
}

// flood asks and answers the askers' questions in turn, each asker
// until one of its questions is held, and returns how many each had
// texted. Each answered question closes and keeps its tag for Keep (Q5).
func flood(t *testing.T, r *rig, seen map[string]bool, askers ...string) map[string]int {
	t.Helper()
	texted := map[string]int{}
	held := map[string]bool{}
	for i := 0; len(held) < len(askers); i++ {
		for _, a := range askers {
			if held[a] {
				continue
			}
			st := r.ask(a, fmt.Sprintf("q%d", i), slot())
			if st.State == Held {
				held[a] = true
				continue
			}
			if st.State != Waiting || seen[st.ID] {
				t.Fatalf("%s question %d: %+v (tag reused: %v)", a, i, st, seen[st.ID])
			}
			seen[st.ID] = true
			texted[a]++
			if _, ok := r.answer(st.ID + " 9:00"); !ok {
				t.Fatalf("answer %s not taken", st.ID)
			}
			r.advance(3*time.Minute + time.Second)
			r.b.Tick(context.Background())
		}
	}
	return texted
}

// REQ: CH-15, HLD-1
// A flooding lineage is held at its share of the free tags, half of the
// room the others leave, while a lineage with no kept questions still
// texts; no tag is reused within Keep (#2380, Q5).
func TestAFlooderIsHeldAtItsShareOfTheTags(t *testing.T) {
	r := tagRig(t)
	seen := map[string]bool{}
	room := numTags - r.b.cfg.MaxOpen
	n := flood(t, r, seen, "flood")["flood"]
	if n != room/2 {
		t.Fatalf("the flooder texted %d before it was held, want %d", n, room/2)
	}
	r.advance(time.Hour)
	r.b.Tick(context.Background())
	if st := r.status("flood", fmt.Sprintf("q%d", n)); st.State != Held {
		t.Fatalf("the flooder past its share: %+v", st)
	}
	if st := r.ask("other", "q", slot()); st.State != Waiting || seen[st.ID] {
		t.Fatalf("another lineage beside the flooder: %+v (tag reused: %v)", st, seen[st.ID])
	}
}

// REQ: CH-15, HLD-1
// Two lineages flood until each is held at its share, and a third
// lineage's question still goes on the next tick (#2380).
func TestTwoFloodersLeaveRoomForAThird(t *testing.T) {
	r := tagRig(t)
	seen := map[string]bool{}
	room := numTags - r.b.cfg.MaxOpen
	kept := flood(t, r, seen, "a", "b")
	if kept["a"]+kept["b"] >= room || kept["a"] > room/3+1 || kept["b"] > room/3+1 {
		t.Fatalf("two flooders kept %v of %d", kept, room)
	}
	r.advance(time.Hour)
	r.b.Tick(context.Background())
	if st := r.ask("victim", "q", slot()); st.State != Waiting || seen[st.ID] {
		t.Fatalf("the third lineage's question: %+v (tag reused: %v)", st, seen[st.ID])
	}
}

// REQ: CH-15
// Tick's check of ctx after Now (#1564, P1 on #1574): Now cancels its ctx
// and fails on the Tick's own call. That is not a restricted clock, so a
// texted question whose wait ran out on the monotonic clock is not lapsed
// on it.
func TestContextCancelledDuringTicksNowLapsesNothing(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Quiet = nil })
	r.ask("lin1", "q", slot())
	r.advance(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	now := r.cfg.Now
	r.cfg.Now = func(c context.Context) (time.Time, error) {
		if c == ctx {
			cancel()
			return time.Time{}, c.Err()
		}
		return now(c)
	}
	r.b.cfg.Now = r.cfg.Now
	r.b.Tick(ctx)
	if st := r.status("lin1", "q"); st.State != Waiting {
		t.Fatalf("lapsed on a cancelled Now: %+v", st)
	}
	r.b.Tick(context.Background())
	if st := r.status("lin1", "q"); st.State != Defaulted {
		t.Fatalf("after a live tick: %+v", st)
	}
}

// REQ: CH-15, HLD-1
// The share counts the questions already joined to the text being built
// (#2380 review): an asker one below its share has two questions due,
// and only one of them joins the text.
func TestTheShareCountsQuestionsInTheSameText(t *testing.T) {
	r := newRig(t, nil)
	room := numTags - r.b.cfg.MaxOpen
	r.b.mu.Lock()
	for i := range room/2 - 1 {
		r.b.qs = append(r.b.qs, &entry{ID: fmt.Sprintf("Q%d", firstTag+i), Asker: "f", Req: fmt.Sprintf("old%d", i),
			Text: "Lunch?", Default: "wait", Wait: 30 * time.Minute, State: Answered, Texted: true, Closed: r.clock})
	}
	r.b.next = firstTag + room/2 - 2
	r.b.mu.Unlock()
	r.set(func() { r.quiet = true })
	r.ask("f", "a", slot())
	r.ask("f", "b", slot())
	r.set(func() { r.quiet = false })
	r.b.Tick(context.Background())
	a, b := r.status("f", "a"), r.status("f", "b")
	if len(r.texts()) != 1 || a.State != Waiting || b.State != Held {
		t.Fatalf("one below its share: a %+v, b %+v, texts %q", a, b, r.texts())
	}
}

// REQ: CH-15
// A text records who asked: the first question's asker, and the askers
// of the questions that joined it, which the hour's order reads (PQ1).
func TestASharedTextRecordsItsOtherAskers(t *testing.T) {
	r := newRig(t, nil)
	r.set(func() { r.quiet = true })
	r.ask("lin1", "q", slot())
	r.ask("lin2", "q", short("Lunch at noon?"))
	r.set(func() { r.quiet = false })
	r.b.Tick(context.Background())
	r.b.mu.Lock()
	defer r.b.mu.Unlock()
	if len(r.texts()) != 1 || len(r.b.sends) != 1 || r.b.sends[0].Asker != "lin1" || fmt.Sprint(r.b.sends[0].Others) != "[lin2]" {
		t.Fatalf("texts %q, sends %+v", r.texts(), r.b.sends)
	}
}

// REQ: CH-15, CH-12
// A question joins a text that it brings to exactly MaxRendered bytes.
func TestAQuestionJoinsATextThatFitsExactly(t *testing.T) {
	r := newRig(t, nil)
	r.set(func() { r.quiet = true })
	r.ask("lin1", "q", short("Lunch at noon with "+strings.Repeat("b", 100)+"?"))
	by := "by " + r.b.clock(r.clock, r.clock.Add(30*time.Minute))
	r.b.mu.Lock()
	first := r.b.renderBy(r.b.findLocked("lin1", "q"), by)
	r.b.mu.Unlock()
	base := len(first) + 1 + len(r.b.renderBy(&entry{ID: "Q101", Text: "Tea at  four?", Default: "wait"}, by))
	text := "Tea at " + strings.Repeat("a", MaxRendered-base) + " four?"
	r.ask("lin2", "q", short(text))
	r.set(func() { r.quiet = false })
	r.b.Tick(context.Background())
	got := r.texts()
	if len(got) != 1 || len(got[0]) != MaxRendered || r.status("lin2", "q").State != Waiting {
		t.Fatalf("texts %q, want one of %d bytes", got, MaxRendered)
	}
}
