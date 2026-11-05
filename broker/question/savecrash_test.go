package question

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// REV-CHK-save-owner (#4193): the question book's save (persist) is stopped
// after every step of its file write (privfile.WriteAtomic: 0 create the
// temporary, 1 write, 2 sync, 3 close, 4 rename, 5 sync the directory), as
// a crash would. The book keeps none of the stopped change in memory and
// says so to whoever caused it; a restart then holds the old book whole
// (before the rename) or the new one whole (after it).

// stopAt is a write stop that ends the write after step.
func stopAt(step int) func(int) bool { return func(i int) bool { return i == step } }

// REQ: HLD-1, CH-15
// A guest's question whose save is stopped is refused, kept nowhere in
// memory and never texted. After a restart it is absent (stopped before
// the rename) or held whole (after it); either way the guest's retry under
// the same request ID leaves one question, texted once.
func TestAskCrashDuringTheFileWrite(t *testing.T) {
	for step := range 6 {
		path := filepath.Join(t.TempDir(), "questions.json")
		r := newRig(t, func(c *Config) { c.Path = path })
		r.b.stop = stopAt(step)
		if _, err := r.b.Ask(context.Background(), "lin1", "q", slot()); err == nil {
			t.Fatalf("step %d: a stopped ask succeeded", step)
		}
		if _, err := r.b.Status(context.Background(), "lin1", "q", "m1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("step %d: memory kept the stopped question: %v", step, err)
		}
		if got := r.texts(); len(got) != 0 {
			t.Fatalf("step %d: a stopped question was texted: %q", step, got)
		}

		r.open() // restart
		_, err := r.b.Status(context.Background(), "lin1", "q", "m1")
		switch {
		case step < 4 && !errors.Is(err, ErrNotFound):
			t.Fatalf("step %d: the question is on disk before the rename: %v", step, err)
		case step >= 4 && err != nil:
			t.Fatalf("step %d: the renamed question did not load: %v", step, err)
		}
		r.ask("lin1", "q", slot())
		r.b.Tick(context.Background()) // a held question loaded at start is texted at the next tick
		if st := r.status("lin1", "q"); st.State != Waiting {
			t.Fatalf("step %d: after the retry: %+v", step, st)
		}
		if n, got := len(r.b.qs), r.texts(); n != 1 || len(got) != 1 {
			t.Fatalf("step %d: after the retry %d questions, texts %q; want one of each", step, n, got)
		}
	}
}

// REQ: HLD-1, CH-15
// The owner's answer whose save is stopped is refused with "send it again"
// and the question stays waiting in memory, so the guest is not told an
// answer the disk may not hold. After a restart the question is waiting
// (stopped before the rename), and the resent answer lands, or answered
// whole with the owner's answer (after it).
func TestAnswerCrashDuringTheFileWrite(t *testing.T) {
	for step := range 6 {
		path := filepath.Join(t.TempDir(), "questions.json")
		r := newRig(t, func(c *Config) { c.Path = path })
		r.ask("lin1", "q", slot())
		r.b.stop = stopAt(step)
		if out, _ := r.answer("Q100 9:00"); out != "Could not save your answer. Send it again." {
			t.Fatalf("step %d: stopped answer replied %q", step, out)
		}
		if st := r.status("lin1", "q"); st.State != Waiting || st.Answer != "" {
			t.Fatalf("step %d: memory kept the stopped answer: %+v", step, st)
		}

		r.open() // restart
		st := r.status("lin1", "q")
		if step >= 4 {
			if st.State != Answered || st.Answer != "9:00" {
				t.Fatalf("step %d: the renamed answer did not load whole: %+v", step, st)
			}
			continue
		}
		if st.State != Waiting || st.Answer != "" {
			t.Fatalf("step %d: the answer is on disk before the rename: %+v", step, st)
		}
		if out, _ := r.answer("Q100 9:00"); out != `Got it: Q100 answered "9:00".` {
			t.Fatalf("step %d: the resent answer: %q", step, out)
		}
	}
}
