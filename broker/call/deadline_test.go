package call_test

// REQ: CH-5

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/call"
)

// clock is a moving test clock: After fires once Advance has moved now to
// or past its deadline, and at once if the deadline has already passed.
type clock struct {
	mu     sync.Mutex
	now    time.Time
	timers []timer
}

type timer struct {
	at time.Time
	c  chan time.Time
}

func newClock() *clock { return &clock{now: time.Unix(1_800_000_000, 0)} }

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *clock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := timer{c.now.Add(d), make(chan time.Time, 1)}
	if !t.at.After(c.now) {
		t.c <- c.now
		return t.c
	}
	c.timers = append(c.timers, t)
	return t.c
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.timers[:0]
	for _, t := range c.timers {
		if t.at.After(c.now) {
			kept = append(kept, t)
		} else {
			t.c <- c.now
		}
	}
	c.timers = kept
}

// The turn's one clip deadline, the end of the owner's speech plus
// OneMomentAfter, covers every wait before the first audio: the speed-dial
// token still being read, the answerer and the synthesizer, alone and in
// sequence, on a speed-dial call and on one dialled by hand. The clip plays
// at the deadline exactly, never before, once, and the answer follows at
// the call's rung (rule 5; UX on #4944).
func TestOneClipDeadlineCoversEveryWait(t *testing.T) {
	for _, c := range []struct {
		name string
		// keys are the token's keys and when they arrive, after the owner
		// spoke; none means a call dialled by hand.
		keys string
		at   time.Duration
		// slow is the part still working when the deadline falls.
		slow string
		// ago is how long before the transcript arrived the owner stopped.
		ago  time.Duration
		want call.Rung
	}{
		{"speed dial, keys after the deadline", "4071#", 2500 * time.Millisecond, "", 0, call.P2},
		{"hand dialled, the window ends", "", 0, "", 0, call.P0},
		{"keys in time, slow answerer", "4071#", 300 * time.Millisecond, "answerer", 0, call.P2},
		{"keys in time, slow synthesizer", "4071#", 300 * time.Millisecond, "synthesizer", 0, call.P2},
		{"no token, slow answerer", "-", 0, "answerer", 0, call.P2},
		{"no token, slow synthesizer", "-", 0, "synthesizer", 0, call.P2},
		{"speed dial, speech ended before it arrived", "4071#", 2500 * time.Millisecond, "", 900 * time.Millisecond, call.P2},
	} {
		clk := newClock()
		release := make(chan struct{})
		r := newRig(t, fixed("Here it is."))
		inner := r.ans
		r.cfg.Now, r.cfg.After = clk.Now, clk.After
		r.cfg.Answerer = answerFunc(func(ctx context.Context, a call.Ask) (<-chan string, error) {
			if c.slow == "answerer" {
				<-release
			}
			return inner.Answer(ctx, a)
		})
		r.cfg.Synthesizer = synthFunc(func(_ context.Context, s string) ([]byte, error) {
			if c.slow == "synthesizer" {
				<-release
			}
			return []byte("S:" + s), nil
		})
		var turns []call.Turn
		var mu sync.Mutex
		r.cfg.Done = func(tu call.Turn) { mu.Lock(); turns = append(turns, tu); mu.Unlock() }
		r.l.keys = make(chan byte)
		if c.keys == "-" {
			r.run(call.P2)
		} else {
			r.cfg.Token = func(k string) bool { return k == "4071" }
			r.serve()
		}
		<-r.rec.ctx
		end := clk.Now().Add(-c.ago)
		r.rec.out <- call.Heard{Text: "what's in my mail", Final: true, End: end}
		due := time.Second - c.ago
		if c.keys != "-" && c.keys != "" && c.at < due {
			clk.Advance(c.at)
			for _, k := range []byte(c.keys) {
				r.l.keys <- k
			}
			due -= c.at
		}
		clk.Advance(due - time.Millisecond)
		r.quiet() // nothing before the deadline
		clk.Advance(time.Millisecond)
		if got := r.next(); got != "CLIP:moment" {
			t.Fatalf("%s: first audio %q, want the clip at the deadline", c.name, got)
		}
		if c.keys != "-" && c.keys != "" && c.at >= time.Second-c.ago {
			clk.Advance(c.at - (time.Second - c.ago))
			for _, k := range []byte(c.keys) {
				r.l.keys <- k
			}
		}
		if c.keys == "" {
			clk.Advance(6 * time.Second) // the token window ends: P0
		}
		clk.Advance(200 * time.Millisecond)
		close(release)
		if got := r.next(); got != "S:Here it is." {
			t.Fatalf("%s: then %q", c.name, got)
		}
		clk.Advance(time.Minute)
		r.quiet() // the clip plays once
		rep := r.hangup()
		if rep.Rung != c.want || len(r.ans.asks) != 1 || r.ans.asks[0].Rung != c.want {
			t.Fatalf("%s: rung %v, asks %+v", c.name, rep.Rung, r.ans.asks)
		}
		mu.Lock()
		if len(turns) != 1 || turns[0].FirstAudio != time.Second || turns[0].FirstContent <= time.Second {
			t.Fatalf("%s: turns %+v", c.name, turns)
		}
		mu.Unlock()
	}
}

// Speech while the token is read, then talking over the clip, then the
// rest of the question: the first words are not lost, the answerer is
// asked once with all of them, and the new turn has its own deadline.
func TestTokenWaitTurnCarriesAcrossBargeIn(t *testing.T) {
	clk := newClock()
	r := newRig(t, fixed("Here it is."))
	r.cfg.Now, r.cfg.After = clk.Now, clk.After
	r.cfg.Token = func(k string) bool { return k == "4071" }
	r.l.keys = make(chan byte)
	r.serve()
	<-r.rec.ctx
	r.rec.out <- call.Heard{Text: "what's in", Final: true, End: clk.Now()}
	clk.Advance(time.Second)
	if got := r.next(); got != "CLIP:moment" {
		t.Fatalf("first audio %q", got)
	}
	r.rec.out <- call.Heard{Text: "my"}                                   // barge-in
	r.rec.out <- call.Heard{Text: "my mail", Final: true, End: clk.Now()} // a new turn
	clk.Advance(999 * time.Millisecond)
	r.quiet()
	clk.Advance(time.Millisecond)
	if got := r.next(); got != "CLIP:moment" {
		t.Fatalf("second turn: %q", got)
	}
	for _, k := range []byte("4071#") {
		r.l.keys <- k
	}
	if got := r.next(); got != "S:Here it is." {
		t.Fatalf("then %q", got)
	}
	r.hangup()
	if len(r.ans.asks) != 1 || r.ans.asks[0].Text != "what's in my mail" || r.ans.asks[0].Rung != call.P2 {
		t.Fatalf("asks %+v", r.ans.asks)
	}
}

// Words carried into a turn are asked once: the next turn asks only its
// own words (UX/Potency on #4944).
func TestCarryIsAskedOnce(t *testing.T) {
	clk := newClock()
	r := newRig(t, fixed("Here it is."))
	r.cfg.Now, r.cfg.After = clk.Now, clk.After
	r.cfg.Token = func(k string) bool { return k == "4071" }
	r.l.keys = make(chan byte)
	r.serve()
	<-r.rec.ctx
	r.rec.out <- call.Heard{Text: "what's in", Final: true, End: clk.Now()}
	r.rec.out <- call.Heard{Text: "my"}
	r.rec.out <- call.Heard{Text: "my mail", Final: true, End: clk.Now()}
	for _, k := range []byte("4071#") {
		r.l.keys <- k
	}
	if got := r.next(); got != "S:Here it is." {
		t.Fatalf("first answer %q", got)
	}
	r.rec.out <- call.Heard{Text: "who called", Final: true, End: clk.Now()}
	if got := r.next(); got != "S:Here it is." {
		t.Fatalf("second answer %q", got)
	}
	r.hangup()
	if len(r.ans.asks) != 2 || r.ans.asks[1].Text != "who called" {
		t.Fatalf("asks %+v", r.ans.asks)
	}
}

// 0 drops words carried from a turn stopped before it was asked: they
// are not asked with the owner's next words (UX/Potency on #4944).
func TestZeroDropsTheCarry(t *testing.T) {
	clk := newClock()
	r := newRig(t, fixed("Here it is."))
	r.cfg.Now, r.cfg.After = clk.Now, clk.After
	r.cfg.Token = func(k string) bool { return k == "4071" }
	r.l.keys = make(chan byte)
	r.serve()
	<-r.rec.ctx
	r.rec.out <- call.Heard{Text: "what's in my mail", Final: true, End: clk.Now()}
	r.rec.out <- call.Heard{Text: "um"} // barge-in while the token is read: carried
	for _, k := range []byte("4071#0") {
		r.l.keys <- k
	}
	time.Sleep(20 * time.Millisecond)
	r.rec.out <- call.Heard{Text: "who called", Final: true, End: clk.Now()}
	if got := r.next(); got != "S:Here it is." {
		t.Fatalf("answer %q", got)
	}
	r.hangup()
	if len(r.ans.asks) != 1 || r.ans.asks[0].Text != "who called" {
		t.Fatalf("asks %+v", r.ans.asks)
	}
}

// A final transcript with no words asks nothing and plays nothing; the
// owner's next words are asked alone.
func TestEmptyFinalAsksNothing(t *testing.T) {
	r := newRig(t, fixed("Here it is."))
	r.run(call.P2)
	<-r.rec.ctx
	r.rec.out <- call.Heard{Text: "  ", Final: true}
	r.quiet()
	r.say("who called")
	if got := r.next(); got != "S:Here it is." {
		t.Fatalf("first audio %q", got)
	}
	r.hangup()
	if len(r.ans.asks) != 1 || r.ans.asks[0].Text != "who called" {
		t.Fatalf("asks %+v", r.ans.asks)
	}
}

// "Stop" after the clip, while the token is read, drops the carried words:
// nothing more plays and the answerer never sees them.
func TestStopWordDropsTheCarry(t *testing.T) {
	clk := newClock()
	r := newRig(t, fixed("Here it is."))
	r.cfg.Now, r.cfg.After = clk.Now, clk.After
	r.cfg.Token = func(k string) bool { return k == "4071" }
	r.l.keys = make(chan byte)
	r.serve()
	<-r.rec.ctx
	r.rec.out <- call.Heard{Text: "what's in my mail", Final: true, End: clk.Now()}
	clk.Advance(time.Second)
	if got := r.next(); got != "CLIP:moment" {
		t.Fatalf("first audio %q", got)
	}
	r.rec.out <- call.Heard{Text: "stop"}
	r.rec.out <- call.Heard{Text: "stop", Final: true, End: clk.Now()}
	for _, k := range []byte("4071#") {
		r.l.keys <- k
	}
	clk.Advance(time.Minute)
	r.quiet()
	r.say("who called")
	if got := r.next(); got != "S:Here it is." {
		t.Fatalf("then %q", got)
	}
	r.hangup()
	if len(r.ans.asks) != 1 || r.ans.asks[0].Text != "who called" || r.ans.asks[0].Rung != call.P2 {
		t.Fatalf("asks %+v", r.ans.asks)
	}
}
