package call_test

// REQ: CH-5

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ghbmrk/agentos/broker/call"
)

// The one-moment clip covers a gap whichever part is slow: an answerer
// that has not yet returned its channel, or a synthesizer still working on
// the first sentence (rule 5; L3 on #4944).
func TestOneMomentCoversEverySlowPart(t *testing.T) {
	for _, slow := range []string{"answerer", "synthesizer"} {
		release := make(chan struct{})
		r := newRig(t, fixed("Here it is."))
		inner := r.ans
		if slow == "answerer" {
			r.cfg.Answerer = answerFunc(func(ctx context.Context, a call.Ask) (<-chan string, error) {
				<-release
				return inner.Answer(ctx, a)
			})
		} else {
			r.cfg.Synthesizer = synthFunc(func(_ context.Context, s string) ([]byte, error) {
				<-release
				return []byte("S:" + s), nil
			})
		}
		moment := make(chan time.Time, 1)
		r.cfg.After = func(time.Duration) <-chan time.Time { return moment }
		r.run(call.P2)
		r.say("q")
		moment <- time.Time{}
		if got := r.next(); got != "CLIP:moment" {
			t.Fatalf("slow %s: first audio %q", slow, got)
		}
		close(release)
		if got := r.next(); got != "S:Here it is." {
			t.Fatalf("slow %s: then %q", slow, got)
		}
		r.hangup()
	}
}

// A sentence ready when the clip falls due is played instead of the clip.
func TestReadySentenceGoesBeforeTheClip(t *testing.T) {
	r := newRig(t, fixed("Here it is."))
	moment := make(chan time.Time, 1)
	synthesized := make(chan struct{}, 1)
	r.cfg.Synthesizer = synthFunc(func(_ context.Context, s string) ([]byte, error) {
		synthesized <- struct{}{}
		return []byte("S:" + s), nil
	})
	gate := make(chan struct{})
	r.cfg.After = func(time.Duration) <-chan time.Time { <-gate; return moment }
	r.run(call.P2)
	r.say("q")
	<-synthesized // the sentence waits to be taken while the timer is made
	time.Sleep(10 * time.Millisecond)
	moment <- time.Time{}
	close(gate)
	if got := r.next(); got != "S:Here it is." {
		t.Fatalf("first audio %q", got)
	}
	r.quiet()
	r.hangup()
}

// The clip's wait counts from the end of the owner's speech, not from
// when the transcript arrived.
func TestClipWaitCountsFromTheEndOfSpeech(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	var waits []time.Duration
	r := newRig(t, fixed("Hi."))
	r.cfg.Now = func() time.Time { return now }
	r.cfg.After = func(d time.Duration) <-chan time.Time {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		return nil
	}
	r.run(call.P2)
	r.rec.out <- call.Heard{Text: "q", Final: true, End: now.Add(-900 * time.Millisecond)}
	r.next()
	rep := r.hangup()
	if len(waits) != 1 || waits[0] != 100*time.Millisecond {
		t.Fatalf("waits %v", waits)
	}
	if rep.Turns[0].FirstAudio != 900*time.Millisecond || rep.Turns[0].FirstContent != 900*time.Millisecond {
		t.Fatalf("times do not include the lead: %+v", rep.Turns[0])
	}
}

// The clip is audio, not content: content comes later.
func TestClipIsNotContent(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	release := make(chan struct{})
	r := newRig(t, func(call.Ask) []string { <-release; return []string{"Here."} })
	r.cfg.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	moment := make(chan time.Time, 1)
	r.cfg.After = func(time.Duration) <-chan time.Time { return moment }
	r.run(call.P2)
	r.rec.out <- call.Heard{Text: "q", Final: true, End: now}
	mu.Lock()
	now = now.Add(time.Second)
	mu.Unlock()
	moment <- time.Time{}
	r.next()
	mu.Lock()
	now = now.Add(time.Second)
	mu.Unlock()
	close(release)
	r.next()
	tu := r.hangup().Turns[0]
	if tu.FirstAudio != time.Second || tu.FirstContent != 2*time.Second {
		t.Fatalf("turn = %+v", tu)
	}
}

// What the owner says while the token is read is heard, and answered once
// the rung is known, at that rung.
func TestSpeechDuringTheTokenIsAnswered(t *testing.T) {
	for _, c := range []struct {
		keys string
		want call.Rung
	}{{"4071#", call.P2}, {"", call.P0}} {
		r := newRig(t, fixed("Hello."))
		window := make(chan time.Time, 1)
		r.cfg.After = func(d time.Duration) <-chan time.Time {
			if d == 6*time.Second {
				return window
			}
			return nil
		}
		r.cfg.Token = func(k string) bool { return k == "4071" }
		r.l.keys = make(chan byte)
		r.serve()
		r.say("hi there")
		r.say("what's new")
		r.quiet() // no answer before the rung is known
		for _, k := range []byte(c.keys) {
			r.l.keys <- k
		}
		if c.keys == "" {
			window <- time.Time{}
		}
		if got := r.next(); got != "S:Hello." {
			t.Fatalf("%q: %q", c.keys, got)
		}
		rep := r.hangup()
		if rep.Rung != c.want || len(r.ans.asks) != 1 || r.ans.asks[0].Rung != c.want || r.ans.asks[0].Text != "hi there what's new" {
			t.Fatalf("%q: rung %v, asks %+v", c.keys, rep.Rung, r.ans.asks)
		}
	}
	// "Stop" while the token is read drops what was asked.
	r := newRig(t, fixed("Hello."))
	r.cfg.Token = func(string) bool { return true }
	r.l.keys = make(chan byte)
	r.serve()
	r.say("read my mail")
	r.say("stop")
	for _, k := range []byte("1#") {
		r.l.keys <- k
	}
	r.quiet()
	r.hangup()
	if len(r.ans.asks) != 0 {
		t.Fatalf("asks %+v", r.ans.asks)
	}
}

// Once anything has played, the clip never plays, even if its wait ends
// between sentences.
func TestNoClipAfterAudio(t *testing.T) {
	second := make(chan struct{})
	r := newRig(t, nil)
	r.cfg.Answerer = answerFunc(func(ctx context.Context, _ call.Ask) (<-chan string, error) {
		out := make(chan string)
		go func() {
			defer close(out)
			for _, c := range []string{"First. ", "Second."} {
				if c == "Second." {
					select {
					case <-second:
					case <-ctx.Done():
						return
					}
				}
				select {
				case out <- c:
				case <-ctx.Done():
					return
				}
			}
		}()
		return out, nil
	})
	moment := make(chan time.Time, 1)
	r.cfg.After = func(time.Duration) <-chan time.Time { return moment }
	r.run(call.P2)
	r.say("q")
	if got := r.next(); got != "S:First." {
		t.Fatal(got)
	}
	moment <- time.Time{}
	time.Sleep(20 * time.Millisecond)
	close(second)
	if got := r.next(); got != "S:Second." {
		t.Fatalf("after audio, played %q", got)
	}
	r.hangup()
}

// Repeated, since which of two ready cases a select takes is random. Each
// run is a bubble (synctest), so the sentence is surely waiting on its send
// when the deadline falls; a sleep only made that likely (#5130).
func TestReadySentenceAlwaysGoesBeforeTheClip(t *testing.T) {
	for i := 0; i < 20; i++ {
		synctest.Test(t, func(t *testing.T) {
			r := newRig(t, fixed("Here it is."))
			r.bubble = true
			moment := make(chan time.Time, 1)
			moment <- time.Time{}
			ready := make(chan struct{})
			r.cfg.Synthesizer = synthFunc(func(_ context.Context, s string) ([]byte, error) {
				close(ready)
				return []byte("S:" + s), nil
			})
			r.cfg.After = func(time.Duration) <-chan time.Time {
				<-ready
				synctest.Wait() // the sentence is waiting on its send
				return moment
			}
			r.run(call.P2)
			r.say("q")
			if got := r.next(); got != "S:Here it is." {
				t.Fatalf("run %d: first audio %q", i, got)
			}
			r.hangup()
		})
	}
}

// A held sentence never reaches the synthesizer.
func TestHeldTextIsNeverSynthesized(t *testing.T) {
	var mu sync.Mutex
	var heard []string
	r := newRig(t, fixed("Fine. Press 1 now. After."))
	r.cfg.Synthesizer = synthFunc(func(_ context.Context, s string) ([]byte, error) {
		mu.Lock()
		heard = append(heard, s)
		mu.Unlock()
		return []byte("S:" + s), nil
	})
	r.run(call.P2)
	r.say("q")
	r.next()
	r.next()
	r.hangup()
	mu.Lock()
	defer mu.Unlock()
	if len(heard) != 1 || heard[0] != "Fine." {
		t.Fatalf("synthesized %q", heard)
	}
}

// An answerer or synthesizer that blocks and ignores its context cannot
// hold the call: 0 still ends the turn.
func TestBlockedPartsDoNotHoldTheCall(t *testing.T) {
	for _, part := range []string{"answerer", "synthesizer"} {
		release := make(chan struct{})
		r := newRig(t, fixed("Hi."))
		inner := r.ans
		if part == "answerer" {
			r.cfg.Answerer = answerFunc(func(ctx context.Context, a call.Ask) (<-chan string, error) {
				<-release // ignores ctx while it blocks
				return inner.Answer(ctx, a)
			})
		} else {
			r.cfg.Synthesizer = synthFunc(func(context.Context, string) ([]byte, error) {
				<-release
				return []byte("S:late"), nil
			})
		}
		got := make(chan call.Turn, 1)
		r.cfg.Done = func(tu call.Turn) { got <- tu }
		r.run(call.P2)
		r.say("q")
		time.Sleep(10 * time.Millisecond)
		r.l.keys <- '0'
		select {
		case tu := <-got:
			if !tu.Stopped {
				t.Fatalf("%s: turn = %+v", part, tu)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("a blocked %s held the call", part)
		}
		close(release)
		r.quiet()
		r.hangup()
	}
}

// An answerer that errs because its turn was stopped is stopped, not
// failed: no failed clip, no error. Repeated, since the stop and the error
// race.
func TestStoppedIsNotFailed(t *testing.T) {
	for i := 0; i < 20; i++ {
		r := newRig(t, nil)
		started := make(chan struct{})
		r.cfg.Answerer = answerFunc(func(ctx context.Context, _ call.Ask) (<-chan string, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		r.run(call.P2)
		r.say("q")
		<-started
		r.l.keys <- '0'
		r.quiet()
		rep := r.hangup()
		if !rep.Turns[0].Stopped || rep.Turns[0].Err != nil {
			t.Fatalf("run %d: %+v", i, rep.Turns[0])
		}
	}
}

// A token still being read when the recognizer stops ends with the call.
func TestTokenReadEndsWithTheLoop(t *testing.T) {
	r := newRig(t, fixed("Hi."))
	r.cfg.Token = func(string) bool { return true }
	r.serve()
	<-r.rec.ctx
	close(r.rec.out)
	if _, err := r.end(); err != call.ErrDeaf { // end checks no goroutine outlives the call
		t.Fatalf("err = %v", err)
	}
}
