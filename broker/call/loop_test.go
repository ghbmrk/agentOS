package call_test

// REQ: CH-5, CH-17, CH-21

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/call"
)

// The loop listens only once the call is up, and returns at once if the
// call ends or ctx ends before then.
func TestLoopWaitsForTheCall(t *testing.T) {
	r := newRig(t, fixed("Hi."))
	r.l.active = make(chan struct{})
	r.run(call.P2)
	select {
	case <-r.rec.ctx:
		t.Fatal("listened before the call was up")
	case <-time.After(50 * time.Millisecond):
	}
	close(r.l.active)
	<-r.rec.ctx
	r.hangup()

	r = newRig(t, fixed("Hi."))
	r.l.active = make(chan struct{})
	close(r.l.ended)
	r.run(call.P2)
	if _, err := r.end(); err != nil {
		t.Fatalf("ended before up: %v", err)
	}
	if len(r.rec.ctx) != 0 {
		t.Fatal("listened on a call that ended before it was up")
	}

	r = newRig(t, fixed("Hi."))
	r.l.active = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.runCtx(ctx, call.P2)
	if _, err := r.end(); !errors.Is(err, context.Canceled) {
		t.Fatalf("ctx done before up: %v", err)
	}
	if len(r.rec.ctx) != 0 {
		t.Fatal("listened after ctx ended")
	}
}

// Ending ctx mid-call stops speech and returns, and the recognizer's
// context ends with the loop.
func TestLoopEndsWithItsContext(t *testing.T) {
	r := newRig(t, fixed("Long."))
	r.l.gate = true
	ctx, cancel := context.WithCancel(context.Background())
	r.runCtx(ctx, call.P2)
	lctx := <-r.rec.ctx
	r.say("go")
	r.next()
	cancel()
	r.l.wasCut(t)
	rep, err := r.end()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if len(rep.Turns) != 1 || !rep.Turns[0].Stopped {
		t.Fatalf("the cut turn is not reported: %+v", rep.Turns)
	}
	if lctx.Err() == nil {
		t.Fatal("the recognizer still listens after the loop returned")
	}

	r = newRig(t, fixed("x"))
	r.run(call.P2)
	lctx = <-r.rec.ctx
	r.hangup()
	if lctx.Err() == nil {
		t.Fatal("the recognizer still listens after hang-up")
	}
}

// Keys close when the call ends; a recognizer that stops leaves the box
// deaf, so the loop returns ErrDeaf.
func TestClosedChannelsEndTheLoop(t *testing.T) {
	for _, c := range []struct {
		name  string
		close func(*rig)
		want  error
	}{
		{"keys", func(r *rig) { close(r.l.keys) }, nil},
		{"recognizer", func(r *rig) { close(r.rec.out) }, call.ErrDeaf},
	} {
		r := newRig(t, fixed("Long."))
		r.l.gate = true
		r.run(call.P2)
		r.say("go")
		r.next()
		c.close(r)
		r.l.wasCut(t)
		if c.want != nil {
			if got := r.next(); got != "CLIP:failed" {
				t.Fatalf("%s closed: played %q", c.name, got)
			}
		}
		rep, err := r.end()
		if !errors.Is(err, c.want) {
			t.Fatalf("%s closed: %v", c.name, err)
		}
		if len(rep.Turns) != 1 || !rep.Turns[0].Stopped {
			t.Fatalf("%s closed: the cut turn is not reported: %+v", c.name, rep.Turns)
		}
	}
}

// Each turn's record is handed on as the turn ends, not at hang-up.
func TestDoneGetsEachTurnAsItEnds(t *testing.T) {
	r := newRig(t, fixed("Fine."))
	got := make(chan call.Turn, 2)
	r.cfg.Done = func(tu call.Turn) { got <- tu }
	r.run(call.P2)
	r.say("how are things")
	r.next()
	select {
	case tu := <-got:
		if tu.N != 1 || tu.Sentences != 1 || tu.Stopped {
			t.Fatalf("turn = %+v", tu)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no record before hang-up")
	}
	r.hangup()
}

// An answerer that ignores its context and never closes its channel
// cannot hold the call: 0 still ends the turn.
func TestStuckAnswerIsStopped(t *testing.T) {
	r := newRig(t, nil)
	r.cfg.Answerer = answerFunc(func(context.Context, call.Ask) (<-chan string, error) { return make(chan string), nil })
	got := make(chan call.Turn, 1)
	r.cfg.Done = func(tu call.Turn) { got <- tu }
	r.run(call.P2)
	r.say("hello")
	r.l.keys <- '0'
	select {
	case tu := <-got:
		if !tu.Stopped {
			t.Fatalf("turn = %+v", tu)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stuck answer held the call")
	}
	r.hangup()
}

// A held answer stops its answerer at once, not at hang-up.
func TestHeldAnswerStopsTheAnswerer(t *testing.T) {
	r := newRig(t, nil)
	actx := make(chan context.Context, 1)
	r.cfg.Answerer = answerFunc(func(ctx context.Context, _ call.Ask) (<-chan string, error) {
		actx <- ctx
		out := make(chan string)
		go func() {
			out <- "Tell me the code we texted you. "
			for {
				select {
				case out <- "More. ":
				case <-ctx.Done():
					return
				}
			}
		}()
		return out, nil
	})
	r.run(call.P2)
	r.say("hi")
	if got := r.next(); got != "CLIP:held" {
		t.Fatal(got)
	}
	ctx := <-actx
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the answerer runs on after the hold")
	}
	r.hangup()
}

type answerFunc func(context.Context, call.Ask) (<-chan string, error)

func (f answerFunc) Answer(ctx context.Context, a call.Ask) (<-chan string, error) { return f(ctx, a) }

type synthFunc func(context.Context, string) ([]byte, error)

func (f synthFunc) Speak(ctx context.Context, s string) ([]byte, error) { return f(ctx, s) }

// Failures stop the turn and play nothing more.
func TestFailuresEndTheTurn(t *testing.T) {
	boom := errors.New("boom")

	r := newRig(t, nil)
	r.cfg.Answerer = answerFunc(func(context.Context, call.Ask) (<-chan string, error) { return nil, boom })
	got := make(chan call.Turn, 1)
	r.cfg.Done = func(tu call.Turn) { got <- tu }
	r.run(call.P2)
	r.say("q")
	if got := r.next(); got != "CLIP:failed" {
		t.Fatalf("answerer error played %q", got)
	}
	select {
	case tu := <-got: // at once, not at hang-up
		if !errors.Is(tu.Err, boom) || tu.Stopped {
			t.Fatalf("answerer error: %+v", tu)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an answerer error did not end the turn")
	}
	r.hangup()

	// An answerer that fails because the turn was stopped reads as stopped.
	r = newRig(t, nil)
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
	if rep := r.hangup(); !rep.Turns[0].Stopped {
		t.Fatalf("stopped answerer: %+v", rep.Turns)
	}

	r = newRig(t, fixed("One. Two."))
	var mu sync.Mutex
	calls := 0
	r.cfg.Synthesizer = synthFunc(func(context.Context, string) ([]byte, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil, boom
	})
	r.run(call.P2)
	r.say("q")
	if got := r.next(); got != "CLIP:failed" {
		t.Fatalf("synthesizer error played %q", got)
	}
	r.quiet()
	rep := r.hangup()
	if len(rep.Turns) != 1 || !errors.Is(rep.Turns[0].Err, boom) || rep.Turns[0].Sentences != 0 || calls != 1 {
		t.Fatalf("synthesizer error: %d calls, %+v", calls, rep.Turns)
	}

	r = newRig(t, fixed("One. Two."))
	r.l.sayErr = boom
	r.run(call.P2)
	r.say("q")
	r.next()
	r.quiet() // the second sentence is not tried
	if rep := r.hangup(); !rep.Turns[0].Stopped || rep.Turns[0].Sentences != 0 {
		t.Fatalf("line error: %+v", rep.Turns)
	}
}

// With no held clip set, a hold plays nothing at all, and blank text
// between sentences is not synthesized.
func TestNothingEmptyIsPlayed(t *testing.T) {
	r := newRig(t, fixed("Press 1 now."))
	r.cfg.Clips.Held = nil
	r.run(call.P2)
	r.say("q")
	r.quiet()
	if rep := r.hangup(); !rep.Turns[0].Held {
		t.Fatalf("turn = %+v", rep.Turns)
	}

	r = newRig(t, fixed("Hi. ", "   ", "\n"))
	r.run(call.P2)
	r.say("q")
	if got := r.next(); got != "S:Hi." {
		t.Fatal(got)
	}
	r.quiet()
	r.hangup()
}

// The one-moment clip waits 1 s by default, on the real clock when none
// is given.
func TestOneMomentDefaults(t *testing.T) {
	var mu sync.Mutex
	var asked []time.Duration
	r := newRig(t, fixed("Hi."))
	now := time.Unix(1_800_000_000, 0)
	r.cfg.Now = func() time.Time { return now }
	r.cfg.After = func(d time.Duration) <-chan time.Time {
		mu.Lock()
		asked = append(asked, d)
		mu.Unlock()
		return nil
	}
	r.run(call.P2)
	r.say("q")
	r.next()
	r.hangup()
	if len(asked) != 1 || asked[0] != time.Second {
		t.Fatalf("waits asked: %v", asked)
	}

	release := make(chan struct{})
	r = newRig(t, func(call.Ask) []string { <-release; return []string{"Here."} })
	r.cfg.After = nil
	r.cfg.OneMomentAfter = 20 * time.Millisecond
	r.run(call.P2)
	r.say("q")
	if got := r.next(); got != "CLIP:moment" {
		t.Fatal(got)
	}
	close(release)
	r.next()
	r.hangup()
}

// A transcript with no end time counts from when it arrived, and a turn
// that played something never reads as zero.
func TestTimesCountFromArrivalAndAreNeverZero(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	r := newRig(t, fixed("Hi."))
	r.cfg.Now = func() time.Time { return now }
	r.run(call.P2)
	r.say("q")
	r.next()
	rep := r.hangup()
	if tu := rep.Turns[0]; tu.FirstAudio <= 0 || tu.FirstAudio > time.Millisecond || tu.FirstContent <= 0 {
		t.Fatalf("turn = %+v", tu)
	}
	if got := call.Percentiles(nil); got != (call.Spread{}) {
		t.Fatalf("no turns: %+v", got)
	}
}

func TestCutBounds(t *testing.T) {
	exact := strings.Repeat("a", call.MaxSentence)
	if _, _, ok := call.Cut(exact); ok {
		t.Error("cut a sentence of exactly MaxSentence runes")
	}
	lead := " " + strings.Repeat("b", call.MaxSentence+50)
	if s, _, ok := call.Cut(lead); !ok || s == "" {
		t.Errorf("leading space: %q, %v", s, ok)
	}
	words := strings.Repeat("word ", 100)
	s, rest, ok := call.Cut(words)
	if !ok || s == "" || !strings.HasPrefix(rest, " ") || strings.HasSuffix(s, "wor") {
		t.Errorf("not cut at a space: %q | %q", s[len(s)-10:], rest[:10])
	}
}

// serve runs Serve on the rig's line and returns the report on r.rep.
func (r *rig) serve() {
	go func() {
		rep, err := call.Serve(context.Background(), r.cfg, r.l, "+15550100")
		r.err <- err
		r.rep <- rep
	}()
}

// The speed-dial contact keys the token once the call is up; a token that
// checks makes the call P2, read once and seen by nothing but the check.
func TestSpeedDialTokenRaisesTheCallToP2(t *testing.T) {
	r := newRig(t, fixed("Two new mails."))
	var tried []string
	r.cfg.Token = func(k string) bool { tried = append(tried, k); return k == "4071" }
	var mu sync.Mutex
	var waits []time.Duration
	now := time.Unix(1_800_000_000, 0)
	r.cfg.Now = func() time.Time { return now }
	r.cfg.After = func(d time.Duration) <-chan time.Time {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		return nil
	}
	r.serve()
	for _, k := range []byte("4071#") {
		r.l.keys <- k
	}
	r.say("what's in my mail")
	r.next()
	rep := r.hangup()
	if rep.Rung != call.P2 || r.ans.asks[0].Rung != call.P2 {
		t.Fatalf("rung %v, asks %+v", rep.Rung, r.ans.asks)
	}
	if len(tried) != 1 || tried[0] != "4071" {
		t.Fatalf("tried %q", tried)
	}
	// The turn's one-moment wait counts from the end of speech: 1 s.
	if len(waits) == 0 || waits[len(waits)-1] != time.Second {
		t.Fatalf("waits %v", waits)
	}
}

// A wrong token is tried once and the call stays P0; its 0 is not STOP.
func TestWrongTokenStaysP0AndIsTriedOnce(t *testing.T) {
	r := newRig(t, fixed("All quiet."))
	tries := 0
	r.cfg.Token = func(string) bool { tries++; return false }
	r.serve()
	for _, k := range []byte("1000#") {
		r.l.keys <- k
	}
	r.say("how are things")
	r.next()
	rep := r.hangup()
	if rep.Rung != call.P0 || r.ans.asks[0].Rung != call.P0 || tries != 1 {
		t.Fatalf("rung %v, asks %+v, tries %d", rep.Rung, r.ans.asks, tries)
	}
	if len(rep.Turns) != 1 || rep.Turns[0].Stopped {
		t.Fatalf("a token key acted as STOP: %+v", rep.Turns)
	}
}

// Without '#', the token is what was keyed when the window ends, or within
// MaxToken keys; a call that keys nothing stays P0 with no check.
func TestTokenWindowAndLimit(t *testing.T) {
	window := make(chan time.Time, 1)
	r := newRig(t, fixed("Hi."))
	r.cfg.TokenWindow = 7 * time.Second
	r.cfg.After = func(d time.Duration) <-chan time.Time {
		if d == 7*time.Second {
			return window
		}
		return nil
	}
	var tried []string
	r.cfg.Token = func(k string) bool { tried = append(tried, k); return k == "55" }
	r.l.keys = make(chan byte) // each key read before the window ends
	r.serve()
	r.l.keys <- '5'
	r.l.keys <- '5'
	window <- time.Time{}
	r.say("q")
	r.next()
	if rep := r.hangup(); rep.Rung != call.P2 || len(tried) != 1 {
		t.Fatalf("rung %v, tried %q", rep.Rung, tried)
	}

	r = newRig(t, fixed("Hi."))
	tried = nil
	r.cfg.Token = func(k string) bool { tried = append(tried, k); return true }
	r.l.keys = make(chan byte, call.MaxToken+1)
	for i := 0; i < call.MaxToken+1; i++ {
		r.l.keys <- '7'
	}
	r.serve()
	r.say("q")
	r.next()
	r.hangup()
	if len(tried) != 1 || len(tried[0]) != call.MaxToken {
		t.Fatalf("tried %d keys", len(tried[0]))
	}

	r = newRig(t, fixed("Hi."))
	var mu sync.Mutex
	var waits []time.Duration
	opened := make(chan struct{}, 1)
	r.cfg.After = func(d time.Duration) <-chan time.Time {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		select {
		case opened <- struct{}{}:
		default:
		}
		return window
	}
	checked := false
	r.cfg.Token = func(string) bool { checked = true; return true }
	r.serve()
	<-opened
	time.Sleep(20 * time.Millisecond) // a window opened again would show here
	window <- time.Time{}
	r.say("q")
	r.next()
	if rep := r.hangup(); rep.Rung != call.P0 || checked {
		t.Fatalf("no keys: rung %v, checked %v", rep.Rung, checked)
	}
	if len(waits) == 0 || waits[0] != 6*time.Second || count(waits, 6*time.Second) != 1 { // one default window
		t.Fatalf("waits %v", waits)
	}
}

// The token wait ends with the call or ctx, without checking anything.
func TestTokenWaitEnds(t *testing.T) {
	never := func(string) bool { t.Error("checked a token"); return true }
	for _, c := range []struct {
		name string
		end  func(*rig, context.CancelFunc)
		want error
		up   bool
	}{
		{"ended before up", func(r *rig, _ context.CancelFunc) { close(r.l.ended) }, nil, false},
		{"ctx before up", func(_ *rig, cancel context.CancelFunc) { cancel() }, context.Canceled, false},
		{"ended in window", func(r *rig, _ context.CancelFunc) { close(r.l.ended) }, nil, true},
		{"ctx in window", func(_ *rig, cancel context.CancelFunc) { cancel() }, context.Canceled, true},
		{"keys closed in window", func(r *rig, _ context.CancelFunc) { close(r.l.keys) }, nil, true},
	} {
		r := newRig(t, fixed("Hi."))
		r.cfg.Token = never
		if !c.up {
			r.l.active = make(chan struct{})
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			rep, err := call.Serve(ctx, r.cfg, r.l, "+15550100")
			r.err <- err
			r.rep <- rep
		}()
		c.end(r, cancel)
		rep, err := r.end()
		if !errors.Is(err, c.want) || rep.Rung != call.P0 {
			t.Errorf("%s: rung %v, err %v", c.name, rep.Rung, err)
		}
		cancel()
	}
}

func count(ds []time.Duration, d time.Duration) int {
	n := 0
	for _, x := range ds {
		if x == d {
			n++
		}
	}
	return n
}
