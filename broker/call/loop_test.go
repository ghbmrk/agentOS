package call_test

// REQ: CH-5, CH-17, CH-21

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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

// With no Failed clip set, a recognizer that stops plays nothing and the
// call still ends deaf (#5305).
func TestAnUnsetFailedClipPlaysNothing(t *testing.T) {
	r := newRig(t, fixed("Hi."))
	r.cfg.Clips.Failed = nil
	r.serve()
	<-r.rec.ctx
	close(r.rec.out)
	if _, err := r.end(); err != call.ErrDeaf { // end fails on empty audio
		t.Fatalf("err = %v", err)
	}
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
	mu.Lock()
	got := append([]time.Duration(nil), asked...)
	mu.Unlock()
	if len(got) != 1 || got[0] != time.Second {
		t.Fatalf("waits asked: %v", got)
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
	// The turn's one-moment wait counts from the end of speech: 1 s. The
	// token window (6 s) is asked for when the call is up, which can land
	// before or after the turn's wait, so the test asserts the set, not
	// the order (#5354).
	mu.Lock()
	got := append([]time.Duration(nil), waits...)
	mu.Unlock()
	if count(got, time.Second) != 1 || count(got, 6*time.Second) > 1 || len(got) != count(got, time.Second)+count(got, 6*time.Second) {
		t.Fatalf("waits %v", got)
	}
}

// A wrong token is tried once and the call stays P0; its 0 is not STOP.
// The token's keys arrive while turn 1 is live: it is heard first, waits
// for the rung while "1000" is keyed, and its sentence plays (gated) across
// the '#'. A '0' that leaked past the token reader, before or after the
// check, would stop that turn. A sentence cannot play before the rung is
// known, since the turn asks the answerer only then. A '0' keyed after the
// token does stop it, so the keys do reach the loop by then.
func TestWrongTokenStaysP0AndIsTriedOnce(t *testing.T) {
	r := newRig(t, fixed("All quiet."))
	r.l.gate = true
	tries := 0
	r.cfg.Token = func(string) bool { tries++; return false }
	ends := r.records()
	r.serve()
	r.say("how are things")
	for _, k := range []byte("1000") {
		r.l.keys <- k
	}
	select {
	case tu := <-ends:
		t.Fatalf("a token key stopped the turn waiting for the rung: %+v", tu)
	case <-time.After(50 * time.Millisecond):
	}
	r.l.keys <- '#'
	if s := r.next(); s != "S:All quiet." {
		t.Fatalf("played %q", s)
	}
	select {
	case <-r.l.cut:
		t.Fatal("a token key acted as STOP")
	case tu := <-ends:
		t.Fatalf("a token key ended the playing turn: %+v", tu)
	case <-time.After(50 * time.Millisecond):
	}
	r.l.keys <- '0'
	r.l.wasCut(t)
	rep := r.hangup()
	if rep.Rung != call.P0 || r.ans.asks[0].Rung != call.P0 || tries != 1 {
		t.Fatalf("rung %v, asks %+v, tries %d", rep.Rung, r.ans.asks, tries)
	}
	if len(rep.Turns) != 1 || !rep.Turns[0].Stopped {
		t.Fatalf("turns = %+v", rep.Turns)
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
	mu.Lock()
	got := append([]time.Duration(nil), waits...)
	mu.Unlock()
	if len(got) == 0 || got[0] != 6*time.Second || count(got, 6*time.Second) != 1 { // one default window
		t.Fatalf("waits %v", got)
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

// A token try happens while the call is live, and never after Serve
// returns: Serve ends the token read and waits for it (#5259). In the
// second part the reader holds "4071" when the call ends and is held in
// the window's clock until Serve has returned (or 20 ms, since Serve now
// waits for it); then its window and its ended ctx are both ready. A
// reader Serve did not wait for picks the window half the time and tries
// "4071" after the call; one it waited for does the same before Serve
// returns, unless check tries nothing once the call has ended (#5274).
func TestNoTokenTryFollowsTheCall(t *testing.T) {
	var mu sync.Mutex
	var tried []string
	tries := func() int { mu.Lock(); defer mu.Unlock(); return len(tried) }
	token := func(k string) bool { mu.Lock(); tried = append(tried, k); mu.Unlock(); return k == "4071" }

	// Keys pressed before an Answer that fails reach no try (#5274).
	r := newRig(t, fixed("Hi."))
	r.cfg.Token = token
	r.l.answerErr = errors.New("no carrier")
	r.l.answerWait = 50 * time.Millisecond // time for a token read to try
	for _, k := range []byte("1#") {
		r.l.keys <- k
	}
	r.serve()
	if _, err := r.end(); !errors.Is(err, r.l.answerErr) || tries() != 0 {
		t.Fatalf("a failed Answer: err %v, tried %q", err, tried)
	}
	if r.l.answerCtx.Err() == nil {
		t.Fatal("a failed Answer's call ctx outlives Serve")
	}

	r = newRig(t, fixed("Hi."))
	r.cfg.Token = token
	r.serve()
	for _, k := range []byte("4071#") {
		r.l.keys <- k
	}
	for i := 0; i < 500 && tries() == 0; i++ {
		time.Sleep(time.Millisecond)
	}
	if n := tries(); n != 1 {
		t.Fatalf("live call: %d tries before the end", n)
	}
	if rep := r.hangup(); rep.Rung != call.P2 || tries() != 1 {
		t.Fatalf("live call: rung %v, tried %q", rep.Rung, tried)
	}

	for i := range 20 {
		mu.Lock()
		tried = nil
		mu.Unlock()
		r := newRig(t, fixed("Hi."))
		r.cfg.Token = token
		r.cfg.TokenWindow = 7 * time.Second
		r.l.active = make(chan struct{})
		served, opened := make(chan struct{}), make(chan struct{})
		r.cfg.After = func(d time.Duration) <-chan time.Time {
			if d != 7*time.Second {
				return nil
			}
			close(opened)
			<-r.l.ended
			select {
			case <-served:
			case <-time.After(20 * time.Millisecond):
			}
			w := make(chan time.Time)
			close(w)
			return w
		}
		r.serve()
		for _, k := range []byte("4071") {
			r.l.keys <- k
		}
		for j := 0; j < 500 && len(r.l.keys) > 0; j++ {
			time.Sleep(time.Millisecond)
		}
		close(r.l.active)
		<-opened
		close(r.l.ended)
		select {
		case <-r.err:
			<-r.rep
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not return")
		}
		before := tries()
		if before != 0 {
			t.Fatalf("call %d: %d token tries once the call had ended", i, before)
		}
		close(served)
		r.settle()
		if n := tries(); n != before {
			t.Fatalf("call %d: %d token tries after Serve returned", i, n-before)
		}
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

// An answerer that errs is done, even if it also returned a channel: no
// sentence of that channel is synthesized. Line's Say waits for the test
// to take the failed clip, so the turn has not yet ended the producer's
// context and a producer reading on would reach the synthesizer.
func TestAnswerErrorEndsTheAnswer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		boom := errors.New("boom")
		r := newRig(t, nil)
		r.bubble = true
		r.l.saying = make(chan string)
		chunks := make(chan string, 1)
		chunks <- "One. Two."
		close(chunks)
		r.cfg.Answerer = answerFunc(func(context.Context, call.Ask) (<-chan string, error) { return chunks, boom })
		var mu sync.Mutex
		spoken := 0
		r.cfg.Synthesizer = synthFunc(func(_ context.Context, s string) ([]byte, error) {
			mu.Lock()
			spoken++
			mu.Unlock()
			return []byte("S:" + s), nil
		})
		r.run(call.P2)
		r.say("q")
		synctest.Wait() // the turn is playing the failed clip
		mu.Lock()
		n := spoken
		mu.Unlock()
		if n != 0 {
			t.Fatalf("%d sentences synthesized after the answerer erred", n)
		}
		if got := r.next(); got != "CLIP:failed" {
			t.Fatalf("answerer error played %q", got)
		}
		rep := r.hangup()
		if len(rep.Turns) != 1 || !errors.Is(rep.Turns[0].Err, boom) || rep.Turns[0].Sentences != 0 {
			t.Fatalf("turns = %+v", rep.Turns)
		}
	})
}

// One call is served at a time (#5232 R1): an owner call that rings while
// another is served is left ringing, so a grant kept from the call being
// served, by a package var or an answerer shared by both, never answers
// another live call; once that call ends its grant reads P0 in the next.
func TestOneCallIsServedAtATime(t *testing.T) {
	a := newRig(t, fixed("Two new mails."))
	a.cfg.Token = func(k string) bool { return k == "4071" }
	a.serve()
	for _, k := range []byte("4071#") {
		a.l.keys <- k
	}
	a.say("what's in my mail")
	a.next()

	b := newRig(t, fixed("All quiet."))
	b.cfg.Answerer = a.ans // one answerer wired to both calls
	ring := make(chan time.Time)
	waited := make(chan time.Duration, 1)
	b.cfg.After = func(d time.Duration) <-chan time.Time { waited <- d; return ring }
	busy := make(chan error, 1)
	go func() { _, err := call.Serve(context.Background(), b.cfg, b.l, "+15550100"); busy <- err }()
	// It waits, ringing, for the call being served to end (#5252), and
	// is refused once the ring wait (default 10 s) has passed.
	if d := <-waited; d != 10*time.Second {
		t.Fatalf("the ring wait is %v", d)
	}
	select {
	case err := <-busy:
		t.Fatalf("refused before the ring wait passed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(ring)
	select {
	case err := <-busy:
		if !errors.Is(err, call.ErrBusy) {
			t.Fatalf("a second call while one is served: err %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a second call was served while one is")
	}
	if b.l.answered {
		t.Fatal("answered a second call while one is served")
	}
	// A waiting call whose caller gives up, or whose ctx ends, stops
	// waiting at once.
	for _, how := range []string{"hangs up", "ctx ends"} {
		c := newRig(t, fixed("x"))
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _, err := call.Serve(ctx, c.cfg, c.l, "+15550100"); busy <- err }()
		time.Sleep(20 * time.Millisecond)
		want := call.ErrBusy
		if how == "hangs up" {
			close(c.l.ended)
		} else {
			cancel()
			want = context.Canceled
		}
		select {
		case err := <-busy:
			if !errors.Is(err, want) {
				t.Fatalf("a waiting call whose %s: err %v", how, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("a waiting call whose %s kept waiting", how)
		}
		cancel()
	}
	if rep := a.hangup(); rep.Rung != call.P2 {
		t.Fatalf("the first call ran at %v", rep.Rung)
	}

	b.cfg.After = func(time.Duration) <-chan time.Time { return nil }
	b.serve()
	b.say("and now")
	b.next()
	rep := b.hangup()
	if !b.l.answered || rep.Rung != call.P0 || len(a.ans.kept) != 2 {
		t.Fatalf("the next call: answered %v, rung %v, asks %d", b.l.answered, rep.Rung, len(a.ans.kept))
	}
	for i, q := range a.ans.kept {
		if q.Rung() != call.P0 {
			t.Fatalf("ask %d kept by the shared answerer says %v once its call ended", i, q.Rung())
		}
	}
}

// An owner redial right after a dropped call is answered, not refused while
// the dropped call unwinds (#5252). Here the old call's turn is held in the
// check (Hold) as its line drops, so its Serve still holds the lock when
// the redial rings; the redial waits and is answered once it is let go.
func TestARedialAfterADropIsAnswered(t *testing.T) {
	a := newRig(t, fixed("Two new mails."))
	inHold, release := make(chan struct{}, 1), make(chan struct{})
	a.cfg.Hold = func(string) bool {
		select {
		case inHold <- struct{}{}:
			<-release
		default:
		}
		return false
	}
	a.serve()
	a.say("what's in my mail")
	<-inHold
	close(a.l.ended) // the call drops

	b := newRig(t, fixed("All quiet."))
	b.cfg.After = func(time.Duration) <-chan time.Time { return nil } // the redial keeps ringing
	b.serve()
	select {
	case err := <-b.err:
		t.Fatalf("the redial was refused while the dropped call unwound: %v", err)
	case <-a.err:
		t.Fatal("the dropped call returned before its turn's producer ended")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-a.err; err != nil { // not a.end: b's call is up
		t.Fatalf("the dropped call: %v", err)
	}
	b.say("and now")
	if got := b.next(); got != "S:All quiet." {
		t.Fatalf("the redial played %q", got)
	}
	b.hangup()
}

// A call whose line never reports its end, or never finishes answering, is
// ended at MaxCall (default 30 min), hung up, and the next owner call is
// answered (#5252). The hang-up runs on a live ctx bounded by HangupWait
// (5 s), though Serve's own ctx has no deadline, so a line that wedges on
// it frees the next call, and it ends with Serve's ctx (#5274).
func TestACallEndsAtMaxCall(t *testing.T) {
	if call.HangupWait != 5*time.Second {
		t.Fatalf("HangupWait is %v", call.HangupWait)
	}
	hungUp := func(r *rig) bool {
		r.l.mu.Lock()
		defer r.l.mu.Unlock()
		if r.l.hungUp && (r.l.hangErr != nil || r.l.hangLeft <= 0 || r.l.hangLeft > call.HangupWait) {
			t.Fatalf("hung up on a ctx with err %v, %v left", r.l.hangErr, r.l.hangLeft)
		}
		return r.l.hungUp
	}
	r := newRig(t, fixed("Hi."))
	deadline := make(chan time.Duration, 1)
	r.cfg.Answerer = answerFunc(func(ctx context.Context, a call.Ask) (<-chan string, error) {
		d, _ := ctx.Deadline()
		deadline <- time.Until(d)
		return r.ans.Answer(ctx, a)
	})
	r.serve()
	r.say("q")
	r.next()
	if d := <-deadline; d < 29*time.Minute || d > 30*time.Minute {
		t.Fatalf("the default call length is %v", d)
	}
	if rep := r.hangup(); len(rep.Turns) != 1 {
		t.Fatalf("turns = %+v", rep.Turns)
	}

	r = newRig(t, fixed("Hi."))
	r.cfg.MaxCall = 100 * time.Millisecond
	r.l.hangStuck = true // the hang-up waits for its ctx to end
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { // the carrier never drops
		rep, err := call.Serve(ctx, r.cfg, r.l, "+15550100")
		r.err <- err
		r.rep <- rep
	}()
	r.say("q")
	r.next()
	for i := 0; i < 500 && !hungUp(r); i++ {
		time.Sleep(time.Millisecond)
	}
	if !hungUp(r) {
		t.Fatal("a call past MaxCall was not hung up")
	}
	select { // the hang-up ends with Serve's ctx, not HangupWait later
	case <-r.err:
		t.Fatal("Serve returned during the hang-up")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-r.err:
		r.err <- err
	case <-time.After(time.Second):
		t.Fatal("the hang-up outlived Serve's ctx")
	}
	if _, err := r.end(); !errors.Is(err, call.ErrTooLong) {
		t.Fatalf("a call past MaxCall: err %v", err)
	}

	// An Answer that never completes is bounded the same way (Lens on
	// #5258).
	r = newRig(t, fixed("Hi."))
	r.cfg.MaxCall = 100 * time.Millisecond
	r.l.stuck = true
	r.serve()
	if _, err := r.end(); !errors.Is(err, call.ErrTooLong) {
		t.Fatalf("an Answer past MaxCall: err %v", err)
	}
	if !hungUp(r) {
		t.Fatal("an Answer past MaxCall was not hung up")
	}
	if r.l.hangCtx.Err() == nil { // its ctx ends with the hang-up
		t.Fatal("the hang-up's ctx outlives Serve")
	}

	next := newRig(t, fixed("All quiet."))
	next.serve()
	next.say("and now")
	if got := next.next(); got != "S:All quiet." {
		t.Fatalf("the next call played %q", got)
	}
	next.hangup()
}

// A call that reaches MaxCall hears the ending clip EndingNotice before it
// is hung up, cutting the answer then playing; a call that ends sooner
// hears none; and the clip plays on the call's ctx, so a clip still playing
// at MaxCall ends with the call and Serve returns at MaxCall (#5262).
func TestTheOwnerHearsTheEndBeforeMaxCall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		played := func(r *rig) string {
			select {
			case s := <-r.l.saying:
				return s
			default:
				return ""
			}
		}
		hungUp := func(r *rig) bool {
			r.l.mu.Lock()
			defer r.l.mu.Unlock()
			return r.l.hungUp
		}

		// Reaches MaxCall (default 30 min) mid-answer.
		start := time.Now()
		r := newRig(t, fixed("Hi."))
		r.bubble = true
		r.cfg.Clips.Ending = []byte("CLIP:ending")
		r.l.setGate(true) // the answer plays until it is stopped
		r.serve()
		r.say("q")
		synctest.Wait()
		if got := played(r); got != "S:Hi." {
			t.Fatalf("the answer played %q", got)
		}
		time.Sleep(29*time.Minute - time.Nanosecond) // a minute before the end
		synctest.Wait()
		if got := played(r); got != "" {
			t.Fatalf("played %q before the notice was due", got)
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if got := played(r); got != "CLIP:ending" || hungUp(r) {
			t.Fatalf("a minute before MaxCall: played %q, hung up %v", got, hungUp(r))
		}
		r.l.wasCut(t) // the answer stopped for the notice
		time.Sleep(time.Minute)
		synctest.Wait()
		rep, err := r.end()
		if !errors.Is(err, call.ErrTooLong) || !hungUp(r) || time.Since(start) != 30*time.Minute {
			t.Fatalf("at MaxCall: err %v, hung up %v, after %v", err, hungUp(r), time.Since(start))
		}
		if len(rep.Turns) != 1 || !rep.Turns[0].Stopped {
			t.Fatalf("turns = %+v", rep.Turns)
		}
		if got := r.l.spoken(); len(got) != 1 || got[0] != "CLIP:ending" {
			t.Fatalf("played in full %q", got)
		}

		// Ends a moment before the notice is due: no notice.
		r = newRig(t, fixed("Hi."))
		r.bubble = true
		r.cfg.Clips.Ending = []byte("CLIP:ending")
		r.serve()
		r.say("q")
		synctest.Wait()
		time.Sleep(29*time.Minute - time.Nanosecond) // a minute before the end
		r.hangup()
		time.Sleep(time.Hour)
		synctest.Wait()
		if got := r.l.spoken(); len(got) != 1 || got[0] != "S:Hi." {
			t.Fatalf("a shorter call played %q", got)
		}

		// A notice still playing at MaxCall (here 10 min) ends there, so
		// it gives the call no longer life.
		start = time.Now()
		r = newRig(t, fixed("Hi."))
		r.bubble = true
		r.cfg.MaxCall = 10 * time.Minute
		r.cfg.Clips.Ending = []byte("S:ending") // held by the gate until stopped
		r.l.setGate(true)
		r.serve()
		time.Sleep(9 * time.Minute)
		synctest.Wait()
		if got := played(r); got != "S:ending" {
			t.Fatalf("a minute before MaxCall: played %q", got)
		}
		time.Sleep(time.Minute)
		synctest.Wait() // Serve has returned at MaxCall, not later
		select {
		case err := <-r.err:
			<-r.rep
			if !errors.Is(err, call.ErrTooLong) || !hungUp(r) || time.Since(start) != 10*time.Minute {
				t.Fatalf("a notice playing at MaxCall: err %v, hung up %v, after %v", err, hungUp(r), time.Since(start))
			}
		default:
			t.Fatal("a notice playing at MaxCall kept the call")
		}
		r.l.wasCut(t)
	})
}

// The ending notice leaves the call's state as it was (#5262): with no
// Ending clip set nothing is cut and nothing empty plays; a question the
// answerer has not yet seen is asked with the owner's next words; and a 0
// or a barge-in during the clip acts once the clip has played. A call
// shorter than EndingNotice hears none.
func TestTheEndingNoticeKeepsTheCallsState(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// No Ending clip: the answer playing a minute before MaxCall plays on.
		r := newRig(t, fixed("Hi."))
		r.bubble = true
		r.l.setGate(true)
		r.serve()
		r.say("q")
		synctest.Wait()
		<-r.l.saying
		time.Sleep(29 * time.Minute)
		synctest.Wait()
		select {
		case <-r.l.cut:
			t.Fatal("the answer was cut a minute before MaxCall with no Ending clip")
		default:
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if _, err := r.end(); !errors.Is(err, call.ErrTooLong) {
			t.Fatalf("no Ending clip: err %v", err)
		}

		// A question asked while the token is read, so not yet asked, is
		// carried past the notice into the owner's next words.
		r = newRig(t, fixed("Hi."))
		r.bubble = true
		r.cfg.Clips.Ending = []byte("CLIP:ending")
		r.cfg.Token = func(string) bool { return false }
		r.serve()
		r.say("what's in my mail")
		time.Sleep(29 * time.Minute)
		synctest.Wait()
		if got := <-r.l.saying; got != "CLIP:ending" {
			t.Fatalf("a minute before MaxCall: played %q", got)
		}
		r.l.keys <- '#' // the token read ends: P0
		r.say("from today")
		synctest.Wait()
		if got := <-r.l.saying; got != "S:Hi." {
			t.Fatalf("after the notice: played %q", got)
		}
		r.ans.mu.Lock()
		asks := r.ans.asks
		r.ans.mu.Unlock()
		if len(asks) != 1 || asks[0].Text != "what's in my mail from today" {
			t.Fatalf("asks = %+v", asks)
		}
		r.hangup()

		// A question the answerer already saw is not asked again after
		// the notice: only the owner's next words are (#5274).
		r = newRig(t, fixed("Hi."))
		r.bubble = true
		r.cfg.Clips.Ending = []byte("CLIP:ending")
		r.l.setGate(true) // the answer plays until it is stopped
		r.serve()
		r.say("what's in my mail")
		synctest.Wait()
		if got := <-r.l.saying; got != "S:Hi." {
			t.Fatalf("the answer played %q", got)
		}
		time.Sleep(29 * time.Minute)
		synctest.Wait()
		if got := <-r.l.saying; got != "CLIP:ending" {
			t.Fatalf("a minute before MaxCall: played %q", got)
		}
		r.l.wasCut(t)
		r.say("from today")
		synctest.Wait()
		r.ans.mu.Lock()
		asks = r.ans.asks
		r.ans.mu.Unlock()
		if len(asks) != 2 || asks[1].Text != "from today" {
			t.Fatalf("asks = %+v", asks)
		}
		r.hangup()

		// A 0 and a barge-in during the clip wait for it to play.
		r = newRig(t, fixed("Hi."))
		r.bubble = true
		r.cfg.Clips.Ending = []byte("CLIP:ending")
		r.l.saying = make(chan string) // Say waits for the test to take each sound
		r.serve()
		time.Sleep(29 * time.Minute)
		synctest.Wait() // the loop is playing the clip
		r.l.keys <- '0'
		heard := make(chan struct{})
		go func() { r.rec.out <- call.Heard{Text: "wait"}; close(heard) }()
		synctest.Wait()
		select {
		case <-heard:
			t.Fatal("speech was read while the clip played")
		default:
		}
		if len(r.l.keys) != 1 {
			t.Fatal("a key was read while the clip played")
		}
		if got := <-r.l.saying; got != "CLIP:ending" {
			t.Fatalf("a minute before MaxCall: played %q", got)
		}
		synctest.Wait()
		select {
		case <-heard:
		default:
			t.Fatal("speech was not read once the clip played")
		}
		if len(r.l.keys) != 0 {
			t.Fatal("the key was not read once the clip played")
		}
		r.hangup()

		// A call shorter than EndingNotice has no notice at all.
		r = newRig(t, fixed("Hi."))
		r.bubble = true
		r.cfg.MaxCall = 30 * time.Second
		r.cfg.Clips.Ending = []byte("CLIP:ending")
		r.serve()
		time.Sleep(time.Hour)
		synctest.Wait()
		if _, err := r.end(); !errors.Is(err, call.ErrTooLong) || len(r.l.spoken()) != 0 {
			t.Fatalf("a 30 s call: err %v, played %q", err, r.l.spoken())
		}
	})
}

// A panic in Serve frees the line and leaves no token read behind (#5274):
// a nil ctx panics after the take, and a loop that panics still ends the
// token read and waits for it before Serve unwinds. Here the loop panics
// playing the failed clip (the line's Say sends on a closed channel) once
// the reader is in the token window's clock, which stops the recognizer
// and holds the reader there 20 ms more, so a Serve that did not wait
// unwinds first.
func TestAPanicInServeFreesTheLine(t *testing.T) {
	recovered := func(f func()) (v any) {
		defer func() { v = recover() }()
		f()
		return nil
	}
	answered := func() { // fails within a second if the line is still held
		next := newRig(t, fixed("All quiet."))
		next.cfg.After = func(d time.Duration) <-chan time.Time {
			if d == 10*time.Second { // RingWait
				return time.After(time.Second)
			}
			return nil
		}
		next.serve()
		select {
		case next.rec.out <- call.Heard{Text: "and now", Final: true}:
		case err := <-next.err:
			t.Fatalf("the next call was refused: %v", err)
		}
		if got := next.next(); got != "S:All quiet." {
			t.Fatalf("the next call played %q", got)
		}
		next.hangup()
	}

	r := newRig(t, fixed("Hi."))
	var none context.Context
	if v := recovered(func() { call.Serve(none, r.cfg, r.l, "+15550100") }); v == nil {
		t.Fatal("a nil ctx did not panic")
	}
	answered()

	r = newRig(t, fixed("Hi."))
	r.cfg.Token = func(string) bool { return true }
	r.cfg.TokenWindow = 7 * time.Second
	r.l.saying = make(chan string)
	close(r.l.saying) // Say panics
	var read atomic.Bool
	r.cfg.After = func(d time.Duration) <-chan time.Time {
		if d == 7*time.Second {
			<-r.rec.ctx      // the loop is listening
			close(r.rec.out) // so it plays the failed clip
			time.Sleep(20 * time.Millisecond)
			read.Store(true)
		}
		return nil
	}
	unwound := make(chan any, 1)
	go func() { unwound <- recovered(func() { call.Serve(context.Background(), r.cfg, r.l, "+15550100") }) }()
	select {
	case v := <-unwound:
		if v == nil {
			t.Fatalf("Serve unwound with %v", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not unwind")
	}
	if !read.Load() {
		t.Fatal("Serve unwound a panic before its token read ended")
	}
	r.settle()
	answered()
}

// A turn whose sentence fails to play ends its producer first (#5274): the
// rest of the answer is not synthesized unplayed. A turn that drained its
// producer before ending it would synthesize all 20 sentences.
func TestAFailedSayEndsTheAnswer(t *testing.T) {
	r := newRig(t, fixed(strings.Repeat("A sentence. ", 20)))
	r.l.sayErr = errors.New("line gone")
	var spoken atomic.Int32
	r.cfg.Synthesizer = synthFunc(func(_ context.Context, s string) ([]byte, error) {
		spoken.Add(1)
		return []byte("S:" + s), nil
	})
	ends := r.records()
	r.run(call.P2)
	r.say("q")
	r.turnEnds(ends, 1)
	if n := spoken.Load(); n >= 20 {
		t.Fatalf("%d sentences synthesized after the first failed to play", n)
	}
	if rep := r.hangup(); len(rep.Turns) != 1 || !rep.Turns[0].Stopped || rep.Turns[0].Sentences != 0 {
		t.Fatalf("turns = %+v", rep.Turns)
	}
}
