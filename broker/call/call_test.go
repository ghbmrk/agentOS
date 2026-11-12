package call_test

// REQ: CH-5, CH-17, CH-21

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/call"
)

// line is a fake call. Say logs what was played; while gate is set, Say
// blocks until ctx ends, so a test can stop speech mid-sentence.
type line struct {
	active, ended chan struct{}
	speech        chan []byte
	keys          chan byte
	mu            sync.Mutex
	said          []string
	saying        chan string
	gate          bool
	answered      bool
	number        string
	// cut gets one value each time speech is stopped mid-sentence.
	cut     chan struct{}
	inSay   int
	overlap bool
	sayErr  error
	empty   bool
	hungUp  bool
	// hangErr and hangLeft are the hang-up ctx's error and the time left
	// to its deadline (0 with none) as Hangup got it; with hangStuck,
	// Hangup then waits for that ctx to end.
	hangStuck bool
	hangCtx   context.Context
	hangErr   error
	hangLeft  time.Duration
	stuck     bool
	answerErr error
	// answerWait delays a failing Answer; answerCtx is the ctx it got.
	answerWait time.Duration
	answerCtx  context.Context
}

func newLine() *line {
	l := &line{active: make(chan struct{}), ended: make(chan struct{}), speech: make(chan []byte),
		keys: make(chan byte, 4), saying: make(chan string, 64), number: "+15550100", cut: make(chan struct{}, 8)}
	close(l.active)
	return l
}

func (l *line) Active() <-chan struct{} { return l.active }
func (l *line) Ended() <-chan struct{}  { return l.ended }
func (l *line) Speech() <-chan []byte   { return l.speech }
func (l *line) Keys() <-chan byte       { return l.keys }
func (l *line) Hangup(ctx context.Context) error {
	l.mu.Lock()
	l.hungUp, l.hangCtx, l.hangErr = true, ctx, ctx.Err()
	if d, ok := ctx.Deadline(); ok {
		l.hangLeft = time.Until(d)
	}
	stuck := l.hangStuck
	l.mu.Unlock()
	if stuck {
		<-ctx.Done()
	}
	return nil
}
func (l *line) Number() string { return l.number }
func (l *line) Answer(ctx context.Context) error {
	l.mu.Lock()
	l.answerCtx = ctx
	l.mu.Unlock()
	if l.stuck { // answers nothing until ctx ends
		<-ctx.Done()
		return ctx.Err()
	}
	if l.answerErr != nil {
		time.Sleep(l.answerWait)
		return l.answerErr
	}
	l.answered = true
	return nil
}
func (l *line) Say(ctx context.Context, pcm []byte) error {
	l.mu.Lock()
	gate, err := l.gate, l.sayErr
	l.inSay++
	l.overlap = l.overlap || l.inSay > 1
	l.empty = l.empty || len(pcm) == 0
	l.mu.Unlock()
	defer func() { l.mu.Lock(); l.inSay--; l.mu.Unlock() }()
	l.saying <- string(pcm)
	if err != nil {
		return err
	}
	if gate && strings.HasPrefix(string(pcm), "S:") { // clips always play
		<-ctx.Done()
		l.cut <- struct{}{}
		return ctx.Err()
	}
	l.mu.Lock()
	l.said = append(l.said, string(pcm))
	l.mu.Unlock()
	return nil
}

func (l *line) setGate(g bool) { l.mu.Lock(); l.gate = g; l.mu.Unlock() }

// wasCut waits for speech to be stopped mid-sentence.
func (l *line) wasCut(t *testing.T) {
	t.Helper()
	select {
	case <-l.cut:
	case <-time.After(5 * time.Second):
		t.Fatal("speech was not stopped")
	}
}

func (l *line) spoken() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.said...)
}

type recognizer struct {
	out chan call.Heard
	ctx chan context.Context
}

func (r recognizer) Listen(ctx context.Context, _ <-chan []byte) <-chan call.Heard {
	r.ctx <- ctx
	return r.out
}

// answerer returns the scripted chunks for each turn's text.
type answerer struct {
	mu   sync.Mutex
	asks []asked
	// kept are the Asks as given, to read once the call is over.
	kept   []call.Ask
	script func(call.Ask) []string
}

// asked is an Ask as the answerer read it, rung and all, during the call.
type asked struct {
	Text string
	Rung call.Rung
	Turn int
}

func (a *answerer) Answer(ctx context.Context, q call.Ask) (<-chan string, error) {
	a.mu.Lock()
	a.asks = append(a.asks, asked{q.Text, q.Rung(), q.Turn})
	a.kept = append(a.kept, q)
	a.mu.Unlock()
	out := make(chan string)
	go func() {
		defer close(out)
		for _, c := range a.script(q) {
			select {
			case out <- c:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

type synth struct{ tick func() }

func (s synth) Speak(_ context.Context, t string) ([]byte, error) {
	if s.tick != nil {
		s.tick()
	}
	return []byte("S:" + t), nil
}

var clips = call.Clips{OneMoment: []byte("CLIP:moment"), Held: []byte("CLIP:held"), Failed: []byte("CLIP:failed")}

type rig struct {
	t   *testing.T
	l   *line
	rec recognizer
	ans *answerer
	cfg call.Config
	rep chan call.Report
	err chan error
	// base is the goroutine count before the call: every goroutine the
	// call starts must be gone after it ends.
	base int
	// bubble marks a rig made in a synctest bubble. Its sleeps pass no real
	// time, so the count can see goroutines outside it still ending; the
	// bubble checks instead, failing the test on any goroutine left blocked.
	bubble bool
}

func newRig(t *testing.T, script func(call.Ask) []string) *rig {
	r := &rig{t: t, l: newLine(), rec: recognizer{make(chan call.Heard), make(chan context.Context, 1)}, ans: &answerer{script: script}, rep: make(chan call.Report, 1), err: make(chan error, 1), base: runtime.NumGoroutine()}
	r.cfg = call.Config{Recognizer: r.rec, Answerer: r.ans, Synthesizer: synth{}, Clips: clips,
		After: func(time.Duration) <-chan time.Time { return nil }}
	return r
}

func (r *rig) run(rung call.Rung) { r.runCtx(context.Background(), rung) }

func (r *rig) runCtx(ctx context.Context, rung call.Rung) {
	go func() {
		rep, err := call.RunAt(ctx, r.cfg, r.l, rung)
		r.err <- err
		r.rep <- rep
	}()
}

// settle fails the test if goroutines the call started outlive it.
func (r *rig) settle() {
	r.t.Helper()
	if r.bubble {
		return
	}
	for i := 0; i < 200 && runtime.NumGoroutine() > r.base; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > r.base {
		buf := make([]byte, 1<<16)
		r.t.Errorf("%d goroutines outlive the call:\n%s", n-r.base, buf[:runtime.Stack(buf, true)])
	}
}

// end waits for the loop to return, without hanging up.
func (r *rig) end() (call.Report, error) {
	r.t.Helper()
	select {
	case err := <-r.err:
		rep := <-r.rep
		r.settle()
		r.l.mu.Lock()
		defer r.l.mu.Unlock()
		if r.l.overlap {
			r.t.Error("two sounds played at once")
		}
		if r.l.empty {
			r.t.Error("played empty audio")
		}
		return rep, err
	case <-time.After(5 * time.Second):
		r.t.Fatal("loop did not end")
		return call.Report{}, nil
	}
}

func (r *rig) say(text string) { r.rec.out <- call.Heard{Text: text, Final: true} }

func (r *rig) hangup() call.Report {
	r.t.Helper()
	close(r.l.ended)
	rep, err := r.end()
	if err != nil {
		r.t.Fatal(err)
	}
	return rep
}

// next waits for the next audio played.
func (r *rig) next() string {
	select {
	case s := <-r.l.saying:
		return s
	case <-time.After(5 * time.Second):
		r.t.Fatal("nothing played")
		return ""
	}
}

// records hands each turn's record to the returned channel as the turn
// ends (Config.Done). Set it before run or serve.
func (r *rig) records() <-chan call.Turn {
	ch := make(chan call.Turn, 8)
	r.cfg.Done = func(tu call.Turn) { ch <- tu }
	return ch
}

// turnEnds waits for turn n's record. next returns once a sentence starts
// playing, while the turn may still be waiting for its answer to close; a
// hang-up then cuts the turn short. A test that asserts a turn ran to its
// end waits for its record before hanging up.
func (r *rig) turnEnds(ch <-chan call.Turn, n int) {
	r.t.Helper()
	for {
		select {
		case tu := <-ch:
			if tu.N == n {
				return
			}
		case <-time.After(5 * time.Second):
			r.t.Fatalf("turn %d did not end", n)
		}
	}
}

func (r *rig) quiet() {
	select {
	case s := <-r.l.saying:
		r.t.Fatalf("played %q, want nothing", s)
	case <-time.After(50 * time.Millisecond):
	}
}

func fixed(chunks ...string) func(call.Ask) []string {
	return func(call.Ask) []string { return chunks }
}

// Failure path first: a sentence asking for a code is never synthesized,
// the held clip plays instead and the rest of the answer is dropped.
func TestCodeAskIsNeverSpoken(t *testing.T) {
	r := newRig(t, fixed("You have two new mails. ", "Please tell me the code from your text. ", "Also the dentist is at nine."))
	r.run(call.P2)
	r.say("what's in my mail")
	if got := r.next(); got != "S:You have two new mails." {
		t.Fatalf("first = %q", got)
	}
	if got := r.next(); got != "CLIP:held" {
		t.Fatalf("second = %q, want the held clip", got)
	}
	r.quiet()
	rep := r.hangup()
	if len(rep.Turns) != 1 || !rep.Turns[0].Held || rep.Turns[0].Sentences != 1 {
		t.Fatalf("turns = %+v", rep.Turns)
	}
}

func TestKeyPromptIsNeverSpoken(t *testing.T) {
	for _, s := range []string{
		"To confirm, press 1.",
		"Press one to approve the payment.",
		"Now key in 4 4 7 2.",
		"Please dial the number nine.",
		"Hit the pound key now.",
		"Ｐｒｅｓｓ 1 now.",             // fullwidth
		"Pr​ess 1 now.",            // zero-width space
		"Рress 1 to continue.",     // Cyrillic Р
		"press\n1 to continue now", // line break inside the prompt
	} {
		if !call.KeyPrompt(s) {
			t.Errorf("KeyPrompt(%q) = false", s)
		}
	}
	for _, s := range []string{"You have one meeting at nine.", "The press release went out at 4.", "Your keys are on the hook."} {
		if call.KeyPrompt(s) {
			t.Errorf("KeyPrompt(%q) = true, a false hold", s)
		}
	}
	r := newRig(t, fixed("Your bill is due Friday. Press 1 to pay it now."))
	r.run(call.P2)
	r.say("what's due")
	r.next()
	if got := r.next(); got != "CLIP:held" {
		t.Fatalf("got %q, want the held clip", got)
	}
	r.hangup()
}

// A prompt split across the sentence cut is caught on the joined text.
func TestCheckSpansTheSentenceCut(t *testing.T) {
	r := newRig(t, fixed("Okay, just press. ", "1 and we are done."))
	r.run(call.P2)
	r.say("hello")
	if got := r.next(); got != "S:Okay, just press." {
		t.Fatalf("got %q; alone it names no key", got)
	}
	if got := r.next(); got != "CLIP:held" {
		t.Fatalf("got %q, want the joined text held", got)
	}
	r.hangup()

	// Three ways (Security on #4944): each pair is clean, the whole is a prompt.
	r = newRig(t, fixed("Please press. Right now. Nine."))
	r.run(call.P2)
	r.say("what's due")
	r.next()
	r.next()
	if got := r.next(); got != "CLIP:held" {
		t.Fatalf("got %q, want the third sentence held", got)
	}
	r.hangup()

	// With a check that sees only the joined text, the second sentence is held.
	var seen []string
	r = newRig(t, fixed("Your code word. ", "Is tulip."))
	r.cfg.Hold = func(s string) bool { seen = append(seen, s); return strings.Contains(s, "word. Is") }
	r.run(call.P2)
	r.say("hello")
	if got := r.next(); got != "S:Your code word." {
		t.Fatalf("got %q", got)
	}
	if got := r.next(); got != "CLIP:held" {
		t.Fatalf("got %q, want the joined check to hold", got)
	}
	r.hangup()
}

// No key approves anything: keys reach neither the answerer nor speech,
// and only 0 does anything at all.
func TestKeysApproveNothing(t *testing.T) {
	r := newRig(t, fixed("Done."))
	r.run(call.P0)
	for _, k := range []byte("12#*9") {
		r.l.keys <- k
	}
	r.quiet()
	r.say("yes 1 2 3 4")
	r.next()
	r.hangup()
	if len(r.ans.asks) != 1 || r.ans.asks[0].Text != "yes 1 2 3 4" {
		t.Fatalf("asks = %+v", r.ans.asks)
	}
}

func TestZeroStopsSpeech(t *testing.T) {
	r := newRig(t, fixed("This is a long answer. And it goes on."))
	r.l.gate = true
	r.run(call.P2)
	r.say("read my mail")
	r.next() // blocked mid-sentence
	for _, k := range []byte("12#*") {
		r.l.keys <- k // no other key stops it
	}
	select {
	case <-r.l.cut:
		t.Fatal("a key other than 0 stopped speech")
	case <-time.After(50 * time.Millisecond):
	}
	r.l.keys <- '0'
	r.l.wasCut(t)
	r.quiet()
	rep := r.hangup()
	if len(rep.Turns) != 1 || !rep.Turns[0].Stopped {
		t.Fatalf("turns = %+v", rep.Turns)
	}
}

// RunAt's rung is known before its first turn starts, so every turn asks the
// answerer at once and a barge-in carries nothing: carry is only for a
// question stopped while a speed-dial token is still read. The owner's
// words are already waiting when the loop starts, the case where a loop
// that read the rung as one more event could start the turn first (one
// time in four here; 64 calls make a miss about 1e-8).
func TestRunKnowsItsRungBeforeTheFirstTurn(t *testing.T) {
	for i := 0; i < 64; i++ {
		r := newRig(t, func(a call.Ask) []string { return []string{"Answer to " + a.Text + "."} })
		r.rec.out = make(chan call.Heard, 3)
		r.cfg.Recognizer = r.rec
		r.rec.out <- call.Heard{Text: "first", Final: true}
		r.rec.out <- call.Heard{Text: "sec"} // barge-in
		r.rec.out <- call.Heard{Text: "second", Final: true}
		ends := r.records()
		r.run(call.P2)
		for {
			got := r.next()
			if strings.HasSuffix(got, "second.") {
				if got != "S:Answer to second." {
					t.Fatalf("call %d: %q, the stopped question was carried", i, got)
				}
				break
			}
		}
		r.turnEnds(ends, 2)
		r.hangup()
		r.ans.mu.Lock()
		asks := append([]asked(nil), r.ans.asks...)
		r.ans.mu.Unlock()
		for _, a := range asks {
			if a.Rung != call.P2 || (a.Text != "first" && a.Text != "second") {
				t.Fatalf("call %d: asks %+v", i, asks)
			}
		}
	}
}

func TestBargeInStopsAndStartsANewTurn(t *testing.T) {
	r := newRig(t, func(a call.Ask) []string { return []string{"Answer to " + a.Text + "."} })
	r.l.gate = true
	ends := r.records()
	r.run(call.P2)
	r.say("first")
	if got := r.next(); got != "S:Answer to first." {
		t.Fatal(got)
	}
	r.rec.out <- call.Heard{Text: " "} // noise with no words stops nothing
	select {
	case <-r.l.cut:
		t.Fatal("an empty partial stopped speech")
	case <-time.After(50 * time.Millisecond):
	}
	r.rec.out <- call.Heard{Text: "wait"} // the owner talks over the box
	r.l.wasCut(t)
	r.l.setGate(false)
	r.say("second")
	if got := r.next(); got != "S:Answer to second." {
		t.Fatal(got)
	}
	r.turnEnds(ends, 2)
	rep := r.hangup()
	if len(rep.Turns) != 2 || !rep.Turns[0].Stopped || rep.Turns[1].Stopped {
		t.Fatalf("turns = %+v", rep.Turns)
	}
	for i, a := range r.ans.asks {
		if a.Turn != i+1 || rep.Turns[i].N != i+1 {
			t.Fatalf("turn %d numbered %d and %d", i+1, a.Turn, rep.Turns[i].N)
		}
	}
	// A new question with no partial first still stops the answer being
	// spoken before the next one starts: one sound at a time.
	r = newRig(t, func(a call.Ask) []string { return []string{"Answer to " + a.Text + "."} })
	r.l.gate = true
	r.run(call.P2)
	r.say("first")
	r.next()
	r.say("second")
	r.l.wasCut(t)
	r.next()
	r.l.setGate(false)
	r.hangup()
	// Saying "stop" stops speech and asks nothing.
	r = newRig(t, fixed("Long."))
	r.l.gate = true
	r.run(call.P2)
	r.say("go")
	r.next()
	r.say("Stop!")
	r.quiet()
	r.hangup()
	if len(r.ans.asks) != 1 {
		t.Fatalf("asks = %+v", r.ans.asks)
	}
}

func TestHangupEndsTheLoop(t *testing.T) {
	r := newRig(t, fixed("Something."))
	r.l.gate = true
	r.run(call.P2)
	r.say("go")
	r.next()
	rep := r.hangup()
	if len(rep.Turns) != 1 || !rep.Turns[0].Stopped {
		t.Fatalf("turns = %+v", rep.Turns)
	}
}

func TestOwnerCallRunsAtP0(t *testing.T) {
	r := newRig(t, fixed("All quiet."))
	done := make(chan call.Report, 1)
	go func() {
		rep, _ := call.Serve(context.Background(), r.cfg, r.l, "+15550100")
		done <- rep
	}()
	r.say("how are things")
	r.next()
	close(r.l.ended)
	rep := <-done
	if !r.l.answered || rep.Rung != call.P0 || r.ans.asks[0].Rung != call.P0 {
		t.Fatalf("answered %v, report rung %v, asks %+v", r.l.answered, rep.Rung, r.ans.asks)
	}
}

func TestOtherCallerIsNotAnswered(t *testing.T) {
	r := newRig(t, fixed("x"))
	for _, owner := range []string{"+15550199", ""} {
		if _, err := call.Serve(context.Background(), r.cfg, r.l, owner); !errors.Is(err, call.ErrNotOwner) {
			t.Fatalf("owner %q: err = %v", owner, err)
		}
	}
	if r.l.answered {
		t.Fatal("answered a call that is not the owner's")
	}
}

// A call the line fails to answer ends there with the line's error: nothing
// listens and no turn runs.
func TestAFailedAnswerEndsTheCall(t *testing.T) {
	r := newRig(t, fixed("x"))
	boom := errors.New("ATA failed")
	r.l.answerErr = boom
	r.serve()
	select {
	case err := <-r.err:
		if rep := <-r.rep; !errors.Is(err, boom) || len(rep.Turns) != 0 {
			t.Fatalf("err %v, turns %+v", err, rep.Turns)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a call the line failed to answer went on")
	}
	select {
	case <-r.rec.ctx:
		t.Fatal("listened on a call that was not answered")
	default:
	}
}

func TestOneMomentCoversASlowAnswer(t *testing.T) {
	release := make(chan struct{})
	r := newRig(t, func(call.Ask) []string { <-release; return []string{"Here it is."} })
	moment := make(chan time.Time, 1)
	r.cfg.After = func(time.Duration) <-chan time.Time { return moment }
	r.run(call.P2)
	r.say("slow one")
	r.quiet()
	moment <- time.Time{}
	if got := r.next(); got != "CLIP:moment" {
		t.Fatalf("got %q", got)
	}
	close(release)
	if got := r.next(); got != "S:Here it is." {
		t.Fatalf("got %q", got)
	}
	rep := r.hangup()
	if tu := rep.Turns[0]; tu.FirstAudio == 0 || tu.FirstContent < tu.FirstAudio {
		t.Fatalf("turn = %+v", tu)
	}
}

func TestTurnTimesArePercentiles(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	step := time.Duration(0)
	r := newRig(t, fixed("Fine."))
	r.cfg.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	r.cfg.Synthesizer = synth{tick: func() { mu.Lock(); now = now.Add(step); mu.Unlock() }}
	r.run(call.P2)
	for i := 1; i <= 100; i++ {
		mu.Lock()
		step = time.Duration(i) * time.Millisecond
		end := now
		mu.Unlock()
		r.rec.out <- call.Heard{Text: "q", Final: true, End: end}
		r.next()
	}
	rep := r.hangup()
	audio, content := rep.Timing()
	want := call.Spread{N: 100, P50: 50 * time.Millisecond, P95: 95 * time.Millisecond, P99: 99 * time.Millisecond}
	if audio != want || content != want {
		t.Fatalf("audio %+v content %+v, want %+v", audio, content, want)
	}
	if got := call.Percentiles([]time.Duration{0, 3, 1, 2}); got != (call.Spread{N: 3, P50: 2, P95: 3, P99: 3}) {
		t.Fatalf("small set: %+v", got)
	}
}

func TestCutSentences(t *testing.T) {
	for _, c := range []struct{ in, s, rest string }{
		{"It costs 3.50 today. Next", "It costs 3.50 today.", " Next"},
		{"Line one\nline two", "Line one", "line two"},
		{"Really? Yes", "Really?", " Yes"},
	} {
		s, rest, ok := call.Cut(c.in)
		if !ok || s != c.s || rest != c.rest {
			t.Errorf("Cut(%q) = %q, %q, %v", c.in, s, rest, ok)
		}
	}
	if _, _, ok := call.Cut("no end yet"); ok {
		t.Error("cut an unfinished sentence")
	}
	long := strings.Repeat("word ", 100)
	s, rest, ok := call.Cut(long)
	if !ok || len([]rune(s)) > call.MaxSentence || s+rest != long {
		t.Errorf("long cut: %d runes, ok %v", len([]rune(s)), ok)
	}
}
