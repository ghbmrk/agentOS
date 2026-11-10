// Package call runs the read-only voice assistant on one owner call
// (VOICE-ro-a, briefs/VOICE-ro.md; SPEC CH-5, CH-17, CH-21).
//
// The owner speaks; an untrusted recognizer turns speech into text; an
// answerer, under read keys only, writes text; every sentence of that text
// passes the CH-21 check and the spoken key-prompt check before an untrusted
// synthesizer reads it aloud. Models emit text and this loop decides what is
// spoken. No key on these calls means yes: the loop opens no approval
// window, and 0 only stops speech.
package call

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/owner"
)

// Rung names what an owner event has proved (rearchitecture note §2.1). It
// is a label: a Rung value proves nothing. What a call has proved reaches
// the answerer only through Ask.Rung, which reads the call's grant.
type Rung int

const (
	// P0: a number claims to be the owner's. A call the owner placed.
	P0 Rung = iota
	// P1: whoever holds the owner's number received the box's message.
	P1
	// P2: the caller holds the owner's number and handset (the token call, after S2).
	P2
)

// Line is one connected call. *at.Call satisfies it.
type Line interface {
	Active() <-chan struct{}
	Ended() <-chan struct{}
	// Speech is the far end's voice with keypad tones cut out.
	Speech() <-chan []byte
	// Keys are keypad presses, decoded below the speech path.
	Keys() <-chan byte
	// Say plays 8 kHz S16_LE mono PCM and returns when it is played or ctx ends.
	Say(ctx context.Context, pcm []byte) error
	Hangup(ctx context.Context) error
}

// Incoming is a ringing call.
type Incoming interface {
	Line
	Number() string
	Answer(ctx context.Context) error
}

// Heard is what the recognizer proposes. Text is a claim (flip-phone note
// §2.2 rule 3). A non-final Heard with text means the owner is speaking.
type Heard struct {
	Text  string
	Final bool
	// End is when the owner stopped speaking, by the recognizer's account.
	End time.Time
}

// Recognizer is the untrusted speech-to-text service.
type Recognizer interface {
	Listen(ctx context.Context, speech <-chan []byte) <-chan Heard
}

// Ask is one owner turn handed to the answerer. Its rung is read with
// Rung; only this package can set it.
type Ask struct {
	Text string
	Turn int
	rung *grant
}

// Rung is the rung of the call that asked: P2 if its token checked, until
// that call's Serve has returned, and P0 otherwise, so an Ask kept from one
// call never vouches for a later one. An Ask built outside this package is
// P0.
func (a Ask) Rung() Rung { return a.rung.level() }

// Answerer writes the answer as text. Wired to read keys only; the rung
// bounds what it may disclose. The channel closes at the end of the answer.
type Answerer interface {
	Answer(ctx context.Context, a Ask) (<-chan string, error)
}

// Synthesizer is the untrusted text-to-speech service. It only reads.
type Synthesizer interface {
	Speak(ctx context.Context, sentence string) ([]byte, error)
}

// Clips are the box's own fixed audio, never written by a model.
type Clips struct {
	// OneMoment covers an answer slower than Config.OneMomentAfter.
	OneMoment []byte
	// Held replaces an answer whose sentence the check held.
	Held []byte
	// Failed tells the owner a turn failed (the answerer or synthesizer
	// erred, or the recognizer stopped), so a failure is never silence.
	Failed []byte
	// Ending tells the owner the call ends in a minute and they can call
	// again ("This call ends in one minute. Call again to carry on."), so
	// the hang-up at MaxCall is never a silent drop. It plays EndingNotice
	// before the call's end, and stops an answer then playing.
	Ending []byte
}

// Config wires one call loop.
type Config struct {
	Recognizer  Recognizer
	Answerer    Answerer
	Synthesizer Synthesizer
	Clips       Clips
	// Hold reports text that must not be spoken. Nil means owner.AgentVoice
	// (CH-21). KeyPrompt is always checked as well.
	Hold func(string) bool
	// OneMomentAfter is how long a turn waits for content before the
	// OneMoment clip plays (default 1 s, flip-phone note §2.4).
	OneMomentAfter time.Duration
	// Now and After are the clock (default time.Now, time.After).
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time
	// Token checks the speed-dial token's keys; the kernel holds the token
	// and limits tries across calls. Nil means no token: every call is P0.
	Token func(keys string) bool
	// TokenWindow is how long Serve waits after the call is up for the
	// token's keys (default 6 s: a contact's pause is 2 to 3 s per comma).
	TokenWindow time.Duration
	// RingWait is how long an owner call that rings while another is
	// served waits for it to end before ErrBusy (default 10 s, inside the
	// time a carrier rings before voicemail).
	RingWait time.Duration
	// MaxCall ends a call that lasts longer (default 30 min), so a lost
	// NO CARRIER or a wedged line frees the next owner call.
	MaxCall time.Duration
	// Done, if set, gets each turn's record as the turn ends, so timing
	// is reported while the call goes on.
	Done func(Turn)
}

// Turn is one owner turn's record.
type Turn struct {
	N int
	// FirstAudio and FirstContent run from the end of the owner's speech
	// to the start of the first clip or sentence played, and of the first
	// sentence played. Zero means none was played.
	FirstAudio, FirstContent time.Duration
	Sentences                int
	Held                     bool
	// Stopped means 0, barge-in, hang-up or the end of the loop cut it short.
	Stopped bool
	Err     error
}

// Report is what one call did. Rung records the call's rung once the token
// was read; it is a record, not a proof.
type Report struct {
	Rung  Rung
	Turns []Turn
}

// EndingNotice is how long before the end of a call (Config.MaxCall)
// Clips.Ending plays.
const EndingNotice = time.Minute

// MaxSentence caps a sentence that has no end mark, in runes.
const MaxSentence = 300

// ErrDeaf is returned when the recognizer stops during a call: nothing
// the owner says can be heard any more.
var ErrDeaf = errors.New("call: the recognizer stopped")

// ErrNotOwner is returned for a call from a number other than the owner's.
var ErrNotOwner = errors.New("call: not the owner's number")

// MaxToken caps the keys read as the speed-dial token.
const MaxToken = 32

// ErrBusy is returned for an owner call that rings while another call is
// served, once Config.RingWait has passed with it still ringing or once its
// caller hangs up first. It is left ringing, like any other caller.
var ErrBusy = errors.New("call: another call is being served")

// ErrTooLong is returned for a call ended at Config.MaxCall.
var ErrTooLong = errors.New("call: the call reached its maximum length")

// HangupWait bounds the hang-up of a call ended at Config.MaxCall, so a
// line that wedges on it holds the next owner call for that long at most.
const HangupWait = 5 * time.Second

// serving holds a value while Serve runs, so one call is served at a time
// and a P2 grant is live only while no other call is: a grant kept from one
// call, by a package var or a shared answerer, reads P0 in every later call
// (#5232). Only Serve names it (TestOnlyServeChoosesTheRung).
var serving = make(chan struct{}, 1)

// Serve answers a ringing call from the owner's number, reads the
// speed-dial token, and runs the loop at P2 if the token checks and at P0
// otherwise (briefs/VOICE-ro.md rule 4). Any other caller is left ringing
// for the line's own rules; nothing here answers it. An owner call that
// rings while another is served waits for it to end, up to RingWait, so a
// redial right after a dropped call is answered once the dropped call has
// unwound (#5252); one still ringing then gets ErrBusy. A call is ended
// at MaxCall, so a call end the line never reports frees the next call;
// the owner hears Clips.Ending EndingNotice before then (#5262).
//
// The unlock is deferred first, so a panic after the take (a nil ctx)
// still frees the line; the token read, started once the call is
// answered, is ended and awaited in a defer, so a panic in the loop still
// waits for it (#5274).
func Serve(ctx context.Context, cfg Config, c Incoming, ownerNumber string) (Report, error) {
	if ownerNumber == "" || c.Number() != ownerNumber {
		return Report{}, ErrNotOwner
	}
	cfg = cfg.withDefaults()
	select {
	case serving <- struct{}{}:
	default: // another call is served: wait for it to end, up to RingWait
		select {
		case serving <- struct{}{}:
		case <-cfg.After(cfg.RingWait):
			return Report{}, ErrBusy
		case <-c.Ended(): // the caller gave up first
			return Report{}, ErrBusy
		case <-ctx.Done():
			return Report{}, ctx.Err()
		}
	}
	defer func() { <-serving }()
	// The call's ctx: it ends at MaxCall, ends the token read and with it
	// the call's grant, and is cancelled before the next call can be
	// served (TestOnlyServeChoosesTheRung pins the order).
	tctx, cancel := context.WithTimeoutCause(ctx, cfg.MaxCall, ErrTooLong)
	defer cancel()
	if err := c.Answer(tctx); err != nil {
		return Report{}, overrun(ctx, tctx, c, err)
	}
	// The token is read only once the call is answered, so keys pressed
	// before then reach no try if it never is.
	token := make(chan *grant, 1)
	go cfg.token(tctx, c, token)
	// End the token read and wait for it: token closes token once its one
	// check is done, so no Config.Token try follows Serve (#5259). The
	// read ends at tctx's end, and Token is the kernel's, not the line's.
	defer func() {
		cancel()
		for range token {
		}
	}()
	rep, err := loop(tctx, cfg, c, token)
	return rep, overrun(ctx, tctx, c, err)
}

// overrun is err, or ErrTooLong once the call's ctx has reached MaxCall:
// then the line never reported the end, or never finished answering, so
// overrun hangs it up on a ctx of its own, Serve's bounded by HangupWait
// (the call's has ended).
func overrun(ctx, call context.Context, l Line, err error) error {
	if context.Cause(call) != ErrTooLong {
		return err
	}
	hctx, cancel := context.WithTimeout(ctx, HangupWait)
	defer cancel()
	l.Hangup(hctx)
	return ErrTooLong
}

// token sends the call's grant on out: check's verdict on the speed-dial
// keys, live as long as ctx. Then it closes out, so Serve can wait for it.
// Only Serve calls it, with a ctx it ends when the call ends, so no grant
// outlives its call.
func (cfg Config) token(ctx context.Context, l Line, out chan<- *grant) {
	defer close(out)
	out <- check(cfg, ctx.Done(), cfg.keys(ctx, l))
}

// keys reads the speed-dial token: the handset's contact holds the box's
// number, a pause and the token, so the phone keys it once the call is up
// (flip-phone note §2.1). Keys up to '#', MaxToken keys, or the end of
// TokenWindow are the token, checked once by check; they reach nothing
// else, and none of them is STOP. With no Token, or a call that ends or
// keys none, it is "", which stays at P0.
func (cfg Config) keys(ctx context.Context, l Line) string {
	if cfg.Token == nil {
		return ""
	}
	active, keys := l.Active(), l.Keys()
	var window <-chan time.Time // opens when the call is up
	var b strings.Builder
	for b.Len() < MaxToken {
		select {
		case <-active:
			active = nil
			window = cfg.After(cfg.TokenWindow)
		case k, ok := <-keys:
			if !ok {
				return ""
			}
			if k == '#' {
				return b.String()
			}
			b.WriteByte(k)
		case <-window:
			return b.String()
		case <-ctx.Done(): // Serve's, ended when the call ends
			return ""
		}
	}
	return b.String()
}

// check is the one place a grant is made: P2 when the kernel's Token
// accepts the keys, until live closes. Only token calls it. Once live has
// closed it tries nothing, so keys read as the call ends are not a try
// (#5274).
func check(cfg Config, live <-chan struct{}, keys string) *grant {
	select {
	case <-live:
		return nil
	default:
	}
	if keys != "" && cfg.Token(keys) {
		return &grant{r: P2, live: live}
	}
	return nil
}

// grant is what a call has proved, and the only thing that lets the
// answerer hear more than P0. Its type is unexported, so no other package
// can make one, and in this package only check makes one and nothing
// writes its fields (TestOnlyServeChoosesTheRung). So every grant is
// either check's or a zero value, and a copy of either is the same: no
// write can mint one or stretch its life.
type grant struct {
	r    Rung
	live <-chan struct{} // closed when Serve returns
}

// level is the grant's rung while its call is live, and P0 otherwise: for
// no grant, a zero grant (whose live is nil), or once live has closed.
func (g *grant) level() Rung {
	if g == nil || g.live == nil {
		return P0
	}
	select {
	case <-g.live:
		return P0
	default:
		return g.r
	}
}

// callRung is the call's grant as the turns see it: ready closes once the
// token is read, and g is fixed from then on.
type callRung struct {
	ready chan struct{}
	g     *grant
}

// loop holds one call until it ends or ctx is done. Turns are answered one
// at a time: a new final turn, any speech from the owner, or the 0 key
// stops the answer being spoken first. The call is at P0 until its grant
// comes on token. loop is a plain unexported function, not a method, so no
// interface or type constraint can name it: code reaches it only by naming
// it, and Serve, which answers only the owner's number and fills token from
// the speed-dial check, is the one place that does (briefs/VOICE-ro.md rule
// 4, #4949; TestOnlyServeChoosesTheRung).
//
// It listens from the start, so the owner's first words are heard while
// the token is read; keys are the token's until it is read. A turn starts
// as soon as it is heard, whether or not the rung is known yet, so its one
// clip deadline covers the wait for the rung as well as the answerer and
// the synthesizer (rule 5; UX on #4944).
func loop(ctx context.Context, cfg Config, l Line, token <-chan *grant) (Report, error) {
	rep := Report{Rung: P0}
	select {
	case <-l.Active():
	case <-l.Ended():
		return rep, nil
	case <-ctx.Done():
		return rep, ctx.Err()
	}
	// The ending notice falls EndingNotice before ctx's deadline (Serve's
	// MaxCall) and plays on ctx, so it never outlasts the call (#5262). A
	// call up with less time left than that, or with no Ending clip, has
	// none: an unset clip neither cuts the answer nor plays empty audio.
	var ending <-chan time.Time
	if d, ok := ctx.Deadline(); ok && len(cfg.Clips.Ending) > 0 {
		if w := time.Until(d) - EndingNotice; w > 0 {
			ending = time.After(w) // the wall clock, as ctx's deadline is
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	heard := cfg.Recognizer.Listen(ctx, l.Speech())
	cr := &callRung{ready: make(chan struct{})}
	var keys <-chan byte // nil while the token is read
	known := func(g *grant) {
		cr.g = g
		close(cr.ready)
		rep.Rung, token, keys = g.level(), nil, l.Keys()
	}
	select { // a grant already on token is known before the first turn can start
	case g := <-token:
		known(g)
	default:
	}

	type running struct {
		cancel context.CancelFunc
		done   chan struct{}
		turn   *Turn
		text   string
		// asked is set by the turn before it asks the answerer, and read
		// only after done.
		asked bool
	}
	var cur *running
	// carry is what the owner asked in a turn stopped before it reached
	// the answerer (only while the rung is still being read), asked again
	// with the owner's next words.
	var carry string
	finish := func() {
		rep.Turns = append(rep.Turns, *cur.turn)
		if cfg.Done != nil {
			cfg.Done(*cur.turn)
		}
		cur = nil
	}
	// stop ends the current turn; keep carries its question forward if the
	// answerer never saw it.
	stop := func(keep bool) {
		if cur == nil {
			return
		}
		cur.cancel()
		<-cur.done
		if keep && !cur.asked {
			carry = cur.text
		}
		finish()
	}
	n := 0
	start := func(text string, end time.Time) {
		n++
		tctx, tcancel := context.WithCancel(ctx)
		r := &running{cancel: tcancel, done: make(chan struct{}), turn: &Turn{N: n}, text: text}
		cur = r
		if end.IsZero() {
			end = cfg.Now()
		}
		go func() {
			defer close(r.done)
			cfg.turn(tctx, l, text, n, cr, end, r.turn, &r.asked)
		}()
	}
	for {
		var done chan struct{}
		if cur != nil {
			done = cur.done
		}
		select {
		case <-ctx.Done():
			stop(false)
			return rep, ctx.Err()
		case <-l.Ended():
			stop(false)
			return rep, nil
		case <-done:
			finish()
		case g := <-token:
			known(g)
		case <-ending: // one sound at a time: the notice stops the answer
			stop(true)
			l.Say(ctx, cfg.Clips.Ending)
		case k, ok := <-keys:
			if !ok { // keys close when the call ends
				stop(false)
				return rep, nil
			}
			// 0 is STOP (flip-phone note §2.2 rule 4). No other key does
			// anything on a read-only call: none means yes.
			if k == '0' {
				stop(false)
				carry = ""
			}
		case h, ok := <-heard:
			if !ok {
				stop(false)
				l.Say(ctx, cfg.Clips.Failed)
				return rep, ErrDeaf
			}
			if !h.Final {
				if strings.TrimSpace(h.Text) != "" {
					stop(true) // barge-in
				}
				continue
			}
			stop(true)
			text := strings.TrimSpace(carry + " " + h.Text)
			carry = ""
			if stopWord(h.Text) || text == "" {
				continue
			}
			start(text, h.End)
		}
	}
}

func (cfg Config) withDefaults() Config {
	if cfg.Hold == nil {
		cfg.Hold = owner.AgentVoice
	}
	if cfg.OneMomentAfter <= 0 {
		cfg.OneMomentAfter = time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.TokenWindow <= 0 {
		cfg.TokenWindow = 6 * time.Second
	}
	if cfg.After == nil {
		cfg.After = time.After
	}
	if cfg.RingWait <= 0 {
		cfg.RingWait = 10 * time.Second
	}
	if cfg.MaxCall <= 0 {
		cfg.MaxCall = 30 * time.Minute
	}
	return cfg
}

// sound is one thing an answer has ready to play, or why it ends.
type sound struct {
	pcm  []byte
	held bool
	err  error
}

// turn plays one owner turn into t. It owns the turn's one clip deadline,
// end plus OneMomentAfter, set once when the turn starts and spent at the
// first audio, and every wait before that audio is a case of the one
// select below: the call's rung, the answerer and the synthesizer (rule 5).
// Once the rung is known a producer writes, checks and synthesizes the
// sentences while the one before plays; this loop plays them one at a
// time, and a sentence ready when the deadline falls goes before the clip.
func (cfg Config) turn(ctx context.Context, l Line, text string, n int, cr *callRung, end time.Time, t *Turn, asked *bool) {
	var sounds chan sound // nil until the rung is known
	pctx, cancel := context.WithCancel(ctx)
	defer func() { // the producer ends with its turn (#5252)
		cancel()
		if sounds != nil {
			for range sounds {
			}
		}
	}()
	defer func() {
		if ctx.Err() != nil {
			t.Stopped = true
		}
	}()
	rung := cr.ready
	ask := func() {
		rung = nil
		*asked = true
		sounds = make(chan sound)
		go cfg.produce(pctx, Ask{Text: text, Turn: n, rung: cr.g}, sounds)
	}
	select { // a known rung asks the answerer before the deadline is set
	case <-rung:
		ask()
	default:
	}
	moment := cfg.After(cfg.OneMomentAfter - cfg.Now().Sub(end))
	play := func(pcm []byte, content bool) bool {
		if len(pcm) == 0 {
			return true
		}
		if t.FirstAudio == 0 {
			t.FirstAudio = nonZero(cfg.Now().Sub(end))
		}
		if content && t.FirstContent == 0 {
			t.FirstContent = nonZero(cfg.Now().Sub(end))
		}
		if err := l.Say(ctx, pcm); err != nil {
			t.Stopped = true
			return false
		}
		return true
	}
	take := func(s sound, ok bool) bool { return cfg.take(ctx, s, ok, t, play) }
	for {
		select {
		case <-ctx.Done():
			return
		case <-rung:
			ask()
		case <-moment:
			moment = nil
			if t.FirstAudio != 0 {
				continue
			}
			select { // a sentence ready now goes before the clip
			case s, ok := <-sounds:
				if !take(s, ok) {
					return
				}
			default:
				if !play(cfg.Clips.OneMoment, false) {
					return
				}
			}
		case s, ok := <-sounds:
			if !take(s, ok) {
				return
			}
		}
	}
}

// take plays s, one sound from the producer, into t and reports whether
// the answer goes on. An error that arrives once ctx is done is a stop, not
// a failure. The turn receives an error only before ctx ends (a send loses
// to ctx.Done after), so that case is a stop landing between the receive
// and the check here; it is tested on take itself.
func (cfg Config) take(ctx context.Context, s sound, ok bool, t *Turn, play func([]byte, bool) bool) bool {
	switch {
	case !ok:
		return false
	case s.err != nil:
		if ctx.Err() != nil { // stopped, not failed
			return false
		}
		t.Err = s.err
		play(cfg.Clips.Failed, false)
		return false
	case s.held:
		t.Held = true
		play(cfg.Clips.Held, false)
		return false
	case !play(s.pcm, true):
		return false
	}
	t.Sentences++
	return true
}

// produce writes the answer's sentences to out, each checked and
// synthesized, and closes out at the end of the answer. It stops at the
// first hold or error, which it sends, or once ctx ends, even while the
// answerer or synthesizer it called ignores ctx (within), so its turn can
// wait for it and none outlives Serve (#5252).
func (cfg Config) produce(ctx context.Context, a Ask, out chan<- sound) {
	defer close(out)
	send := func(s sound) bool {
		select {
		case out <- s:
			return true
		case <-ctx.Done():
			return false
		}
	}
	// last sends s, a hold or an error, which ends the answer.
	last := func(s sound) bool {
		send(s)
		return false
	}
	chunks, err := within(ctx, func() (<-chan string, error) { return cfg.Answerer.Answer(ctx, a) })
	if err != nil {
		send(sound{err: err})
		return
	}
	// said is everything this answer has sent to be spoken.
	var said string
	sentence := func(s string) bool {
		s = strings.TrimSpace(s)
		if s == "" {
			return true
		}
		// The check runs on the sentence alone and joined with all the
		// answer has said, so nothing straddles a cut, however many
		// sentences it spans (rule 1; Security on #4944).
		if cfg.held(s) || (said != "" && cfg.held(said+" "+s)) {
			return last(sound{held: true})
		}
		pcm, err := within(ctx, func() ([]byte, error) { return cfg.Synthesizer.Speak(ctx, s) })
		if err != nil {
			return last(sound{err: err})
		}
		said = strings.TrimSpace(said + " " + s)
		return send(sound{pcm: pcm})
	}
	var buf string
	for {
		select {
		case <-ctx.Done():
			return
		case c, ok := <-chunks:
			if !ok {
				sentence(buf)
				return
			}
			buf += c
			for {
				s, rest, cut := Cut(buf)
				if !cut {
					break
				}
				if !sentence(s) {
					return
				}
				buf = rest
			}
		}
	}
}

// within returns f's result, or ctx's error once ctx ends first. f runs
// on its own goroutine, which ends when f returns: a part that ignores ctx
// keeps only its own call, never the turn or the call.
func within[T any](ctx context.Context, f func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := f()
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

func (cfg Config) held(s string) bool { return cfg.Hold(s) || KeyPrompt(s) }

func nonZero(d time.Duration) time.Duration {
	if d <= 0 {
		return 1
	}
	return d
}

// Cut takes the first complete sentence off s: text up to an end mark
// (. ! ? or a line break) followed by space, or MaxSentence runes cut at
// the last space. cut is false while the sentence may still go on.
func Cut(s string) (sentence, rest string, cut bool) {
	for i, r := range s {
		switch r {
		case '\n':
			return s[:i], s[i+1:], true
		case '.', '!', '?':
			// At the end of s, s[j:] is "", which decodes as RuneError, not space.
			j := i + utf8.RuneLen(r)
			if n, _ := utf8.DecodeRuneInString(s[j:]); unicode.IsSpace(n) {
				return s[:j], s[j:], true
			}
		}
	}
	if utf8.RuneCountInString(s) <= MaxSentence {
		return "", s, false
	}
	b := len(string([]rune(s)[:MaxSentence]))
	if sp := strings.LastIndexFunc(s[:b], unicode.IsSpace); sp > 0 {
		b = sp
	}
	return s[:b], s[b:], true
}

// keyPrompt is the spoken prompt grammar (flip-phone note §2.2 rule 2): a
// keypad verb or "key" followed within three words by a digit or key name.
// Only the box asks for a key, and only inside a window it opens itself.
// On CH-12's folds 1 reads as l and 0 as o, so those letters count too.
const (
	keyVerb  = `(?i)\b(press|pressing|presses|pressed|key|keys|keypad|dial|dialing|dialling|enter|entering|push|tap|hit|type)\b[^\p{L}\p{N}]*(?:[\p{L}']+[^\p{L}\p{N}]+){0,3}?`
	keyNames = `\d|zero|oh|one|two|three|four|five|six|seven|eight|nine|pound|hash|star|asterisk`
)

var keyPrompt = regexp.MustCompile(keyVerb + `(` + keyNames + `|l|o)\b`)

// KeyPrompt reports text telling the listener to press a key, on the text
// and on each of CH-12's folds (homoglyphs, marks, invisible joins).
func KeyPrompt(s string) bool {
	for _, f := range append([]string{s}, owner.CheckFolds(s)...) {
		if keyPrompt.MatchString(f) {
			return true
		}
	}
	return false
}

// stopWord is the owner saying only "stop" (or "stop it", "stop that"),
// which stops speech like the 0 key. A narrowing by speech applies at once
// (rearchitecture note §2.3).
func stopWord(s string) bool {
	s = strings.ToLower(strings.TrimFunc(s, func(r rune) bool { return !unicode.IsLetter(r) }))
	switch s {
	case "stop", "stop it", "stop that", "stop talking", "quiet", "be quiet", "shush":
		return true
	}
	return false
}
