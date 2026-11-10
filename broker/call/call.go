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

// Rung is the proof an owner event carries (rearchitecture note §2.1). The
// call sets it, never the transcript.
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

// Ask is one owner turn handed to the answerer.
type Ask struct {
	Text string
	Rung Rung
	Turn int
}

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

// Report is what one call did.
type Report struct {
	Rung  Rung
	Turns []Turn
}

// MaxSentence caps a sentence that has no end mark, in runes.
const MaxSentence = 300

// ErrDeaf is returned when the recognizer stops during a call: nothing
// the owner says can be heard any more.
var ErrDeaf = errors.New("call: the recognizer stopped")

// ErrNotOwner is returned for a call from a number other than the owner's.
var ErrNotOwner = errors.New("call: not the owner's number")

// MaxToken caps the keys read as the speed-dial token.
const MaxToken = 32

// Serve answers a ringing call from the owner's number, reads the
// speed-dial token, and runs the loop at P2 if the token checks and at P0
// otherwise (briefs/VOICE-ro.md rule 4). Any other caller is left ringing
// for the line's own rules; nothing here answers it.
func Serve(ctx context.Context, cfg Config, c Incoming, ownerNumber string) (Report, error) {
	if ownerNumber == "" || c.Number() != ownerNumber {
		return Report{}, ErrNotOwner
	}
	if err := c.Answer(ctx); err != nil {
		return Report{}, err
	}
	cfg = cfg.withDefaults()
	tctx, cancel := context.WithCancel(ctx)
	defer cancel()
	token := make(chan Rung, 1)
	go func() { token <- cfg.token(tctx, c) }()
	return loop(ctx, cfg, c, token)
}

// token reads the speed-dial token: the handset's contact holds the box's
// number, a pause and the token, so the phone keys it once the call is up
// (flip-phone note §2.1). Keys up to '#', MaxToken keys, or the end of
// TokenWindow are the token, checked once by cfg.Token; they reach nothing
// else, and none of them is STOP. A call whose token does not check, or
// that keys none, stays at P0.
func (cfg Config) token(ctx context.Context, l Line) Rung {
	if cfg.Token == nil {
		return P0
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
				return P0
			}
			if k == '#' {
				return cfg.check(b.String())
			}
			b.WriteByte(k)
		case <-window:
			return cfg.check(b.String())
		case <-ctx.Done(): // Serve's, ended when the call ends
			return P0
		}
	}
	return cfg.check(b.String())
}

func (cfg Config) check(token string) Rung {
	if token != "" && cfg.Token(token) {
		return P2
	}
	return P0
}

// callRung is the call's rung as the turns see it: ready closes once it is
// known, and r is fixed from then on.
type callRung struct {
	ready chan struct{}
	r     Rung
}

// loop holds one call until it ends or ctx is done. Turns are answered one
// at a time: a new final turn, any speech from the owner, or the 0 key
// stops the answer being spoken first. The call is at P0 until its rung
// comes on token, and token is the loop's only rung input. loop is a plain
// unexported function, not a method, so no interface or type constraint can
// name it: code reaches it only by naming it, and Serve, which fills token
// from the speed-dial check, is the one place that does (briefs/VOICE-ro.md
// rule 4, #4949; TestOnlyServeChoosesTheRung).
//
// It listens from the start, so the owner's first words are heard while
// the token is read; keys are the token's until it is read. A turn starts
// as soon as it is heard, whether or not the rung is known yet, so its one
// clip deadline covers the wait for the rung as well as the answerer and
// the synthesizer (rule 5; UX on #4944).
func loop(ctx context.Context, cfg Config, l Line, token <-chan Rung) (Report, error) {
	rep := Report{Rung: P0}
	select {
	case <-l.Active():
	case <-l.Ended():
		return rep, nil
	case <-ctx.Done():
		return rep, ctx.Err()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	heard := cfg.Recognizer.Listen(ctx, l.Speech())
	cr := &callRung{ready: make(chan struct{})}
	var keys <-chan byte // nil while the token is read
	known := func(r Rung) {
		cr.r = r
		close(cr.ready)
		rep.Rung, token, keys = r, nil, l.Keys()
	}
	select { // a rung already on token is known before the first turn can start
	case r := <-token:
		known(r)
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
		case r := <-token:
			known(r)
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
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		if ctx.Err() != nil {
			t.Stopped = true
		}
	}()
	rung := cr.ready
	var sounds chan sound // nil until the rung is known
	ask := func() {
		rung = nil
		*asked = true
		sounds = make(chan sound)
		go cfg.produce(pctx, Ask{Text: text, Rung: cr.r, Turn: n}, sounds)
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
// first hold or error, which it sends.
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
	chunks, err := cfg.Answerer.Answer(ctx, a)
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
		pcm, err := cfg.Synthesizer.Speak(ctx, s)
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
