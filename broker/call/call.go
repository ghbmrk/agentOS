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
	return Run(ctx, cfg, c, cfg.token(ctx, c))
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
		case <-l.Ended(): // Run returns at once
			return P0
		case <-ctx.Done():
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

// Run holds one call until it ends or ctx is done. Turns are answered one
// at a time: a new final turn, any speech from the owner, or the 0 key
// stops the answer being spoken first.
func Run(ctx context.Context, cfg Config, l Line, rung Rung) (Report, error) {
	cfg = cfg.withDefaults()
	rep := Report{Rung: rung}
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
	keys := l.Keys()

	type running struct {
		cancel context.CancelFunc
		done   chan struct{}
		turn   *Turn
	}
	var cur *running
	finish := func() {
		rep.Turns = append(rep.Turns, *cur.turn)
		if cfg.Done != nil {
			cfg.Done(*cur.turn)
		}
		cur = nil
	}
	stop := func() {
		if cur == nil {
			return
		}
		cur.cancel()
		<-cur.done
		finish()
	}
	n := 0
	for {
		var done chan struct{}
		if cur != nil {
			done = cur.done
		}
		select {
		case <-ctx.Done():
			stop()
			return rep, ctx.Err()
		case <-l.Ended():
			stop()
			return rep, nil
		case <-done:
			finish()
		case k, ok := <-keys:
			if !ok { // keys close when the call ends
				stop()
				return rep, nil
			}
			// 0 is STOP (flip-phone note §2.2 rule 4). No other key does
			// anything on a read-only call: none means yes.
			if k == '0' {
				stop()
			}
		case h, ok := <-heard:
			if !ok {
				stop()
				return rep, ErrDeaf
			}
			if !h.Final {
				if strings.TrimSpace(h.Text) != "" {
					stop() // barge-in
				}
				continue
			}
			stop()
			if stopWord(h.Text) || strings.TrimSpace(h.Text) == "" {
				continue
			}
			n++
			tctx, tcancel := context.WithCancel(ctx)
			r := &running{cancel: tcancel, done: make(chan struct{}), turn: &Turn{N: n}}
			cur = r
			end := h.End
			if end.IsZero() {
				end = cfg.Now()
			}
			go func() {
				defer close(r.done)
				defer tcancel()
				cfg.answer(tctx, l, Ask{Text: h.Text, Rung: rung, Turn: n}, end, r.turn)
			}()
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

// answer speaks one answer, sentence by sentence, into t.
func (cfg Config) answer(ctx context.Context, l Line, a Ask, end time.Time, t *Turn) {
	chunks, err := cfg.Answerer.Answer(ctx, a)
	if err != nil {
		t.Err = err
		t.Stopped = ctx.Err() != nil
		return
	}
	// spoken is everything this answer has said so far.
	var spoken string
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
	speak := func(s string) bool {
		s = strings.TrimSpace(s)
		if s == "" {
			return true
		}
		// The check runs on the sentence alone and joined with all the
		// answer has spoken, so nothing straddles a cut, however many
		// sentences it spans (rule 1; Security on #4944).
		if cfg.held(s) || (spoken != "" && cfg.held(spoken+" "+s)) {
			t.Held = true
			play(cfg.Clips.Held, false)
			return false
		}
		pcm, err := cfg.Synthesizer.Speak(ctx, s)
		if err != nil {
			if ctx.Err() != nil {
				t.Stopped = true
			} else {
				t.Err = err
			}
			return false
		}
		if !play(pcm, true) {
			return false
		}
		t.Sentences++
		spoken = strings.TrimSpace(spoken + " " + s)
		return true
	}
	moment := cfg.After(cfg.OneMomentAfter)
	var buf strings.Builder
	for {
		select {
		case <-ctx.Done():
			t.Stopped = true
			return
		case <-moment:
			moment = nil
			if t.FirstAudio == 0 && !play(cfg.Clips.OneMoment, false) {
				return
			}
		case c, ok := <-chunks:
			if !ok {
				speak(buf.String())
				return
			}
			buf.WriteString(c)
			rest := buf.String()
			for {
				s, r, cut := Cut(rest)
				if !cut {
					break
				}
				if !speak(s) {
					return
				}
				rest = r
			}
			buf.Reset()
			buf.WriteString(rest)
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
			j := i + utf8.RuneLen(r)
			if j < len(s) {
				if n, _ := utf8.DecodeRuneInString(s[j:]); unicode.IsSpace(n) {
					return s[:j], s[j:], true
				}
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
