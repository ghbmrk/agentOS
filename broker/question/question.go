package question

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// A guest asks the owner a question with a default and a wait (CAP-10).
// The broker texts it, matches the owner's tagged reply back to it, and,
// when no reply has come by the deadline, closes it on the default and
// lists that in the digest. The broker's own timer decides the lapse:
// nothing the guest sends moves a question. A default, or an answer,
// carries no authority. This package reaches neither the journal nor the
// grants gate (boundary_test.go); an irreversible effect that follows
// still needs its own approval (REV-2).

// Bounds the broker puts on a question (P3-8 Q2, Q3).
const (
	DefaultMinWait      = 5 * time.Minute
	DefaultMaxWait      = 24 * time.Hour
	DefaultPerAsker     = 3
	DefaultMaxOpen      = 8
	DefaultSendsPerHour = 3 // CH-15's default for unsolicited texts
	DefaultRestartGrace = 2 * time.Minute
	DefaultKeep         = 4 * 24 * time.Hour
	// DefaultWaitersPerMachine is how many owner_question_status calls
	// one machine may hold open at once (PQ3): the guest plane serves a
	// machine 8 requests at a time (guest G1), and its bridge holds one
	// for owner messages, so two leaves the rest for effects and models.
	DefaultWaitersPerMachine = 2

	// MaxPerText is how many questions share one owner text (PQ1).
	MaxPerText = 3
	// MaxPoll bounds one owner_question_status wait (PQ3), as the guest
	// plane's own /owner/next poll is bounded.
	MaxPoll = 25 * time.Second
	// DefaultAgedAfter is how long a question waits unsent before its
	// text may go ahead of a waiting approval batch (PQ5; Config.Reserve).
	DefaultAgedAfter = time.Hour

	MaxText = 200 // runes
	// MaxRendered is the longest owner text a question may render to, in
	// bytes: control.MaxText (459) less owner.AgentPrefix ("Agent: "),
	// which Notify adds, so Fit never cuts off the default or the
	// deadline (owner/question_test.go pins both).
	MaxRendered = 452
	MaxDefault  = 80
	MaxChoices  = 4
	MaxChoice   = 40
	MaxAnswer   = 480
)

// ErrTooMany: the asker, or the box, has as many open questions as allowed.
var ErrTooMany = errors.New("question: too many open questions; wait for one to be answered or to lapse")

// ErrNotFound: no question by that request ID for this asker.
var ErrNotFound = errors.New("question: no such question")

// ErrConflict: the request ID was already used for another question.
var ErrConflict = errors.New("question: request ID already used for a different question")

// State is where a question stands.
type State string

const (
	// Held: not texted yet (pacing, quiet hours, no modem, or the clock is
	// restricted), or texted but the clock is restricted, so the deadline
	// is not running.
	Held State = "held"
	// Waiting: texted; the deadline is running.
	Waiting State = "waiting"
	// Answered: the owner replied in time.
	Answered State = "answered"
	// Defaulted: no reply by the deadline; the default stands.
	Defaulted State = "defaulted"
	// NotAsked: still unsent when the asker's ask-by time passed, so the
	// owner never saw it (PQ2).
	NotAsked State = "not_asked"
)

// Spec is what a guest asks.
type Spec struct {
	Text    string
	Default string
	// Choices, when set, are the only answers (at most MaxChoices); the
	// default must be one of them.
	Choices []string
	// Wait is how long after the owner is texted the default takes over.
	// It is clamped to [MinWait, MaxWait].
	Wait time.Duration
	// AskWithin, when set, is how long after asking the question may
	// still be texted; past it, an unsent question closes NotAsked (PQ2).
	// It is clamped to [MinWait, MaxWait].
	AskWithin time.Duration
}

// Status is what the asker learns.
type Status struct {
	ID    string // the tag the owner replies with, e.g. "Q4"
	State State
	// Answer is the owner's answer (FromOwner) or the default.
	Answer    string
	FromOwner bool
	// Late is an owner reply that came after the default had been taken.
	Late     string
	Default  string
	Deadline time.Time // zero unless the deadline is running
	Reason   string
}

// Config configures a Book.
type Config struct {
	// Send texts the owner. The wiring passes owner.Channel.Notify: the
	// question is agent-written, so it goes out behind the agent prefix,
	// with secret-shaped text replaced (CH-19). Required.
	Send func(text string) error
	// Now is the time for deadlines: clock.Guard.Now once P2-9 lands. An
	// error (the guard's ErrRestricted) holds every question: nothing is
	// texted and nothing lapses until time can be trusted again (TIM-1).
	// Required.
	Now func(context.Context) (time.Time, error)
	// Reveal raises the reading machine's label to private before it is
	// given text the owner wrote (REV-5). An error withholds the answer.
	// Nil withholds every owner answer.
	Reveal func(machine string) error
	// Quiet reports the owner's quiet hours: questions wait to be texted
	// until they end (CH-15). Nil: never quiet.
	Quiet func(time.Time) bool
	// Path keeps questions and pending digest lines across restarts
	// (0600). Empty keeps nothing.
	Path string
	// Location renders times in texts; nil means time.Local.
	Location *time.Location
	// Hidden reports whether Send would withhold the text as secret-shaped
	// (owner.SecretShaped). Such a question is refused at Ask, since the
	// owner would see only a pointer and it would still default. Nil:
	// nothing is.
	Hidden func(string) bool
	// ApprovalsOpen reports whether the owner channel has an approval
	// request open. An untagged reply answers the only open question only
	// when none is, so a bare reply meant for a request never lands here.
	// Nil: untagged replies are never answers.
	ApprovalsOpen func() bool
	// Reserve takes one text of the owner channel's CH-15 budget, shared
	// with approval requests, just before a question is texted; false
	// holds the question (Q3, UX-71-1). The wiring passes the gate's
	// Reserve, which refuses while an approval request waits to be sent
	// and counts the text in the same step. aged is set when the text's
	// first question has waited AgedAfter unsent: the gate then lets it
	// ahead of a waiting batch, at most once an hour (PQ5). Nil:
	// questions are paced alone, by SendsPerHour.
	Reserve func(aged bool) bool
	// Mono reads a monotonic clock (any origin). While Now is restricted,
	// a texted question's wait is counted on it, so a restriction never
	// stretches a deadline the owner was given (PQ4). Nil: the process's
	// monotonic clock.
	Mono func() time.Duration
	// Logf records store failures. Nil: discarded.
	Logf func(format string, args ...any)

	MinWait, MaxWait  time.Duration
	PerAsker, MaxOpen int
	SendsPerHour      int
	WaitersPerMachine int
	RestartGrace      time.Duration
	Keep              time.Duration
	// AgedAfter: a question held this long since it was asked leads the
	// next text and may go ahead of a waiting approval batch (PQ5).
	AgedAfter time.Duration
}

type entry struct {
	ID      string        `json:"id"`
	Asker   string        `json:"asker"`
	Req     string        `json:"req"`
	Text    string        `json:"text"`
	Default string        `json:"default"`
	Choices []string      `json:"choices,omitempty"`
	Wait    time.Duration `json:"wait"`
	// AskWithin is the asker's ask-by, counted from Asked: the first
	// trusted time after the question was asked (PQ2).
	AskWithin time.Duration `json:"ask_within,omitempty"`
	Asked     time.Time     `json:"asked,omitempty"`

	State State `json:"state"`
	// Texted is set when the question's text went out; Sent and Deadline
	// stay zero for a text sent while the clock was restricted until the
	// next trusted tick dates them (PQ4).
	Texted    bool      `json:"texted,omitempty"`
	Sent      time.Time `json:"sent,omitempty"`
	Deadline  time.Time `json:"deadline,omitempty"`
	Closed    time.Time `json:"closed,omitempty"`
	Answer    string    `json:"answer,omitempty"`
	FromOwner bool      `json:"from_owner,omitempty"`
	Late      string    `json:"late,omitempty"`

	// sentMono is Mono when the question was texted (monoSet), and
	// askedMono when it was asked (askMono). Monotonic time does not
	// survive a restart, so a loaded question takes the time of loading:
	// its wait and its age never run short.
	sentMono, askedMono time.Duration
	monoSet, askMono    bool
	// askLoaded: askedMono is the time of loading, which understates the
	// age, so a restricted clock cannot tell the ask-by (PQ2).
	askLoaded bool
}

// texted reports whether e's text went out (Sent, from files written
// before Texted, or Texted).
func (e *entry) texted() bool { return e.Texted || !e.Sent.IsZero() }

func (e *entry) open() bool { return e.State == Held || e.State == Waiting }

// Open reports a question held or waiting for the owner: the sleeper does
// not stop the agent then (PE7 condition 2).
func (b *Book) Open() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, e := range b.qs {
		if e.open() {
			return true
		}
	}
	return false
}

// dueLocked reports whether e may be texted: held, never sent, and not
// past its ask-by. While the clock is restricted the ask-by is read on the
// monotonic clock, and a question whose ask-by cannot be read that way
// (asked before a restart) waits for trusted time (L3 MUST on #125).
func (b *Book) dueLocked(e *entry, now time.Time, trusted bool, m time.Duration) bool {
	if e.State != Held || e.texted() || b.askByPassed(e, now, trusted, m) {
		return false
	}
	return trusted || e.AskWithin == 0 || e.askMono && !e.askLoaded
}

// askByPassed reports whether e, unsent, is past its ask-by: on the
// monotonic clock from the ask, or on trusted time from Asked.
func (b *Book) askByPassed(e *entry, now time.Time, trusted bool, m time.Duration) bool {
	if e.AskWithin == 0 {
		return false
	}
	if e.askMono && !e.askLoaded && m-e.askedMono >= e.AskWithin {
		return true
	}
	return trusted && e.pastAskBy(now)
}

func (e *entry) pastAskBy(now time.Time) bool {
	return e.AskWithin > 0 && !e.Asked.IsZero() && !now.Before(e.Asked.Add(e.AskWithin))
}

// tagged reports whether e's tag means something to the owner: it is
// open, or it was texted. A question closed without a text never showed
// its tag, so the tag is free again (PQ2).
func (e *entry) tagged() bool { return e.open() || e.texted() }

type file struct {
	Next      int      `json:"next"`
	Questions []*entry `json:"questions"`
	Digest    []string `json:"digest"`
	Refused   int      `json:"refused,omitempty"`
	// NotAskedLines and NotAskedMore count not-asked digest lines pending
	// and those past maxNotAskedLines, which the digest only counts.
	NotAskedLines int    `json:"not_asked_lines,omitempty"`
	NotAskedMore  int    `json:"not_asked_more,omitempty"`
	Sends         []send `json:"sends,omitempty"`
}

// send is one owner text, kept an hour for pacing (CH-15). Others are
// the askers of further questions that shared it (PQ1).
type send struct {
	At     time.Time `json:"at"` // zero for a text sent while restricted
	Asker  string    `json:"asker"`
	Others []string  `json:"others,omitempty"`
	// mono is Mono at the text, or at loading (monoSet), so pacing holds
	// while the clock is restricted (PQ4).
	mono    time.Duration
	monoSet bool
}

// Book holds the box's questions.
type Book struct {
	cfg    Config
	sendMu sync.Mutex // one sender at a time, so no question is texted twice
	mu     sync.Mutex
	qs     []*entry
	next   int
	digest []string
	// refused counts answers refused as code- or key-shaped since the last
	// digest: a guard hit the owner should see (security R1 on #71).
	refused int
	// notAskedLines are the not-asked lines pending in digest; past
	// maxNotAskedLines, notAskedMore counts the rest.
	notAskedLines, notAskedMore int
	sends                       []send
	// loaded is set when questions came from disk; grace, set at the first
	// trusted tick after that, is when lapsing resumes, so owner replies
	// the carrier queued while the box was down arrive first.
	loaded bool
	grace  time.Time
	// changed is closed, and replaced, whenever a question changes state,
	// waking owner_question_status waits (PQ3); waiters counts them by
	// machine.
	changed chan struct{}
	waiters map[string]int
}

// New opens a Book, loading Config.Path if it exists.
func New(cfg Config) (*Book, error) {
	if cfg.Send == nil || cfg.Now == nil {
		return nil, errors.New("question: Send and Now are required")
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	defi := func(n *int, v int) {
		if *n <= 0 {
			*n = v
		}
	}
	def(&cfg.MinWait, DefaultMinWait)
	def(&cfg.MaxWait, DefaultMaxWait)
	def(&cfg.RestartGrace, DefaultRestartGrace)
	def(&cfg.Keep, DefaultKeep)
	def(&cfg.AgedAfter, DefaultAgedAfter)
	defi(&cfg.PerAsker, DefaultPerAsker)
	defi(&cfg.MaxOpen, DefaultMaxOpen)
	defi(&cfg.SendsPerHour, DefaultSendsPerHour)
	defi(&cfg.WaitersPerMachine, DefaultWaitersPerMachine)
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Mono == nil {
		origin := time.Now()
		cfg.Mono = func() time.Duration { return time.Since(origin) }
	}
	// Tags are held while their question is kept and was texted (a
	// question closed unsent frees its tag at once). At most SendsPerHour
	// texts an hour carry at most MaxPerText questions each, so keeping
	// them for less than tags/(SendsPerHour*MaxPerText) hours means a tag
	// is always free for an asker under its open cap (P3-8 Q5).
	// Open questions hold tags too, and a question texted in the hour
	// before the oldest kept one closes inside the window, hence the
	// margins (S1 on #117).
	if maxKeep := time.Duration((numTags-2*cfg.MaxOpen)/(cfg.SendsPerHour*MaxPerText)-1) * time.Hour; cfg.Keep > maxKeep {
		cfg.Keep = maxKeep
	}
	b := &Book{cfg: cfg}
	if cfg.Path == "" {
		return b, nil
	}
	raw, err := os.ReadFile(cfg.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		var f file
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("question: %s: %v", cfg.Path, err)
		}
		b.qs, b.next, b.digest, b.sends, b.refused = f.Questions, f.Next, f.Digest, f.Sends, f.Refused
		b.notAskedLines, b.notAskedMore = f.NotAskedLines, f.NotAskedMore
		b.loaded = len(b.qs) > 0
		m := cfg.Mono()
		for _, e := range b.qs {
			if e.State == Held && !e.texted() {
				e.askedMono, e.askMono, e.askLoaded = m, true, true
			}
			if e.State == Waiting && e.Deadline.IsZero() {
				e.sentMono, e.monoSet = m, true // texted while restricted
			}
		}
		for i := range b.sends {
			b.sends[i].mono, b.sends[i].monoSet = m, true
		}
	}
	return b, nil
}

// persist writes the book through. Called with mu held.
func (b *Book) persist() error {
	if b.cfg.Path == "" {
		return nil
	}
	raw, err := json.Marshal(file{Next: b.next, Questions: b.qs, Digest: b.digest, Sends: b.sends, Refused: b.refused,
		NotAskedLines: b.notAskedLines, NotAskedMore: b.notAskedMore})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(b.cfg.Path), ".questions-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), b.cfg.Path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(b.cfg.Path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// save persists after a change that has already taken effect (a text
// sent, a lapse): a failure is logged, and a restart may repeat it.
func (b *Book) save(what string) {
	if err := b.persist(); err != nil {
		b.cfg.Logf("question: save after %s: %v", what, err)
	}
}

// flatten makes guest or owner text one line of printable characters, so
// a question cannot lay out what looks like a broker template.
func flatten(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func (b *Book) normalize(s Spec) (Spec, error) {
	out := Spec{Text: flatten(s.Text), Default: flatten(s.Default), Wait: s.Wait, AskWithin: s.AskWithin}
	switch n := utf8.RuneCountInString(out.Text); {
	case n == 0:
		return out, errors.New("question: the question is empty")
	case n > MaxText:
		return out, fmt.Errorf("question: the question is longer than %d characters", MaxText)
	}
	switch n := utf8.RuneCountInString(out.Default); {
	case n == 0:
		return out, errors.New("question: a default is required")
	case n > MaxDefault:
		return out, fmt.Errorf("question: the default is longer than %d characters", MaxDefault)
	}
	if out.Wait <= 0 {
		return out, errors.New("question: a wait is required")
	}
	out.Wait = min(max(out.Wait, b.cfg.MinWait), b.cfg.MaxWait)
	if out.AskWithin < 0 {
		return out, errors.New("question: ask-by must be positive")
	}
	if out.AskWithin > 0 {
		out.AskWithin = min(max(out.AskWithin, b.cfg.MinWait), b.cfg.MaxWait)
	}
	if len(s.Choices) > MaxChoices {
		return out, fmt.Errorf("question: more than %d choices", MaxChoices)
	}
	found := len(s.Choices) == 0
	for _, c := range s.Choices {
		c = flatten(c)
		if w := strings.Fields(squeezeAll(c)); len(w) > 0 && controlWords[strings.ToUpper(w[0])] {
			return out, errors.New("question: a choice cannot be an owner-channel word (STOP, YES, NO, RUN...), since the channel takes it when sent alone; use words like \"go ahead\" or \"wait\"")
		}
		if c == "" || utf8.RuneCountInString(c) > MaxChoice {
			return out, fmt.Errorf("question: each choice must be 1 to %d characters", MaxChoice)
		}
		for _, o := range out.Choices {
			if strings.EqualFold(o, c) {
				return out, errors.New("question: choices repeat")
			}
		}
		if strings.EqualFold(c, out.Default) {
			out.Default, found = c, true
		}
		out.Choices = append(out.Choices, c)
	}
	if !found {
		return out, errors.New("question: the default must be one of the choices")
	}
	for _, t := range append([]string{out.Text, out.Default}, out.Choices...) {
		if codeShaped(t) {
			return out, errors.New("question: no 6 to 8 digit numbers; they read as codes")
		}
		if tagShape.MatchString(t) {
			return out, errors.New("question: no question tags (like Q104); the owner's answer to one question must never be steered to another")
		}
		if replyShape.MatchString(t) {
			return out, errors.New("question: no owner-channel replies (YES, NO, UNDO, RESUME... and an ID or code)")
		}
		if credWords.MatchString(t) || credWords.MatchString(squeeze(t)) {
			return out, errors.New("question: no questions about codes, PINs, passwords, keys or the Owner Card; the agent never needs them")
		}
	}
	q := &entry{ID: "Q999", Text: out.Text, Default: out.Default, Choices: out.Choices}
	text := b.renderBy(q, "by Mon 15:04")
	if t := b.renderBy(q, "within "+waitWords(out.Wait)); len(t) > len(text) {
		text = t
	}
	if len(text) > MaxRendered {
		return out, fmt.Errorf("question: the question, choices and default are too long for one text (%d bytes, at most %d)", len(text), MaxRendered)
	}
	if b.cfg.Hidden != nil && b.cfg.Hidden(text) {
		return out, errors.New("question: it reads as carrying a secret, so the owner would not see it")
	}
	return out, nil
}

// squeezeAll turns everything but letters and digits into spaces, as the
// owner channel splits a message into words (owner fields): "(run)" and
// "yes, please" start with a channel word.
func squeezeAll(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return ' '
	}, s)
}

// squeeze drops punctuation inside words ("pass-word", "P.I.N."), so the
// credential words match through it. The list is a backstop: a question
// carries no authority whatever it says (Q8), and answers are filtered.
func squeeze(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) {
			return r
		}
		return -1
	}, s)
}

// credWords are words that only a question fishing for a credential needs
// (security C2 on #71). The agent never needs a code, PIN, password,
// recovery key or anything on the Owner Card, so no question may name one.
var credWords = regexp.MustCompile(`(?i)\b(codes?|otps?|pins?|passwords?|passphrases?|recovery|seeds?|grids?|cells?|cards?|2fa|verification|authenticators?)\b`)

// keyShaped reports text shaped like part of an Owner Card recovery key
// (security C1 on #71): split on anything but letters and digits, two or
// more five-symbol groups, or one run of ten or more, of card-alphabet
// symbols mixing letters and digits.
func keyShaped(s string) bool {
	groups := 0
	for _, w := range strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if !cardMixed(w) {
			continue
		}
		if len(w) >= 10 {
			return true
		}
		if len(w) == 5 {
			if groups++; groups >= 2 {
				return true
			}
		}
	}
	return false
}

// cardMixed reports whether w is all card-alphabet symbols and mixes
// letters and digits, as most groups of a random key do and words do not.
func cardMixed(w string) bool {
	letter, digit := false, false
	for _, r := range strings.ToUpper(w) {
		if !strings.ContainsRune(cardAlphabet, r) {
			return false
		}
		if r >= '0' && r <= '9' {
			digit = true
		} else {
			letter = true
		}
	}
	return letter && digit
}

// cardAlphabet is the Owner Card's symbol set (card.Alphabet).
const cardAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// controlWords are the owner channel's whole-message words (CH-11, and
// the channel's own replies). Sent alone they go to the channel, never to
// a question, so no choice may be one (#71 L3): a choice is what the owner
// is invited to send. A default is not; the owner answers with the tag
// ("Q104 no"), which the channel never takes.
var controlWords = map[string]bool{
	"STOP": true, "STATUS": true, "HELP": true, "YES": true, "NO": true, "UNDO": true, "MORE": true,
	"PUBLIC": true, "RUN": true, "RESUME": true, "UNLOCK": true, "PAUSE": true, "REVOKE": true,
}

// tagShape is a question tag. Questions from several lineages can share a
// text (PQ1), so a question naming a tag could steer the owner's answer
// to another lineage's question (security F1 on #117, CH-12, Q1).
var tagShape = regexp.MustCompile(`(?i)\bq[1-9][0-9]{2}\b`)

// replyShape is an owner-channel reply word with an ID or code after it:
// a question must not hand the owner a reply to copy (CH-12).
var replyShape = regexp.MustCompile(`(?i)\b(yes|no|undo|more|resume|unlock|pause|revoke|run)\b[^a-z0-9]*([a-z][0-9]{1,4}|[0-9]{4,})\b`)

// codeShaped reports a run of 6 or more digits, other than a phone-shaped
// one (10 or 11 digits, or 10 to 13 after a "+"), any Unicode digits counted,
// with digit groups joined across up to maxJoin separators ("482 913",
// "4-8-2-9-1-3"), as owner.SecretShaped does. A run is excused only when
// the whole run, exactly, is a strict date or a list of clock times
// (benign): when in doubt, refuse.
func codeShaped(s string) bool {
	start, end, n, gap := -1, 0, 0, 0
	flush := func() bool {
		intl := start > 0 && s[start-1] == '+'
		phone := n == 10 || n == 11 || intl && n >= 10 && n <= 13 // E.164 is at most 15 with the country code; 13 covers most
		hit := n >= 6 && !phone && !benign(s[start:end])
		start, n, gap = -1, 0, 0
		return hit
	}
	for i, r := range s {
		switch {
		case unicode.IsDigit(r):
			if n == 0 {
				start = i
			}
			n++
			gap = 0
			end = i + utf8.RuneLen(r)
		case n > 0 && gap < maxJoin && !unicode.IsLetter(r):
			gap++ // a short run of separators joins two groups
		default:
			if n > 0 && flush() {
				return true
			}
		}
	}
	return n > 0 && flush()
}

// Strict shapes a digit run may be and not be a code (#71 L3): clock times
// alone or in a list ("9:30, 10:00"), and dates with a four-digit year and
// real day and month ranges ("05/10/2026", "2026-10-05"), or a season
// ("2026/27", the next year). Amounts are not excused: "£1,250.00" is
// refused, and the owner writes it another way ("1250 pounds").
var (
	clockList = regexp.MustCompile(`^([01]?[0-9]|2[0-3]):[0-5][0-9](( ?[,–-] ?| )([01]?[0-9]|2[0-3]):[0-5][0-9])*$`)
	clockAt   = regexp.MustCompile(`([0-9]{1,2}):([0-9]{2})`)
	years     = regexp.MustCompile(`^((?:19|20)[0-9]{2}) ?[–-] ?((?:19|20)[0-9]{2})$`)
	dmy       = regexp.MustCompile(`^(0?[1-9]|[12][0-9]|3[01])([/.-])(0?[1-9]|[12][0-9]|3[01])([/.-])(19|20)[0-9]{2}$`)
	iso       = regexp.MustCompile(`^(19|20)[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$`)
	season    = regexp.MustCompile(`^((?:19|20)[0-9]{2})/([0-9]{2})$`)
)

func benign(run string) bool {
	if iso.MatchString(run) {
		return true
	}
	if clockList.MatchString(run) {
		// Two or more times pass only as people write them: on the five
		// minutes and ascending ("9:30, 10:00"). "4:28, 9:13" could be any
		// code (#71 L3).
		ts := clockAt.FindAllStringSubmatch(run, -1)
		if len(ts) == 1 {
			return true
		}
		last := -1
		for _, t := range ts {
			h, _ := strconv.Atoi(t[1])
			m, _ := strconv.Atoi(t[2])
			if m%5 != 0 || h*60+m <= last {
				return false
			}
			last = h*60 + m
		}
		return true
	}
	if m := years.FindStringSubmatch(run); m != nil {
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		return a < b
	}
	if m := dmy.FindStringSubmatch(run); m != nil {
		// Day and month in either order, but one of them is a month.
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[3])
		return m[2] == m[4] && (a <= 12 || b <= 12)
	}
	if m := season.FindStringSubmatch(run); m != nil {
		y, _ := strconv.Atoi(m[1])
		yy, _ := strconv.Atoi(m[2])
		return (y+1)%100 == yy
	}
	return false
}

// maxJoin is the longest run of separators (anything but a letter or a
// digit) that joins two digit groups: "482 913", "482/913", "482:913",
// "4, 8, 2, 9, 1, 3".
const maxJoin = 3

func same(e *entry, s Spec) bool {
	if e.Text != s.Text || e.Default != s.Default || e.Wait != s.Wait || e.AskWithin != s.AskWithin || len(e.Choices) != len(s.Choices) {
		return false
	}
	for i := range e.Choices {
		if e.Choices[i] != s.Choices[i] {
			return false
		}
	}
	return true
}

// Ask records a question from asker (the guest's lineage) under its own
// request ID, and texts it if pacing allows. Asking again with the same
// request ID and question returns the same question.
func (b *Book) Ask(ctx context.Context, asker, req string, s Spec) (Status, error) {
	if asker == "" || req == "" {
		return Status{}, errors.New("question: asker and request ID are required")
	}
	s, err := b.normalize(s)
	if err != nil {
		return Status{}, err
	}
	now, clockErr := b.cfg.Now(ctx)
	b.mu.Lock()
	if e := b.findLocked(asker, req); e != nil {
		b.mu.Unlock()
		if !same(e, s) {
			return Status{}, ErrConflict
		}
		return b.Status(ctx, asker, req, "")
	}
	mine, all := 0, 0
	for _, e := range b.qs {
		if e.open() {
			all++
			if e.Asker == asker {
				mine++
			}
		}
	}
	if mine >= b.cfg.PerAsker || all >= b.cfg.MaxOpen {
		b.mu.Unlock()
		return Status{}, ErrTooMany
	}
	id := b.allocLocked()
	if id == "" {
		b.mu.Unlock()
		return Status{}, ErrTooMany
	}
	e := &entry{ID: id, Asker: asker, Req: req, Text: s.Text, Default: s.Default, Choices: s.Choices, Wait: s.Wait,
		AskWithin: s.AskWithin, State: Held}
	if clockErr == nil {
		e.Asked = now // else the first trusted tick sets it
	}
	e.askedMono, e.askMono = b.cfg.Mono(), true
	b.qs = append(b.qs, e)
	if err := b.persist(); err != nil {
		b.qs = b.qs[:len(b.qs)-1]
		b.mu.Unlock()
		return Status{}, err
	}
	b.mu.Unlock()
	b.sendDue(ctx)
	return b.Status(ctx, asker, req, "")
}

// Tags are Q100 to Q999: four characters, so never an approval request
// ID, which is a letter and one or two digits (owner newIDLocked, CH-12);
// "YES Q104" is not an approval reply and "Q104 yes" is not a channel word.
const (
	firstTag = 100
	numTags  = 900
)

// allocLocked returns the next free tag, skipping any still known (open,
// or closed within Keep), or "" when none is free.
func (b *Book) allocLocked() string {
	used := map[string]bool{}
	for _, e := range b.qs {
		if e.tagged() {
			used[e.ID] = true
		}
	}
	if b.next < firstTag {
		b.next = firstTag - 1
	}
	for i := 0; i < numTags; i++ {
		b.next = firstTag + (b.next-firstTag+1+numTags)%numTags
		if id := "Q" + strconv.Itoa(b.next); !used[id] {
			return id
		}
	}
	return ""
}

func (b *Book) findLocked(asker, req string) *entry {
	for _, e := range b.qs {
		if e.Asker == asker && e.Req == req {
			return e
		}
	}
	return nil
}

func (b *Book) byIDLocked(id string) *entry {
	for _, e := range b.qs {
		if e.tagged() && strings.EqualFold(e.ID, id) {
			return e
		}
	}
	return nil
}

// Status reports asker's question by request ID. Before it returns text
// the owner wrote, it raises machine's label (Config.Reveal).
func (b *Book) Status(ctx context.Context, asker, req, machine string) (Status, error) {
	now, clockErr := b.cfg.Now(ctx)
	b.mu.Lock()
	e := b.findLocked(asker, req)
	if e == nil {
		b.mu.Unlock()
		return Status{}, ErrNotFound
	}
	st := Status{ID: e.ID, State: e.State, Default: e.Default, Late: e.Late}
	counting := e.State == Waiting && e.monoSet // the wait runs on while restricted (PQ4)
	switch e.State {
	case Held:
		st.Reason = "not texted yet (pacing or quiet hours); the deadline starts when the owner is texted"
	case Waiting:
		st.Deadline = e.Deadline
		if st.Deadline.IsZero() && clockErr == nil {
			st.Deadline = now.Add(e.Wait - (b.cfg.Mono() - e.sentMono)) // texted while restricted (PQ4)
		}
	case Answered:
		st.Answer, st.FromOwner = e.Answer, true
	case Defaulted:
		st.Answer = e.Default
	case NotAsked:
		st.Reason = "not texted by its ask-by time (pacing, quiet hours or the clock check), so the owner never saw it"
	}
	b.mu.Unlock()
	switch {
	case clockErr != nil && counting:
		st.Reason = "the box clock is being checked; the wait the owner was given still runs"
	case clockErr != nil && (st.State == Held || st.State == Waiting):
		st.State, st.Deadline = Held, time.Time{}
		st.Reason = "the box clock is being checked; the default waits until it is"
	}
	if st.FromOwner || st.Late != "" {
		if machine == "" {
			// Ask's own status: no machine to raise, so no owner text.
			st.Answer, st.Late = "", ""
			if st.FromOwner {
				st.Reason = "answered; read it with the status tool"
			}
		} else if b.cfg.Reveal == nil {
			return Status{}, errors.New("question: cannot reveal the owner's answer")
		} else if err := b.cfg.Reveal(machine); err != nil {
			return Status{}, fmt.Errorf("question: machine label: %w", err)
		}
	}
	return st, nil
}

// sendDue texts held questions, oldest first, while it is not quiet hours
// and the hourly budget allows (CH-15). One text carries up to MaxPerText
// questions that fit in it together (PQ1), so the budget counts texts,
// not questions. A question's wait starts when its text is sent; a failed
// text leaves them all held. While the clock is restricted, texts still
// go out, giving the wait ("within 2 hours") instead of a clock time, and
// pacing and the wait run on the monotonic clock (PQ4); with quiet hours
// configured nothing is texted then, since they cannot be told.
func (b *Book) sendDue(ctx context.Context) {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	for {
		now, err := b.cfg.Now(ctx)
		trusted := err == nil
		if b.cfg.Quiet != nil && (!trusted || b.cfg.Quiet(now)) {
			return
		}
		m := b.cfg.Mono()
		b.mu.Lock()
		keep := b.sends[:0]
		recent := map[string]bool{}
		for _, t := range b.sends {
			if b.withinHour(t, now, trusted, m) {
				keep = append(keep, t)
				recent[t.Asker] = true
				for _, a := range t.Others {
					recent[a] = true
				}
			}
		}
		b.sends = keep
		// Oldest first, but an asker texted in the last hour waits behind
		// one that was not, so one lineage cannot take the whole budget;
		// a question held AgedAfter goes first (PQ5).
		var batch []*entry
		if len(b.sends) < b.cfg.SendsPerHour {
			for tier := range 3 {
				for _, q := range b.qs {
					if !b.dueLocked(q, now, trusted, m) {
						continue
					}
					t := 2
					switch {
					case b.heldFor(q, now, trusted, m) >= b.cfg.AgedAfter:
						t = 0
					case !recent[q.Asker]:
						t = 1
					}
					if t == tier {
						batch = append(batch, q)
					}
				}
			}
		}
		if len(batch) == 0 {
			b.mu.Unlock()
			return
		}
		by := func(q *entry) string {
			if trusted {
				return "by " + b.clock(now, now.Add(q.Wait))
			}
			return "within " + waitWords(q.Wait)
		}
		aged := b.heldFor(batch[0], now, trusted, m) >= b.cfg.AgedAfter
		// The first goes alone if need be; the rest join while the text
		// still fits and is not withheld as secret-shaped (CH-19).
		text := b.renderBy(batch[0], by(batch[0]))
		n := 1
		for _, q := range batch[1:] {
			if n == MaxPerText {
				break
			}
			t := text + " " + b.renderBy(q, by(q))
			if len(t) > MaxRendered || b.cfg.Hidden != nil && b.cfg.Hidden(t) {
				continue
			}
			text, batch[n] = t, q
			n++
		}
		batch = batch[:n]
		b.mu.Unlock()
		// The shared budget is reserved outside b.mu, and sendMu keeps it
		// to one text at a time.
		if b.cfg.Reserve != nil && !b.cfg.Reserve(aged) {
			return
		}
		if err := b.cfg.Send(text); err != nil {
			return
		}
		b.mu.Lock()
		s := send{Asker: batch[0].Asker, mono: m, monoSet: true}
		if trusted {
			s.At = now
		}
		for _, e := range batch {
			if e != batch[0] {
				s.Others = append(s.Others, e.Asker)
			}
			// How long questions wait for a text, to tune AgedAfter (PQ5).
			b.cfg.Logf("question %s texted after %s held", e.ID, b.heldFor(e, now, trusted, m).Round(time.Minute))
			if e.State == Held { // the owner may have answered meanwhile
				e.State = Waiting
				if trusted {
					e.Deadline = now.Add(e.Wait)
				}
			}
			if trusted {
				e.Sent = now
			}
			e.Texted, e.sentMono, e.monoSet = true, m, true
		}
		b.sends = append(b.sends, s)
		b.wakeLocked()
		b.save("send")
		b.mu.Unlock()
	}
}

// withinHour reports whether t counts against this hour's texts: on
// trusted time when both have one, else on the monotonic clock. A loaded
// send reads as sent at loading, so while restricted it counts for the
// hour after a restart.
func (b *Book) withinHour(t send, now time.Time, trusted bool, m time.Duration) bool {
	if trusted && !t.At.IsZero() {
		return now.Sub(t.At) < time.Hour
	}
	return !t.monoSet || m-t.mono < time.Hour
}

// heldFor is how long q has waited since it was asked: the longer of the
// monotonic reading and, with a trusted clock, Asked.
func (b *Book) heldFor(q *entry, now time.Time, trusted bool, m time.Duration) time.Duration {
	var d time.Duration
	if q.askMono {
		d = m - q.askedMono
	}
	if trusted && !q.Asked.IsZero() {
		d = max(d, now.Sub(q.Asked))
	}
	return d
}

// waitWords renders a wait for a text sent while the clock is restricted:
// "2 hours", "1 hour 30 minutes", "45 minutes". Seconds are dropped, so
// the owner is never given longer than the wait.
func waitWords(d time.Duration) string {
	unit := func(n int, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %ss", n, one)
	}
	h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
	switch {
	case h == 0:
		return unit(m, "minute")
	case m == 0:
		return unit(h, "hour")
	}
	return unit(h, "hour") + " " + unit(m, "minute")
}

// wakeLocked wakes every owner_question_status wait (PQ3).
func (b *Book) wakeLocked() {
	if b.changed != nil {
		close(b.changed)
		b.changed = nil
	}
}

func (b *Book) clock(now, t time.Time) string {
	t, now = t.In(b.cfg.Location), now.In(b.cfg.Location)
	if t.Format("2006-01-02") == now.Format("2006-01-02") {
		return t.Format("15:04")
	}
	return t.Format("Mon 15:04")
}

// renderBy is the owner's text for a question, by being "by 14:30" or,
// while the clock is restricted, "within 2 hours" (PQ4). It is sent
// through Notify, which marks it as agent text.
func (b *Book) renderBy(e *entry, by string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: %s", e.ID, e.Text)
	if len(e.Choices) > 0 {
		sb.WriteString(" Choices:")
		for i, c := range e.Choices {
			fmt.Fprintf(&sb, " %d) %s", i+1, c)
		}
		sb.WriteString(".")
	}
	fmt.Fprintf(&sb, ` Reply %s and your answer %s. No reply: it goes ahead with "%s".`, e.ID, by, e.Default)
	return sb.String()
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// lapseLocked closes e on its default and queues its digest line.
// A question texted while the clock was restricted and lapsed before it
// was trusted again has no deadline, so its line gives the wait (PQ4).
func (b *Book) lapseLocked(e *entry, now time.Time) {
	e.State, e.Closed = Defaulted, now
	by := "within " + waitWords(e.Wait)
	if !e.Deadline.IsZero() {
		by = "by " + b.clock(now, e.Deadline)
	}
	b.digest = append(b.digest, fmt.Sprintf(`%s "%s": no reply %s, so the agent went ahead with "%s".`,
		e.ID, clip(e.Text, 60), by, e.Default))
}

// maxNotAsked is how many not-asked questions are kept for status reads;
// older ones are dropped (S2 on #117). Their digest lines are bounded by
// maxNotAskedLines, past which the digest counts them.
const (
	maxNotAsked      = 32
	maxNotAskedLines = 8
)

// notAskedLocked closes e, never texted, past its ask-by (PQ2), and
// queues its digest line. The owner never saw its tag, so the line has
// none.
func (b *Book) notAskedLocked(e *entry, now time.Time) {
	e.State, e.Closed = NotAsked, now
	if b.notAskedLines >= maxNotAskedLines {
		b.notAskedMore++
		return
	}
	b.notAskedLines++
	by := "its ask-by time" // closed while restricted, or asked then
	if !now.IsZero() && !e.Asked.IsZero() {
		by = b.clock(now, e.Asked.Add(e.AskWithin))
	}
	b.digest = append(b.digest, fmt.Sprintf(`Not asked: the agent's question "%s" was held past %s (texts paced or quiet hours), so the agent went ahead without asking.`,
		clip(e.Text, 60), by))
}

// startGraceLocked starts the restart grace at the first trusted time
// after questions were loaded from disk.
func (b *Book) startGraceLocked(now time.Time) {
	if b.loaded && b.grace.IsZero() {
		b.grace = now.Add(b.cfg.RestartGrace)
	}
}

// monoLapsedLocked reports whether e's wait has run out on the monotonic
// clock (PQ4). Only a restricted clock relies on it. It needs no restart
// grace: either e was texted by this process, so no reply to it was
// queued while the box was down, or it was texted while restricted before
// a restart and its reading is the time of loading, so its whole wait,
// at least MinWait and longer than the grace, runs again from there.
func (b *Book) monoLapsedLocked(e *entry, m time.Duration) bool {
	return e.State == Waiting && e.monoSet && m-e.sentMono >= e.Wait
}

// tickRestricted lapses, on the monotonic clock, the questions whose wait
// ran out while Now is restricted (PQ4). A deadline set from a trusted
// time dates the lapse; one texted while restricted has none, and the
// next trusted tick dates its close.
func (b *Book) tickRestricted() {
	m := b.cfg.Mono()
	b.mu.Lock()
	defer b.mu.Unlock()
	changed := false
	for _, e := range b.qs {
		if b.monoLapsedLocked(e, m) {
			b.lapseLocked(e, e.Deadline)
			changed = true
		}
		if e.State == Held && !e.texted() && b.askByPassed(e, time.Time{}, false, m) {
			b.notAskedLocked(e, time.Time{}) // the next trusted tick dates its close
			changed = true
		}
	}
	if changed {
		b.wakeLocked()
		b.save("tick")
	}
}

// Tick lapses questions past their deadline, drops old closed ones, and
// texts held ones. With the clock restricted it lapses only texted
// questions whose wait ran out on the monotonic clock, and texts held
// ones with their wait instead of a time (PQ4).
func (b *Book) Tick(ctx context.Context) {
	now, err := b.cfg.Now(ctx)
	if err != nil {
		b.tickRestricted()
		b.sendDue(ctx)
		return
	}
	m := b.cfg.Mono()
	b.mu.Lock()
	b.startGraceLocked(now)
	changed := false
	keep := b.qs[:0]
	for _, e := range b.qs {
		if e.State == Waiting && e.Deadline.IsZero() {
			// Texted while restricted: date it from the monotonic clock.
			e.Sent = now.Add(-(m - e.sentMono))
			e.Deadline, changed = e.Sent.Add(e.Wait), true
		}
		if e.State == Waiting && !now.Before(e.Deadline) && !now.Before(b.grace) {
			b.lapseLocked(e, now)
			changed = true
		}
		if e.State == Held && !e.texted() {
			if e.Asked.IsZero() { // asked while the clock was restricted
				e.Asked, changed = now, true
				if e.askMono && !e.askLoaded {
					e.Asked = now.Add(-(m - e.askedMono))
				}
			}
			if b.askByPassed(e, now, true, m) {
				b.notAskedLocked(e, now)
				changed = true
			}
		}
		if !e.open() && e.Closed.IsZero() {
			e.Closed, changed = now, true // answered while the clock was restricted
		}
		if !e.open() && now.Sub(e.Closed) > b.cfg.Keep {
			changed = true
			continue
		}
		keep = append(keep, e)
	}
	b.qs = keep
	// Not-asked questions hold no tag, so the tag bound does not limit
	// them; keep only the newest maxNotAsked (S2 on #117).
	for n, i := 0, len(b.qs)-1; i >= 0; i-- {
		if b.qs[i].State != NotAsked {
			continue
		}
		if n++; n > maxNotAsked {
			b.qs = append(b.qs[:i], b.qs[i+1:]...)
			changed = true
		}
	}
	if changed {
		b.wakeLocked()
		b.save("tick")
	}
	b.mu.Unlock()
	b.sendDue(ctx)
}

// Run ticks every interval until ctx is done.
func (b *Book) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.Tick(ctx)
		}
	}
}

// TakeDigest returns and clears the digest lines for defaulted questions.
func (b *Book) TakeDigest() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := append([]string(nil), b.digest...)
	if b.refused > 0 {
		n := fmt.Sprintf("%d answers", b.refused)
		if b.refused == 1 {
			n = "1 answer"
		}
		out = append(out, n+" to the agent's questions held a code or key and were not passed on. If that was not you, reply STOP.")
	}
	if b.notAskedMore > 0 {
		out = append(out, fmt.Sprintf("Not asked: %d more of the agent's questions were held (texts paced or quiet hours), so the agent went ahead without asking.", b.notAskedMore))
	}
	if len(out) == 0 {
		return nil
	}
	digest, refused, lines, more := b.digest, b.refused, b.notAskedLines, b.notAskedMore
	b.digest, b.refused, b.notAskedLines, b.notAskedMore = nil, 0, 0, 0
	if err := b.persist(); err != nil {
		// Keep them for the next digest rather than lose them on restart.
		b.digest, b.refused, b.notAskedLines, b.notAskedMore = digest, refused, lines, more
	}
	return out
}

var (
	tagRE = regexp.MustCompile(`^[Qq]([1-9][0-9]{2})[:.,]?$`)
)

// untaggedLocked returns the only open question when it has choices and
// text is exactly one of them (UX R2 on #71): with one question open, "9:30"
// can only mean it. Anything else untagged stays chat.
func (b *Book) untaggedLocked(text string) *entry {
	var only *entry
	for _, e := range b.qs {
		if e.open() {
			if only != nil {
				return nil
			}
			only = e
		}
	}
	if only == nil || !only.texted() || b.cfg.ApprovalsOpen == nil || b.cfg.ApprovalsOpen() {
		return nil
	}
	for _, c := range only.Choices {
		if strings.EqualFold(c, text) {
			return only
		}
	}
	return nil
}

// Answer takes an owner text that starts with a question's tag ("Q4 yes")
// and returns the fixed reply. ok is false when the text is not an answer
// to a known question; the channel then treats it as chat. The wiring
// calls Answer only for text the channel would pass to the agent: from
// the owner's number, in an unlocked session, with any code already
// stripped (CH-3, CH-14).
func (b *Book) Answer(ctx context.Context, text string) (reply string, ok bool) {
	f := strings.Fields(text)
	if len(f) == 0 {
		return "", false
	}
	now, clockErr := b.cfg.Now(ctx)
	b.mu.Lock()
	defer b.mu.Unlock()
	var e *entry
	var ans string
	if tagRE.MatchString(f[0]) {
		if e = b.byIDLocked("Q" + tagRE.FindStringSubmatch(f[0])[1]); e == nil {
			return "", false
		}
		ans = flatten(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text), f[0])))
	} else if e = b.untaggedLocked(flatten(text)); e != nil {
		ans = flatten(text)
	} else {
		return "", false
	}
	for _, w := range strings.Fields(ans) {
		if m := tagRE.FindStringSubmatch(w); m != nil {
			if o := b.byIDLocked("Q" + m[1]); o != nil && o != e {
				// One answer per text, so the owner's words for one
				// question never land in another (UX-117-1).
				return fmt.Sprintf("Send one answer per question, like %s %s.", e.ID, e.Default), true
			}
		}
	}
	switch {
	case ans == "":
		return fmt.Sprintf("Add your answer after %s, like: %s %s", e.ID, e.ID, e.Default), true
	case utf8.RuneCountInString(ans) > MaxAnswer:
		return fmt.Sprintf("That answer is too long for %s. Keep it under %d characters.", e.ID, MaxAnswer), true
	case codeShaped(ans) || keyShaped(ans) || b.cfg.Hidden != nil && b.cfg.Hidden(ans):
		b.refused++
		b.save("refused answer")
		return "Codes and keys are only for the box, so that answer was not passed on. Write it another way, without codes or keys.", true
	}
	if clockErr == nil {
		b.startGraceLocked(now)
	}
	if e.State == Waiting && clockErr == nil && !now.Before(e.Deadline) && !now.Before(b.grace) {
		b.lapseLocked(e, now) // the deadline passed before the timer ran
	} else if clockErr != nil && b.monoLapsedLocked(e, b.cfg.Mono()) {
		b.lapseLocked(e, e.Deadline) // likewise, counted on the monotonic clock
	}
	switch e.State {
	case Answered:
		return fmt.Sprintf("%s was already answered: \"%s\". To change course, tell the agent.", e.ID, clip(e.Answer, 60)), true
	case Defaulted:
		if e.Late == "" {
			e.Late = ans
			b.wakeLocked()
			b.save("late answer")
		}
		at := ""
		if !e.Closed.IsZero() {
			at = " at " + b.clock(now, e.Closed)
		}
		return fmt.Sprintf("Too late for %s: the agent went ahead with \"%s\"%s. Your answer is passed to it.",
			e.ID, e.Default, at), true
	}
	if len(e.Choices) > 0 {
		pick := ""
		if n, err := strconv.Atoi(ans); err == nil && n >= 1 && n <= len(e.Choices) {
			pick = e.Choices[n-1]
		}
		for _, c := range e.Choices {
			if strings.EqualFold(c, ans) {
				pick = c
			}
		}
		if pick == "" {
			var opts []string
			for i, c := range e.Choices {
				opts = append(opts, fmt.Sprintf("%d) %s", i+1, c))
			}
			return fmt.Sprintf("%s takes one of: %s.", e.ID, strings.Join(opts, ", ")), true
		}
		ans = pick
	}
	e.State, e.Answer, e.FromOwner = Answered, ans, true
	if clockErr == nil {
		e.Closed = now
	}
	if err := b.persist(); err != nil {
		e.State, e.Answer, e.FromOwner, e.Closed = Held, "", false, time.Time{}
		if e.texted() {
			e.State = Waiting
		}
		return "Could not save your answer. Send it again.", true
	}
	b.wakeLocked()
	return fmt.Sprintf("Got it: %s answered \"%s\".", e.ID, clip(ans, 60)), true
}

// Await is Status after waiting up to d (at most MaxPoll) for asker's open
// question to change state: texted, answered, defaulted or not asked
// (PQ3), so a guest need not spend turns polling. At most
// WaitersPerMachine waits per machine are held (guest G1); past that, and
// for a closed question, it answers at once.
func (b *Book) Await(ctx context.Context, asker, req, machine string, d time.Duration) (Status, error) {
	if d = min(d, MaxPoll); d > 0 && machine != "" && b.enterWait(machine) {
		defer b.leaveWait(machine)
		timer := time.NewTimer(d)
		defer timer.Stop()
		var from State
		for {
			b.mu.Lock()
			e := b.findLocked(asker, req)
			if e == nil || !e.open() || from != "" && e.State != from {
				b.mu.Unlock()
				break
			}
			from = e.State
			if b.changed == nil {
				b.changed = make(chan struct{})
			}
			ch := b.changed
			b.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-timer.C:
			case <-ctx.Done():
			}
			break
		}
	}
	return b.Status(ctx, asker, req, machine)
}

func (b *Book) enterWait(machine string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.waiters[machine] >= b.cfg.WaitersPerMachine {
		return false
	}
	if b.waiters == nil {
		b.waiters = map[string]int{}
	}
	b.waiters[machine]++
	return true
}

func (b *Book) leaveWait(machine string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.waiters[machine]--; b.waiters[machine] <= 0 {
		delete(b.waiters, machine)
	}
}
