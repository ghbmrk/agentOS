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
	DefaultKeep         = 7 * 24 * time.Hour

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
	// Logf records store failures. Nil: discarded.
	Logf func(format string, args ...any)

	MinWait, MaxWait  time.Duration
	PerAsker, MaxOpen int
	SendsPerHour      int
	RestartGrace      time.Duration
	Keep              time.Duration
}

type entry struct {
	ID      string        `json:"id"`
	Asker   string        `json:"asker"`
	Req     string        `json:"req"`
	Text    string        `json:"text"`
	Default string        `json:"default"`
	Choices []string      `json:"choices,omitempty"`
	Wait    time.Duration `json:"wait"`

	State     State     `json:"state"`
	Sent      time.Time `json:"sent,omitempty"`
	Deadline  time.Time `json:"deadline,omitempty"`
	Closed    time.Time `json:"closed,omitempty"`
	Answer    string    `json:"answer,omitempty"`
	FromOwner bool      `json:"from_owner,omitempty"`
	Late      string    `json:"late,omitempty"`
}

func (e *entry) open() bool { return e.State == Held || e.State == Waiting }

type file struct {
	Next      int      `json:"next"`
	Questions []*entry `json:"questions"`
	Digest    []string `json:"digest"`
	Sends     []send   `json:"sends,omitempty"`
}

// send is one question text, kept an hour for pacing (CH-15).
type send struct {
	At    time.Time `json:"at"`
	Asker string    `json:"asker"`
}

// Book holds the box's questions.
type Book struct {
	cfg    Config
	sendMu sync.Mutex // one sender at a time, so no question is texted twice
	mu     sync.Mutex
	qs     []*entry
	next   int
	digest []string
	sends  []send
	// loaded is set when questions came from disk; grace, set at the first
	// trusted tick after that, is when lapsing resumes, so owner replies
	// the carrier queued while the box was down arrive first.
	loaded bool
	grace  time.Time
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
	defi(&cfg.PerAsker, DefaultPerAsker)
	defi(&cfg.MaxOpen, DefaultMaxOpen)
	defi(&cfg.SendsPerHour, DefaultSendsPerHour)
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	// Tags are held while their question is kept. Questions close only
	// after a text, so at most SendsPerHour an hour close; keeping them
	// for less than tags/SendsPerHour hours means a tag is always free
	// for an asker under its open cap (P3-8 Q5).
	if maxKeep := time.Duration((numTags-1)/cfg.SendsPerHour) * time.Hour; cfg.Keep > maxKeep {
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
		b.qs, b.next, b.digest, b.sends = f.Questions, f.Next, f.Digest, f.Sends
		b.loaded = len(b.qs) > 0
	}
	return b, nil
}

// persist writes the book through. Called with mu held.
func (b *Book) persist() error {
	if b.cfg.Path == "" {
		return nil
	}
	raw, err := json.Marshal(file{Next: b.next, Questions: b.qs, Digest: b.digest, Sends: b.sends})
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
	out := Spec{Text: flatten(s.Text), Default: flatten(s.Default), Wait: s.Wait}
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
	if len(s.Choices) > MaxChoices {
		return out, fmt.Errorf("question: more than %d choices", MaxChoices)
	}
	found := len(s.Choices) == 0
	for _, c := range s.Choices {
		c = flatten(c)
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
		if replyShape.MatchString(t) {
			return out, errors.New("question: no owner-channel replies (YES, NO, UNDO, RESUME... and an ID or code)")
		}
	}
	text := b.renderBy(&entry{ID: "Q999", Text: out.Text, Default: out.Default, Choices: out.Choices}, "Mon 15:04")
	if len(text) > MaxRendered {
		return out, fmt.Errorf("question: the question, choices and default are too long for one text (%d bytes, at most %d)", len(text), MaxRendered)
	}
	if b.cfg.Hidden != nil && b.cfg.Hidden(text) {
		return out, errors.New("question: it reads as carrying a secret, so the owner would not see it")
	}
	return out, nil
}

// replyShape is an owner-channel reply word with an ID or code after it:
// a question must not hand the owner a reply to copy (CH-12).
var replyShape = regexp.MustCompile(`(?i)\b(yes|no|undo|more|resume|unlock|pause|revoke|run)\b[^a-z0-9]*([a-z][0-9]{1,4}|[0-9]{4,})\b`)

// codeShaped reports a run of 6 to 8 digits, after folding Unicode digits
// to ASCII and joining digit groups split by spaces, dots or dashes
// ("482 913", "4-8-2-9-1-3"), as owner.SecretShaped does.
func codeShaped(s string) bool {
	var runs []int
	n, gap := 0, false
	for _, r := range s {
		switch {
		case unicode.IsDigit(r):
			n++
			gap = false
		case n > 0 && !gap && (r == ' ' || r == '.' || r == '-' || r == '\u00a0'):
			gap = true // a single separator may join two groups
		default:
			if n > 0 {
				runs = append(runs, n)
			}
			n, gap = 0, false
		}
	}
	if n > 0 {
		runs = append(runs, n)
	}
	for _, k := range runs {
		if k >= 6 && k <= 8 {
			return true
		}
	}
	return false
}

func same(e *entry, s Spec) bool {
	if e.Text != s.Text || e.Default != s.Default || e.Wait != s.Wait || len(e.Choices) != len(s.Choices) {
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
	e := &entry{ID: id, Asker: asker, Req: req, Text: s.Text, Default: s.Default, Choices: s.Choices, Wait: s.Wait, State: Held}
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
		used[e.ID] = true
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
		if strings.EqualFold(e.ID, id) {
			return e
		}
	}
	return nil
}

// Status reports asker's question by request ID. Before it returns text
// the owner wrote, it raises machine's label (Config.Reveal).
func (b *Book) Status(ctx context.Context, asker, req, machine string) (Status, error) {
	_, clockErr := b.cfg.Now(ctx)
	b.mu.Lock()
	e := b.findLocked(asker, req)
	if e == nil {
		b.mu.Unlock()
		return Status{}, ErrNotFound
	}
	st := Status{ID: e.ID, State: e.State, Default: e.Default, Late: e.Late}
	switch e.State {
	case Held:
		st.Reason = "not texted yet (pacing or quiet hours); the deadline starts when the owner is texted"
	case Waiting:
		st.Deadline = e.Deadline
	case Answered:
		st.Answer, st.FromOwner = e.Answer, true
	case Defaulted:
		st.Answer = e.Default
	}
	b.mu.Unlock()
	if clockErr != nil && (st.State == Held || st.State == Waiting) {
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

// sendDue texts held questions, oldest first, while the clock is trusted,
// it is not quiet hours, and the hourly budget allows (CH-15). A question's
// deadline starts when its text is sent; a failed text leaves it held.
func (b *Book) sendDue(ctx context.Context) {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	for {
		now, err := b.cfg.Now(ctx)
		if err != nil || (b.cfg.Quiet != nil && b.cfg.Quiet(now)) {
			return
		}
		b.mu.Lock()
		keep := b.sends[:0]
		recent := map[string]bool{}
		for _, t := range b.sends {
			if now.Sub(t.At) < time.Hour {
				keep = append(keep, t)
				recent[t.Asker] = true
			}
		}
		b.sends = keep
		// Oldest first, but an asker texted in the last hour waits behind
		// one that was not, so one lineage cannot take the whole budget.
		var e *entry
		if len(b.sends) < b.cfg.SendsPerHour {
			for _, q := range b.qs {
				if q.State == Held && q.Sent.IsZero() && (e == nil || recent[e.Asker] && !recent[q.Asker]) {
					e = q
				}
			}
		}
		if e == nil {
			b.mu.Unlock()
			return
		}
		deadline := now.Add(e.Wait)
		text := b.render(e, now, deadline)
		b.mu.Unlock()
		if err := b.cfg.Send(text); err != nil {
			return
		}
		b.mu.Lock()
		b.sends = append(b.sends, send{At: now, Asker: e.Asker})
		if e.State == Held { // the owner may have answered meanwhile
			e.State, e.Sent, e.Deadline = Waiting, now, deadline
		} else {
			e.Sent = now
		}
		b.save("send")
		b.mu.Unlock()
	}
}

func (b *Book) clock(now, t time.Time) string {
	t, now = t.In(b.cfg.Location), now.In(b.cfg.Location)
	if t.Format("2006-01-02") == now.Format("2006-01-02") {
		return t.Format("15:04")
	}
	return t.Format("Mon 15:04")
}

// render is the owner's text for a question. It is sent through Notify,
// which marks it as agent text.
func (b *Book) render(e *entry, now, deadline time.Time) string {
	return b.renderBy(e, b.clock(now, deadline))
}

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
	fmt.Fprintf(&sb, ` Reply "%s" and your answer by %s. With no reply it goes ahead with "%s".`, e.ID, by, e.Default)
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
func (b *Book) lapseLocked(e *entry, now time.Time) {
	e.State, e.Closed = Defaulted, now
	b.digest = append(b.digest, fmt.Sprintf(`%s "%s": no reply by %s, so the agent went ahead with "%s".`,
		e.ID, clip(e.Text, 60), b.clock(now, e.Deadline), e.Default))
}

// startGraceLocked starts the restart grace at the first trusted time
// after questions were loaded from disk.
func (b *Book) startGraceLocked(now time.Time) {
	if b.loaded && b.grace.IsZero() {
		b.grace = now.Add(b.cfg.RestartGrace)
	}
}

// Tick lapses questions past their deadline, drops old closed ones, and
// texts held ones. With the clock restricted it does nothing.
func (b *Book) Tick(ctx context.Context) {
	now, err := b.cfg.Now(ctx)
	if err != nil {
		return
	}
	b.mu.Lock()
	b.startGraceLocked(now)
	changed := false
	keep := b.qs[:0]
	for _, e := range b.qs {
		if e.State == Waiting && !now.Before(e.Deadline) && !now.Before(b.grace) {
			b.lapseLocked(e, now)
			changed = true
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
	if changed {
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
	out := b.digest
	if len(out) == 0 {
		return nil
	}
	b.digest = nil
	if err := b.persist(); err != nil {
		b.digest = out // keep them for the next digest rather than lose them on restart
		return append([]string(nil), out...)
	}
	return out
}

var (
	tagRE = regexp.MustCompile(`^[Qq]([1-9][0-9]{2})[:.,]?$`)
)

// Answer takes an owner text that starts with a question's tag ("Q4 yes")
// and returns the fixed reply. ok is false when the text is not an answer
// to a known question; the channel then treats it as chat. The wiring
// calls Answer only for text the channel would pass to the agent: from
// the owner's number, in an unlocked session, with any code already
// stripped (CH-3, CH-14).
func (b *Book) Answer(ctx context.Context, text string) (reply string, ok bool) {
	f := strings.Fields(text)
	if len(f) == 0 || !tagRE.MatchString(f[0]) {
		return "", false
	}
	now, clockErr := b.cfg.Now(ctx)
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.byIDLocked("Q" + tagRE.FindStringSubmatch(f[0])[1])
	if e == nil {
		return "", false
	}
	ans := flatten(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text), f[0])))
	switch {
	case ans == "":
		return fmt.Sprintf("Add your answer after %s, like: %s %s", e.ID, e.ID, e.Default), true
	case utf8.RuneCountInString(ans) > MaxAnswer:
		return fmt.Sprintf("That answer is too long for %s. Keep it under %d characters.", e.ID, MaxAnswer), true
	case codeShaped(ans):
		return "Answers can't include a 6 to 8 digit number, since codes are only for the box. Write it another way.", true
	}
	if clockErr == nil {
		b.startGraceLocked(now)
	}
	if e.State == Waiting && clockErr == nil && !now.Before(e.Deadline) && !now.Before(b.grace) {
		b.lapseLocked(e, now) // the deadline passed before the timer ran
	}
	switch e.State {
	case Answered:
		return fmt.Sprintf("%s was already answered: \"%s\". To change course, tell the agent.", e.ID, clip(e.Answer, 60)), true
	case Defaulted:
		if e.Late == "" {
			e.Late = ans
			b.save("late answer")
		}
		return fmt.Sprintf("%s already went ahead with \"%s\" at %s, since there was no reply by then. Your answer is passed to the agent.",
			e.ID, e.Default, b.clock(now, e.Closed)), true
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
		if !e.Sent.IsZero() {
			e.State = Waiting
		}
		return "Could not save your answer. Send it again.", true
	}
	return fmt.Sprintf("Got it: %s answered \"%s\".", e.ID, clip(ans, 60)), true
}
