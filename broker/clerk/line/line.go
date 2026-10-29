// Package line is the second-line clerk (CLK-8): the keeper side of a
// calling account that texts third parties for the owner's tasks. It holds
// the account's password in a sealed slot (CLK-1), admits each `send` step
// against the key and the log (CLK-2) and against its own recipient rules,
// hands an admitted text to the line process at most once (KRN-8), signs
// only the digest challenges that send needs (sign.go, D-154 option A), and
// shapes texts to the line into untrusted items (CH-1).
//
// It runs no socket and starts no process: part b's agentos-clerk-line
// serves it on the kernel's clerk wire, and agentos-line runs the SIP stack
// (modem/sipline) on the main side. It links no SIP or SRTP stack
// (imports_test.go).
package line

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/check"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/sendrules"
)

// Name is the clerk's name in every key and step that reaches it.
const Name = "second-line"

// Label is the flow label of everything that comes in on the line
// (edgelink.LabelSecondLine, CLK-8).
const Label = "untrusted-second-line"

// Operation is one declared operation and its verb (VRB-2).
type Operation struct {
	Name string
	Verb key.Verb
}

// Operations is the clerk's declaration: texts only. Calls (`call` on
// `send`) are part d, after a speech-rendering row.
var Operations = []Operation{{Name: "text", Verb: key.Send}}

// Line is the line process as the clerk reaches it: part b's call to the
// line's uid, which sends one SIP MESSAGE (sipline.Line.Send).
type Line interface {
	Send(ctx context.Context, to, words string) error
}

// Answers a Line gives besides nil (sent) and anything else (it may have
// been sent).
var (
	// ErrNotTaken: the line took nothing (closed, not registered, the
	// number refused before a request was made), so nothing was sent.
	ErrNotTaken = errors.New("line: the line did not take the text")
	// ErrRefused: the provider answered the text with a final refusal.
	ErrRefused = errors.New("line: the provider refused the text")
)

// Refusal codes: the typed reasons Do answers with, never a value.
const (
	RUnavailable = "unavailable"    // no account set up (DEP-3)
	RUnconfirmed = "unconfirmed"    // the realm is not confirmed by the owner yet (SL3)
	RUndeclared  = "undeclared"     // not a send
	RPlanner     = "planner-number" // a number the planner supplied (KEY-2)
	RNotContact  = "not-a-contact"  // a number the clerk has no owner-created contact for
	RNotFixed    = "not-owner-fixed"
	RNeedContact = "needs-contact" // a short or premium-rate code that is not a contact
	ROwnNumber   = "own-number"    // the owner's number or one of the box's (CH-1, CH-19)
	RNotNumber   = "not-a-number"  // neither E.164 nor a digits-only short code
	RCancelled   = "cancelled"     // cancelled before the line took it
	RNotTaken    = "not-taken"
	RProvider    = "provider-refused"
	RMaybeSent   = "may-have-been-sent" // handed to the line, answer lost
)

// Contact is an owner-created contact: the only source of a number the
// clerk reads itself (CLK-8; numbers read from a cited source are a later
// row).
type Contact struct {
	Name, Number string
}

// Numbers are the numbers the line never texts: the owner's own and the
// box's owner-channel number (CH-1, CH-19). The line's own number comes from
// the account.
type Numbers struct {
	Owner, Channel string
}

// Entry is one log entry the clerk asks the kernel to write (D-154 rule 7):
// a text's transcript, or an inbound text as its untrusted item. It never
// carries the password or a digest.
type Entry struct {
	Kind  string // EntrySent, EntryMaybeSent or EntryInbound
	Idem  string
	To    string
	From  string
	Words string
	Label string
}

// Entry kinds.
const (
	EntrySent      = "sent"
	EntryMaybeSent = "may-have-been-sent"
	EntryInbound   = "inbound"
)

// Config configures a Clerk.
type Config struct {
	Anchors []key.PublicKey
	Secrets *clerk.Secrets
	Line    Line
	Numbers Numbers
	// Log hands an entry to the kernel; nil drops it.
	Log   func(Entry)
	Clock clerk.Clock
}

// state is what the clerk knows of one step, by idempotency key.
type state uint8

const (
	handed state = iota + 1 // with the line now
	sent
	maybe   // handed, its answer lost: never sent again
	notSent // this clerk saw that nothing went out; it may run again
)

// Clerk is the second-line clerk.
type Clerk struct {
	cfg  Config
	acct *Account

	// bind is the signing side (sign.go): told of each admitted send
	// before the hand-off and after it. nil without one.
	bind binder

	mu       sync.Mutex
	steps    map[string]state
	contacts map[string]bool
	fixed    map[string]bool
	sent     int
	maybe    int
	lastMain int64 // when the owner was last given MainNumberText
}

// binder is what Do tells the signing side about a send it admitted.
type binder interface {
	admit(idem, to string)
	revoke(idem string)
	refused() int
}

// New returns a clerk over cfg.Secrets' second-line slots.
func New(cfg Config) (*Clerk, error) {
	if cfg.Secrets == nil || cfg.Line == nil || len(cfg.Anchors) == 0 {
		return nil, errors.New("line: a clerk needs anchors, its secrets and a line")
	}
	return &Clerk{cfg: cfg, acct: &Account{secrets: cfg.Secrets, clock: cfg.Clock},
		steps: map[string]state{}, contacts: map[string]bool{}, fixed: map[string]bool{}}, nil
}

// Account is the clerk's account record.
func (c *Clerk) Account() *Account { return c.acct }

// SetContacts replaces the owner-created contacts, from the owner's side.
func (c *Clerk) SetContacts(cs []Contact) {
	m := map[string]bool{}
	for _, x := range cs {
		m[x.Number] = true
	}
	c.mu.Lock()
	c.contacts = m
	c.mu.Unlock()
}

// SetFixed replaces the numbers the owner fixed for the line to text, from
// the owner's side.
func (c *Clerk) SetFixed(numbers []string) {
	m := map[string]bool{}
	for _, n := range numbers {
		m[n] = true
	}
	c.mu.Lock()
	c.fixed = m
	c.mu.Unlock()
}

// Source is where the clerk reads a step's `to` from. The kernel marks every
// plan argument as the planner's (kernel.Normalize), so the clerk resolves
// the source itself, from its own owner-given records: an owner-created
// contact's exact number is the clerk's, a number the owner fixed is the
// owner's, and anything else is the planner's.
func (c *Clerk) Source(to string) key.Arg {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.contacts[to]:
		return key.Arg{Value: to, Source: key.SrcClerk}
	case c.fixed[to]:
		return key.Arg{Value: to, Source: key.SrcOwner}
	}
	return key.Arg{Value: to, Source: key.SrcPlanner}
}

// Admit is the recipient rule (CLK-8, KEY-2): "" when the line may text
// a, else the refusal code. It re-reads the clerk's records whatever a's
// Source says, so a mislabelled argument passes nothing.
func (c *Clerk) Admit(a key.Arg, own string) string {
	for _, n := range []string{c.cfg.Numbers.Owner, c.cfg.Numbers.Channel, own} {
		if sameNumber(a.Value, n) {
			return ROwnNumber
		}
	}
	if !dialable(a.Value) {
		return RNotNumber
	}
	c.mu.Lock()
	contact, fixed := c.contacts[a.Value], c.fixed[a.Value]
	c.mu.Unlock()
	switch a.Source {
	case key.SrcClerk:
		if !contact {
			return RNotContact
		}
		return ""
	case key.SrcOwner:
		if !fixed {
			return RNotFixed
		}
		// A short or premium-rate code passes only as a contact.
		if sendrules.CheckRecipient(a.Value, "", "") != nil {
			return RNeedContact
		}
		return ""
	}
	return RPlanner
}

// sameNumber is a == n, or a's digits, whatever separators it was saved
// with, are n in a national or international-prefix form
// (sendrules.SameNumber).
func sameNumber(a, n string) bool {
	if n == "" || a == "" {
		return false
	}
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, a)
	return a == n || sendrules.SameNumber(digits, n)
}

// dialable is the only form a recipient may take (CLK-8): E.164, "+" and 3
// to 15 digits, or a short code of 3 to 8 digits.
func dialable(n string) bool {
	d, plus := strings.CutPrefix(n, "+")
	if len(d) < 3 || len(d) > 15 || !plus && len(d) > 8 {
		return false
	}
	for _, r := range d {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Facts is the clerk's reading of a step's claims: a text claims no content
// class or labels, and send has no amount (KEY-2).
func (c *Clerk) Facts(s key.Step) (string, []string, int64) { return "", nil, check.Amount(s) }

// Do runs one step (kernel.Clerk).
func (c *Clerk) Do(r kernel.Request, v kernel.View) kernel.Result {
	return c.DoContext(context.Background(), r, v)
}

// DoContext runs one step: the clerk's own check of the key and the log,
// whose rate caveats are the line's one budget whatever the transport
// (CLK-8), then the account, the recipient rule and at most one hand-off
// (KRN-8). A cancel before the hand-off sends nothing.
func (c *Clerk) DoContext(ctx context.Context, r kernel.Request, v kernel.View) kernel.Result {
	idem := r.Idem()
	c.mu.Lock()
	switch c.steps[idem] {
	case sent:
		c.mu.Unlock()
		return kernel.Result{Outcome: "ok", Detail: "already done"}
	case handed, maybe:
		c.mu.Unlock()
		return kernel.Result{Outcome: "unknown", Detail: RMaybeSent}
	}
	c.mu.Unlock()
	if v == nil {
		return failed(check.RDispatch)
	}
	if rf := check.Check(c.cfg.Anchors, Name, c.Facts, c.cfg.Clock.Now(), r, v); rf != nil {
		return failed(rf.Code)
	}
	s := r.Step()
	if s.Verb != key.Send {
		return failed(RUndeclared)
	}
	rec, ok := c.acct.Record()
	if !ok || !c.acct.hasPassword() {
		return failed(RUnavailable)
	}
	if !rec.RealmConfirmed {
		return failed(RUnconfirmed)
	}
	to, words := s.Args["to"].Value, s.Args["msg"].Value
	if code := c.Admit(c.Source(to), rec.Settings.Number); code != "" {
		return failed(code)
	}
	c.mu.Lock()
	if st := c.steps[idem]; st != 0 && st != notSent { // a concurrent Do of the same step got here first
		c.mu.Unlock()
		return kernel.Result{Outcome: "unknown", Detail: RMaybeSent}
	}
	if ctx.Err() != nil {
		c.steps[idem] = notSent
		c.mu.Unlock()
		return failed(RCancelled)
	}
	c.steps[idem] = handed
	c.mu.Unlock()

	if c.bind != nil {
		c.bind.admit(idem, to)
	}
	err := c.cfg.Line.Send(ctx, to, words)
	if c.bind != nil {
		c.bind.revoke(idem)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case err == nil:
		c.steps[idem] = sent
		c.sent++
		c.log(Entry{Kind: EntrySent, Idem: idem, To: to, Words: words})
		return kernel.Result{Outcome: "ok"}
	case errors.Is(err, ErrNotTaken):
		c.steps[idem] = notSent
		return failed(RNotTaken)
	case errors.Is(err, ErrRefused):
		c.steps[idem] = notSent
		return failed(RProvider)
	}
	c.steps[idem] = maybe
	c.maybe++
	c.log(Entry{Kind: EntryMaybeSent, Idem: idem, To: to, Words: words})
	return kernel.Result{Outcome: "unknown", Detail: RMaybeSent}
}

// Probe answers from the clerk's memory, never by acting (KRN-8): notdone
// only for a step this clerk saw go nowhere. A text the line may have sent,
// and any step the clerk has no record of (its memory is lost on a
// restart), is unknown for good, so the kernel parks it and it is never
// sent again, as clerk.Exit answers for a request that is not idempotent.
func (c *Clerk) Probe(r kernel.Request, _ kernel.View) kernel.Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.steps[r.Idem()] {
	case sent:
		return kernel.Result{Outcome: "done"}
	case notSent:
		return kernel.Result{Outcome: "notdone"}
	}
	return kernel.Result{Outcome: "unknown"}
}

func failed(code string) kernel.Result { return kernel.Result{Outcome: "failed", Detail: code} }

// log hands e to the kernel; c.mu is held or e is the clerk's own.
func (c *Clerk) log(e Entry) {
	if c.cfg.Log != nil {
		c.cfg.Log(e)
	}
}

// Status is the clerk's state for STATUS and the owner page. It names no
// number, password or words.
type Status struct {
	Available, RealmConfirmed bool
	Sent, MaybeSent           int
	// SignRefused counts the signatures the clerk refused (sign.go).
	SignRefused int
}

// Status reports the clerk's state.
func (c *Clerk) Status() Status {
	rec, ok := c.acct.Record()
	st := Status{Available: ok && c.acct.hasPassword(), RealmConfirmed: ok && rec.RealmConfirmed}
	c.mu.Lock()
	st.Sent, st.MaybeSent = c.sent, c.maybe
	c.mu.Unlock()
	if c.bind != nil {
		st.SignRefused = c.bind.refused()
	}
	return st
}

// OwnerText words a refusal code for the owner: what happened and what to
// do, never a number, a status code or the provider's words.
func OwnerText(code string) string {
	switch code {
	case "":
		return ""
	case RUnavailable:
		return "There is no second line set up, so nothing was sent. Set one up on my Wi-Fi page."
	case RUnconfirmed:
		return "The second line's provider isn't confirmed yet, so nothing was sent. Confirm it on my Wi-Fi page."
	case RPlanner, RNotContact, RNotFixed:
		return "The second line only texts your contacts and numbers you gave it, so nothing was sent. Add the number on my Wi-Fi page."
	case RNeedContact:
		return "The second line texts a short or premium-rate number only when it is one of your contacts, so nothing was sent."
	case RNotNumber:
		return "The second line texts a full number with its country code, or a short code, so nothing was sent. Fix the contact's number on my Wi-Fi page."
	case ROwnNumber:
		return "The second line never texts your own number or mine, so nothing was sent."
	case RCancelled, RNotTaken:
		return "The second line didn't send that text. Ask again when it is connected."
	case RProvider:
		return "The second line's provider didn't accept that text. Check the number, or try again later."
	case RMaybeSent:
		return "The second line lost the provider's answer, so that text may have been sent. I won't send it again on my own."
	case RUndeclared:
		return "The second line only sends texts."
	}
	return "The second line didn't send that: its key doesn't allow it now. Check STATUS for its limits."
}
