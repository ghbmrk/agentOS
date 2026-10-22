// Package attention proposes standing keys from use (SPEC KEY-5): it
// watches the owner's approval decisions and, when approvals of one shape
// recur (same clerk, verb and argument class, approved unedited), drafts
// the narrowest key that covers them as caveats (KEY-2), or for in-thread
// replies a thread-scoped one. It only proposes: it holds no kernel, key or
// owner-channel handle, so it cannot enact anything. Taking a proposal is
// the owner's passkey tap, which makes the key, live after KEY-4's grant
// hold.
//
// It also keeps A10's split of owner approvals into necessary and
// avoidable. The package uses no inference.
//
// Assumptions are listed in ASSUMPTIONS.md next to this file.
package attention

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Decision is one owner answer to an approval of a plan step, as the log
// holds it. Every field comes from the kernel and the clerk (what the clerk
// read from the source system or the owner fixed), never from a planner.
type Decision struct {
	// Clerk is the clerk the step ran on, and Verb its verb (VRB-2).
	Clerk string
	Verb  key.Verb
	// Thread: the step was a reply in an existing thread, the shape a
	// thread-scoped key covers (KEY-2).
	Thread bool
	// Approved is the owner's YES; false is a NO or an UNDO.
	Approved bool
	// Expired: the request lapsed unanswered. Silence is not a judgment,
	// so it neither counts nor resets (potency PA1).
	Expired bool
	// Edited: the owner changed the item before it went out. It resets the
	// run like a NO (KEY-5). For a reply class it never counts toward the
	// run but resets it only past Config.ReplyEditPercent (KEY-5).
	Edited bool
	// Wrong: the owner later judged it wrong (OP-7). It resets any run.
	Wrong bool
	// Verified: every argument the approval showed was read by the clerk
	// or fixed by the owner. A key bounds only such arguments (KEY-2), so
	// an unverified approval does not count; an unverified NO, UNDO, edit,
	// or wrong verdict still resets the run.
	Verified bool
	// Content is the step's content class as the clerk reported it: an
	// owner-approved template filled only from verified fields, or a
	// thread scope. Empty is any other content, which no standing key
	// covers (KEY-5).
	Content string
	// Args are the step's other arguments, as approved: every argument
	// but its object (Recipients), its amount, and its message (msg),
	// which the content caveat bounds.
	Args map[string]string
	// Recipients is the step's object argument's value, as the clerk read
	// it (key.RecipientArg names it).
	Recipients []string
	// Amount is the verified amount in minor units (0 when no money moves).
	Amount int64
	At     time.Time
}

// Store persists the optimizer's state; change.MemStore and
// change.FileStore satisfy it.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// Config configures New.
type Config struct {
	Store Store
	// Threshold is the run of unedited approvals that earns a
	// standing-key suggestion (KEY-5). Default 10.
	Threshold int
	// ReplyThreshold is the run that earns a context-scoped reply rule
	// (KEY-5's thread scope). Default 20.
	ReplyThreshold int
	// ReplyEditPercent lets a reply class earn its suggestion
	// despite light edits: ReplyThreshold unedited approvals (edited ones
	// never count) with at most this percentage edited among the last
	// EditWindow answered (SPEC KEY-5; Mark, 2026-10-05, "Allow light
	// edits"). Default 10. Negative: the strict run, any edit resets.
	ReplyEditPercent int
	// UserContent reports a clerk whose service publishes user content
	// (paste sites, file shares, URL shorteners): never suggested, since
	// an attacker can read what it receives (the SPEC egress-allowlist note,
	// security review). Required, so a missing check cannot fail open.
	UserContent func(clerk string) bool
	// ShortID gives the owner-facing ID of a suggestion (CH-12). Nil: S1,
	// S2, ...
	ShortID func(taken func(string) bool) (string, error)
}

// class is one shape of request: a clerk, a verb, and whether it is a
// thread reply. The fixed content and arguments of its run are its
// argument class.
type class struct {
	Clerk string   `json:"clerk"`
	Verb  key.Verb `json:"verb"`
	Reply bool     `json:"reply,omitempty"`
	// Run is the current run of unedited, verified approvals; the fields
	// after it describe that run.
	Run       int               `json:"run"`
	Since     time.Time         `json:"since"`
	Content   string            `json:"content,omitempty"`
	Fixed     map[string]string `json:"fixed,omitempty"`
	Templated bool              `json:"templated"`
	// Recipients is every object the run's approvals named.
	Recipients []string       `json:"recipients,omitempty"`
	MaxAmount  int64          `json:"max_amount,omitempty"`
	Days       map[string]int `json:"days,omitempty"`
	// Recent holds whether each of the last EditWindow answered replies
	// was edited (reply classes only).
	Recent []bool `json:"recent,omitempty"`
	// Declined: the owner said NO to a suggestion; it returns only at
	// twice the threshold (Snooze), counted from the NO.
	Snooze int    `json:"snooze,omitempty"`
	Short  string `json:"short,omitempty"`
	// Offered is when the suggestion last went to the owner; Offers how
	// many times it went unanswered.
	Offered time.Time `json:"offered,omitempty"`
	Offers  int       `json:"offers,omitempty"`
}

type state struct {
	Classes   map[string]*class `json:"classes"`
	Seq       int               `json:"seq"`
	Necessary int               `json:"necessary"`
	Avoidable int               `json:"avoidable"`
}

// Optimizer is safe for concurrent use.
type Optimizer struct {
	cfg Config
	mu  sync.Mutex
	st  state
}

// New loads the saved state, if any.
func New(cfg Config) (*Optimizer, error) {
	if cfg.Store == nil {
		return nil, errors.New("attention: Store is required")
	}
	if cfg.UserContent == nil {
		return nil, errors.New("attention: UserContent is required")
	}
	if cfg.Threshold < 1 {
		cfg.Threshold = 10
	}
	if cfg.ReplyThreshold < 1 {
		cfg.ReplyThreshold = 20
	}
	if cfg.ReplyEditPercent == 0 {
		cfg.ReplyEditPercent = 10
	}
	o := &Optimizer{cfg: cfg, st: state{Classes: map[string]*class{}}}
	raw, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &o.st); err != nil {
			return nil, fmt.Errorf("attention: corrupt state: %w", err)
		}
		if o.st.Classes == nil {
			o.st.Classes = map[string]*class{}
		}
	}
	return o, nil
}

// EditWindow is how many answered replies the edit rate covers when
// Config.ReplyEditPercent is not negative.
const EditWindow = 30

func classKey(clerk string, v key.Verb, reply bool) string {
	return fmt.Sprintf("%s\x00%s\x00%v", clerk, v, reply)
}

// eligible reports whether a verb may ever have a standing key:
// irreversible (a reversible verb needs no approval), and not
// reveal-or-create-secret, a VRB-1 step that keeps per-step approval under
// any key (KEY-5).
func eligible(v key.Verb) bool {
	c, ok := key.ClassOf(v)
	return ok && c.Irreversible() && v != key.RevealOrCreateSecret
}

// Observe records one owner decision. A Wrong verdict is the owner's
// later judgment of an item already observed, so it never counts as an
// approval again (A10).
func (o *Optimizer) Observe(d Decision) error {
	if d.Expired {
		return nil
	}
	reply := d.Thread && d.Verb == key.Send
	o.mu.Lock()
	defer o.mu.Unlock()
	k := classKey(d.Clerk, d.Verb, reply)
	c := o.st.Classes[k]
	if d.Approved && !d.Wrong {
		// A10: avoidable only when a standing key would have let this
		// exact item through: eligible, verified, unedited, earned.
		if c != nil && eligible(d.Verb) && d.Verified && !d.Edited && o.earnedLocked(c) {
			o.st.Avoidable++
		} else {
			o.st.Necessary++
		}
	}
	if !eligible(d.Verb) {
		return o.save()
	}
	if c == nil {
		c = &class{Clerk: d.Clerk, Verb: d.Verb, Reply: reply}
		o.st.Classes[k] = c
	}
	if !d.Approved || d.Wrong || (d.Edited && (!reply || o.cfg.ReplyEditPercent <= 0)) {
		c.reset()
		return o.save()
	}
	if reply {
		// Every answered reply, verified or not, is in the edit rate.
		c.Recent = append(c.Recent, d.Edited)
		if len(c.Recent) > EditWindow {
			c.Recent = c.Recent[len(c.Recent)-EditWindow:]
		}
	}
	if !d.Verified || d.Edited {
		return o.save() // an unverified or edited approval never counts
	}
	fixed := maps.Clone(d.Args)
	delete(fixed, "msg") // a template filled per record varies; the content caveat bounds it
	ok := d.Content != ""
	day := d.At.UTC().Format("2006-01-02")
	if c.Run == 0 {
		c.Since, c.Content, c.Fixed, c.Templated = d.At, d.Content, fixed, ok
		c.Recipients = nil
		c.Days = map[string]int{}
	} else {
		c.Templated = c.Templated && ok && c.Content == d.Content && maps.Equal(c.Fixed, fixed)
	}
	c.Run++
	c.Recipients = union(c.Recipients, d.Recipients)
	c.Days[day]++
	c.MaxAmount = max(c.MaxAmount, d.Amount)
	if c.Snooze > 0 {
		c.Snooze--
	}
	return o.save()
}

// earnedLocked reports whether a class may be suggested now.
func (o *Optimizer) earnedLocked(c *class) bool {
	// A templated key always bounds its object: a run that named none
	// leaves nothing to bound it to, so it earns nothing (KEY-2).
	if c.Run < o.threshold(c) || c.Snooze > 0 || !c.Templated || (!c.Reply && len(c.Recipients) == 0) {
		return false
	}
	if c.Reply && o.cfg.ReplyEditPercent > 0 { // strict: an edit already reset the run
		edits := 0
		for _, e := range c.Recent {
			if e {
				edits++
			}
		}
		if edits*100 > o.cfg.ReplyEditPercent*len(c.Recent) {
			return false
		}
	}
	return o.cfg.UserContent == nil || !o.cfg.UserContent(c.Clerk)
}

// reset ends the run; the edit-rate window (Recent) is kept, since it
// covers the last answered replies whatever happened between (KEY-5).
func (c *class) reset() {
	c.Run, c.Content, c.Fixed, c.Templated, c.Recipients, c.MaxAmount, c.Days = 0, "", nil, false, nil, 0, nil
	c.Short, c.Offered, c.Offers = "", time.Time{}, 0
}

func (o *Optimizer) threshold(c *class) int {
	if c.Reply {
		return o.cfg.ReplyThreshold
	}
	return o.cfg.Threshold
}

// union is a and b as one sorted set.
func union(a, b []string) []string {
	out := sorted(append(append([]string(nil), a...), b...))
	return slices.Compact(out)
}

func sorted(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}

func (o *Optimizer) save() error {
	b, err := json.Marshal(o.st)
	if err != nil {
		return err
	}
	return o.cfg.Store.Save(b)
}

// Suggestion is one proposed standing key, with its evidence. Clerk and
// Caveats are the draft the owner's passkey tap would sign (KEY-4); Text
// is the owner's line, in fixed wording built from logged fields only.
type Suggestion struct {
	Short    string
	Clerk    string
	Caveats  []key.Caveat
	Approved int
	Since    time.Time
	// Text is the owner's text (at most 3 SMS segments, CH-12); Detail
	// is the full fixed wording (Describe) for the owner page, where the
	// owner confirms the key.
	Text   string
	Detail []Term
}

// evidence is the owner-facing run: strict for a templated key, unedited
// count for replies (which may include edits that did not count).
func evidence(c *class) string {
	since := c.Since.UTC().Format("Jan 2")
	if c.Reply {
		return fmt.Sprintf("You approved %d of my replies on %s unedited since %s.", c.Run, c.Clerk, since)
	}
	return fmt.Sprintf("You approved %s on %s %d times in a row since %s, never changed.", c.Verb, c.Clerk, c.Run, since)
}

// MaxText is CH-12's three GSM-7 segments.
const MaxText = 3 * 153

// summary is the key in one clause for the owner's text.
func summary(c *class, perDay int64) string {
	if c.Reply {
		return fmt.Sprintf("let me reply in existing threads on %s without asking, up to %d a day.", c.Clerk, perDay)
	}
	money := "no money"
	if amountBound(c) {
		money = "amounts up to " + minor(c.MaxAmount)
	}
	return fmt.Sprintf("let it run without asking, up to %d a day, %s.", perDay, money)
}

func minor(n int64) string { return fmt.Sprintf("%d.%02d", n/100, n%100) }

// amountBound reports whether the key bounds the amount: money moved, and
// the verb carries it as its amount argument (KEY-2).
func amountBound(c *class) bool {
	return c.MaxAmount > 0 && !c.Reply && slices.Contains(key.ArgNames(c.Verb), key.ArgAmount)
}

// caveats is the narrowest key that covers c's run (KEY-5): its one verb,
// its content class, each fixed argument at the value it had every time,
// the recipients when they never changed, the largest amount approved,
// and the median day's count as the daily rate.
func caveats(c *class, perDay int64) []key.Caveat {
	cs := []key.Caveat{key.LimitVerbs(c.Verb), key.LimitContent(c.Content)}
	names := make([]string, 0, len(c.Fixed))
	for n := range c.Fixed {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		cs = append(cs, key.LimitArg(key.ArgBound{Name: n, OneOf: []string{c.Fixed[n]}}))
	}
	if !c.Reply {
		cs = append(cs, key.LimitArg(key.ArgBound{Name: key.RecipientArg(c.Verb), OneOf: c.Recipients}))
	}
	if amountBound(c) {
		m := c.MaxAmount
		cs = append(cs, key.LimitArg(key.ArgBound{Name: key.ArgAmount, Max: &m}))
	}
	return append(cs, key.LimitRate(perDay))
}

// Suggestions returns the classes that have earned a suggestion, in a
// stable order. A class earns one when its run of unedited, verified
// approvals reaches the threshold (the thread scope's for replies), every
// approval carried the same content class and arguments, and it is not a
// user-content service. A run with the same recipients every time fixes
// them in the key.
func (o *Optimizer) Suggestions() ([]Suggestion, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	keys := make([]string, 0, len(o.st.Classes))
	for k := range o.st.Classes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Suggestion
	dirty := false
	for _, k := range keys {
		c := o.st.Classes[k]
		if !o.earnedLocked(c) {
			continue
		}
		if c.Short == "" {
			s, err := o.shortLocked()
			if err != nil {
				return nil, err
			}
			c.Short, dirty = s, true
		}
		perDay := int64(max(1, median(c.Days)))
		cs := caveats(c, perDay)
		out = append(out, Suggestion{
			Short: c.Short, Clerk: c.Clerk, Caveats: cs, Approved: c.Run, Since: c.Since,
			Text: evidence(c) + fmt.Sprintf(" Suggestion: %s To set it up, open my Wi-Fi page. Reply NO %s to stop suggesting it.",
				summary(c, perDay), c.Short),
			Detail: Describe(c.Clerk, c.Reply, cs),
		})
	}
	if dirty {
		if err := o.save(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Term is one line of a key's fixed wording: a label and the value the
// caveat holds, shown as is.
type Term struct {
	Label, Value string
}

// Describe is the fixed wording of a key on clerk with caveats cs, one
// term per caveat, in their order, then one "any" term for each argument
// of the key's verbs that no caveat bounds. It renders every closed caveat
// kind (KEY-2), so neither a caveat the key carries nor a bound it lacks
// is left off the card that asks for it.
//
// thread marks a thread-scoped key (KEY-2): each reply it covers is texted
// to the owner first and sends after the undo window, to the thread's own
// participants, so its card says so instead of "without notifying you".
func Describe(clerk string, thread bool, cs []key.Caveat) []Term {
	out := []Term{{"Clerk", clerk}}
	bound := map[string]bool{}
	var verbs []string
	for _, c := range cs {
		if t := term(c); thread && c.Kind == key.KVerbs {
			out = append(out, Term{"Runs", strings.Join(c.Set, ", ") +
				" as replies in existing threads, without asking; each is texted to you first and sends after the undo window unless you reply UNDO"})
		} else {
			out = append(out, t)
		}
		switch {
		case c.Kind == key.KArg && c.Arg != nil:
			bound[c.Arg.Name] = true
		case c.Kind == key.KVerbs:
			verbs = c.Set
		}
	}
	var open []string
	for _, v := range verbs {
		for _, n := range key.ArgNames(key.Verb(v)) {
			if thread && n == key.RecipientArg(key.Verb(v)) {
				bound[n] = true // the thread's participants, as the clerk reads them
				out = append(out, Term{"Recipients", "the thread's own participants only"})
			}
			if !bound[n] && !slices.Contains(open, n) {
				open = append(open, n)
			}
		}
	}
	sort.Strings(open)
	for _, n := range open {
		out = append(out, Term{"Argument " + n, "any"})
	}
	return out
}

func term(c key.Caveat) Term {
	list := func(s []string) string {
		if len(s) == 0 {
			return "none"
		}
		return "only " + strings.Join(s, ", ")
	}
	ms := func(n int64) string { return (time.Duration(n) * time.Millisecond).String() }
	switch c.Kind {
	case key.KVerbs:
		return Term{"Runs", strings.Join(c.Set, ", ") + ", without asking or notifying you"}
	case key.KContent:
		return Term{"Content", list(c.Set)}
	case key.KLabels:
		return Term{"Data labels", list(c.Set)}
	case key.KArg:
		if c.Arg == nil {
			return Term{"Argument", "malformed"}
		}
		var b []string
		if c.Arg.OneOf != nil {
			b = append(b, list(c.Arg.OneOf))
		}
		if c.Arg.Min != nil {
			b = append(b, "at least "+minorIf(c.Arg.Name, *c.Arg.Min))
		}
		if c.Arg.Max != nil {
			b = append(b, "up to "+minorIf(c.Arg.Name, *c.Arg.Max))
		}
		if len(b) == 0 {
			b = append(b, "any")
		}
		return Term{"Argument " + c.Arg.Name, strings.Join(b, ", ")}
	case key.KSpendTask:
		return Term{"Spend per task", "up to " + minor(c.N)}
	case key.KSpendDay:
		return Term{"Spend per day", "up to " + minor(c.N)}
	case key.KRateDay:
		return Term{"Per day", fmt.Sprintf("at most %d %s", c.N, plural(c.N, "run"))}
	case key.KRateRecipient:
		return Term{"Per recipient", fmt.Sprintf("at most %d %s a day", c.N, plural(c.N, "run"))}
	case key.KExpires:
		return Term{"Expires", time.UnixMilli(c.N).UTC().Format("Jan 2 2006 15:04 UTC")}
	case key.KUses:
		return Term{"Uses", fmt.Sprintf("at most %d", c.N)}
	case key.KHold:
		return Term{"Hold", fmt.Sprintf("%s before it runs, %s when new", ms(c.N), ms(c.M))}
	case key.KTask:
		return Term{"Task", list(c.Set)}
	}
	return Term{"Unknown limit", c.Kind}
}

func plural(n int64, w string) string {
	if n == 1 {
		return w
	}
	return w + "s"
}

// minorIf shows the amount argument in minor units as an amount, any
// other bound as the number.
func minorIf(name string, n int64) string {
	if name == key.ArgAmount {
		return minor(n)
	}
	return fmt.Sprint(n)
}

func (o *Optimizer) shortLocked() (string, error) {
	taken := func(s string) bool {
		for _, c := range o.st.Classes {
			if c.Short == s {
				return true
			}
		}
		return false
	}
	if o.cfg.ShortID != nil {
		return o.cfg.ShortID(taken)
	}
	for range MaxShort {
		o.st.Seq = o.st.Seq%MaxShort + 1
		if s := fmt.Sprintf("S%d", o.st.Seq); !taken(s) {
			return s, nil
		}
	}
	return "", ErrShortIDs
}

// MaxShort bounds the fallback IDs to S1..S99, three characters (CH-12);
// they cycle, so a declined ID is not reused at once.
const MaxShort = 99

// ErrShortIDs: every fallback short ID is in use.
var ErrShortIDs = errors.New("attention: no free short ID")

// median is the median count per day (the lower middle for an even
// count), so bunching approvals into one day cannot raise the drafted
// daily cap.
func median(days map[string]int) int {
	if len(days) == 0 {
		return 0
	}
	ns := make([]int, 0, len(days))
	for _, n := range days {
		ns = append(ns, n)
	}
	sort.Ints(ns)
	return ns[(len(ns)-1)/2]
}

// Reoffer is the least time between two offers of one suggestion, and
// MaxOffers how many unanswered offers count as a NO.
const (
	Reoffer   = 7 * 24 * time.Hour
	MaxOffers = 2
)

// Due returns the suggestions to send the owner now (in the digest), and
// records them as offered: one never offered, or last offered at least
// Reoffer ago. After MaxOffers unanswered offers the next due one counts
// as a NO (Decline) instead, so an ignored suggestion stops repeating.
func (o *Optimizer) Due(now time.Time) ([]Suggestion, error) {
	all, err := o.Suggestions()
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []Suggestion
	for _, sg := range all {
		var c *class
		for _, x := range o.st.Classes {
			if x.Short == sg.Short {
				c = x
			}
		}
		if c == nil || (!c.Offered.IsZero() && now.Sub(c.Offered) < Reoffer) {
			continue
		}
		if c.Offers >= MaxOffers {
			c.Snooze, c.Short, c.Offered, c.Offers = 2*o.threshold(c), "", time.Time{}, 0
			continue
		}
		c.Offered, c.Offers = now, c.Offers+1
		out = append(out, sg)
	}
	return out, o.save()
}

// ErrUnknown: no open suggestion has that ID.
var ErrUnknown = errors.New("attention: no such suggestion")

// Decline records the owner's NO to a suggestion: it is not offered again
// until the class earns twice the threshold more approvals, unedited.
func (o *Optimizer) Decline(short string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, c := range o.st.Classes {
		if c.Short != "" && strings.EqualFold(c.Short, short) {
			c.Snooze, c.Short, c.Offered, c.Offers = 2*o.threshold(c), "", time.Time{}, 0
			return o.save()
		}
	}
	return ErrUnknown
}

// Split is A10's count of owner approvals: avoidable ones came after the
// class had earned a suggestion (a standing key would have covered
// them), necessary ones before.
func (o *Optimizer) Split() (necessary, avoidable int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.st.Necessary, o.st.Avoidable
}
