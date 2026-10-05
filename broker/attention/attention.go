// Package attention is the attention optimizer's proposer (SPEC CAP-6):
// it watches the owner's approval decisions and, when a class of request
// has been approved unchanged often enough, suggests converting it into an
// owner pre-allowance (ADP-9), or for in-thread replies a context-scoped
// reply rule (ADP-11). It only suggests: it holds no journal, grant, or
// owner-channel handle, so it cannot enact anything. Taking a suggestion
// is the owner's own new-grant intent (CH-3: code plus local page), which
// the grants package checks like any other.
//
// It also keeps A10's split of owner approvals into necessary and
// avoidable. The package uses no inference (ARC-2).
//
// Assumptions are listed in ASSUMPTIONS.md next to this file.
package attention

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/verb"
)

// Decision is one owner answer to an approval request, as the grants gate
// saw it. Every field comes from the broker (the verifier's reading and
// the gate's rendering), never from the agent.
type Decision struct {
	Account string
	Action  string
	// Verb is the action's verb under the account's adapter grant.
	Verb string
	// Approved is the owner's YES; false is a NO or an UNDO.
	Approved bool
	// Expired: the request lapsed unanswered. Silence is not a judgment,
	// so it neither counts nor resets (potency PA1).
	Expired bool
	// Edited: the owner changed the item before it went out. It resets the
	// run like a NO (ADP-9). For a reply class it never counts toward the
	// run but resets it only past Config.ReplyEditPercent (ADP-11).
	Edited bool
	// Wrong: the owner later judged it wrong (OP-7). It resets any run.
	Wrong bool
	// Verified: the approval line came from the account's verifier. An
	// unverified approval can never match a pre-allowance (grants GR5), so
	// it does not count; an unverified NO, UNDO, edit, or wrong verdict
	// still resets the run (ADP-11).
	Verified bool
	// Params and Recipients are what was approved; Amount is the verified
	// amount in minor units (0 when no money moves).
	Params     map[string]any
	Recipients []string
	Amount     int64
	At         time.Time
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
	// pre-allowance suggestion (ADP-9). Default 10.
	Threshold int
	// ReplyThreshold is the run that earns a context-scoped reply rule
	// (ADP-11 "earned"). Default 20.
	ReplyThreshold int
	// ReplyEditPercent lets an ADP-11 reply class earn its suggestion
	// despite light edits: ReplyThreshold unedited approvals (edited ones
	// never count) with at most this percentage edited among the last
	// EditWindow answered (SPEC ADP-11; Mark, 2026-10-05, "Allow light
	// edits"). Default 10. Negative: the strict run, any edit resets.
	ReplyEditPercent int
	// UserContent reports an account whose service publishes user content
	// (paste sites, file shares, URL shorteners): never suggested, since
	// an attacker can read what it receives (the SPEC egress-allowlist note,
	// security review). Required, so a missing check cannot fail open.
	UserContent func(account string) bool
	// ShortID gives the owner-facing ID of a suggestion (CH-12). Nil: S1,
	// S2, ...
	ShortID func(taken func(string) bool) (string, error)
}

// class is one kind of request: an account, an action, and the fixed
// params that make it templated content.
type class struct {
	Account string `json:"account"`
	Action  string `json:"action"`
	Verb    string `json:"verb"`
	Reply   bool   `json:"reply,omitempty"`
	// Run is the current run of unedited, verified approvals; the fields
	// after it describe that run.
	Run        int               `json:"run"`
	Since      time.Time         `json:"since"`
	Fixed      map[string]string `json:"fixed,omitempty"`
	Templated  bool              `json:"templated"`
	Recipients []string          `json:"recipients,omitempty"`
	SameRcpt   bool              `json:"same_rcpt"`
	MaxAmount  int64             `json:"max_amount,omitempty"`
	Days       map[string]int    `json:"days,omitempty"`
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

// Body is the param that makes a send an in-thread reply (grants
// ParamBody); Record names the source record (grants ParamRecord).
const (
	Body   = grants.ParamBody
	Record = grants.ParamRecord
)

func key(account, action string, reply bool) string {
	return fmt.Sprintf("%s\x00%s\x00%v", account, action, reply)
}

// eligible reports whether a verb may ever be pre-allowed: irreversible,
// and not reveal-or-create-secret (CRED-6 keeps per-action approval).
func eligible(v string) bool {
	c, ok := verb.ClassOf(v)
	return ok && c == verb.Irreversible
}

// Observe records one owner decision. A Wrong verdict is the owner's
// later judgment of an item already observed, so it never counts as an
// approval again (A10).
func (o *Optimizer) Observe(d Decision) error {
	if d.Expired {
		return nil
	}
	_, reply := d.Params[Body]
	reply = reply && d.Verb == verb.Send
	o.mu.Lock()
	defer o.mu.Unlock()
	k := key(d.Account, d.Action, reply)
	c := o.st.Classes[k]
	if d.Approved && !d.Wrong {
		// A10: avoidable only when a pre-allowance would have let this
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
		c = &class{Account: d.Account, Action: d.Action, Verb: d.Verb, Reply: reply}
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
	fixed, ok := fixedParams(d.Params, reply)
	day := d.At.UTC().Format("2006-01-02")
	if c.Run == 0 {
		c.Since, c.Fixed, c.Templated = d.At, fixed, ok
		c.Recipients, c.SameRcpt = sorted(d.Recipients), true
		c.Days = map[string]int{}
	} else {
		c.Templated = c.Templated && ok && equalMap(c.Fixed, fixed)
		c.SameRcpt = c.SameRcpt && strings.Join(c.Recipients, "\n") == strings.Join(sorted(d.Recipients), "\n")
	}
	c.Run++
	c.Days[day]++
	c.MaxAmount = max(c.MaxAmount, d.Amount)
	if c.Snooze > 0 {
		c.Snooze--
	}
	return o.save()
}

// earnedLocked reports whether a class may be suggested now.
func (o *Optimizer) earnedLocked(c *class) bool {
	if c.Run < o.threshold(c) || c.Snooze > 0 || !c.Templated {
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
	return o.cfg.UserContent == nil || !o.cfg.UserContent(c.Account)
}

// reset ends the run; the edit-rate window (Recent) is kept, since it
// covers the last answered replies whatever happened between (ADP-11).
func (c *class) reset() {
	c.Run, c.Fixed, c.Templated, c.Recipients, c.SameRcpt, c.MaxAmount, c.Days = 0, nil, false, nil, false, 0, nil
	c.Short, c.Offered, c.Offers = "", time.Time{}, 0
}

func (o *Optimizer) threshold(c *class) int {
	if c.Reply {
		return o.cfg.ReplyThreshold
	}
	return o.cfg.Threshold
}

// fixedParams returns the params a rule would fix: every param but the
// record (and a reply's body) must be a string, since ADP-9 allows only
// templated content filled from verified fields. ok is false otherwise.
func fixedParams(p map[string]any, reply bool) (map[string]string, bool) {
	out := map[string]string{}
	for k, v := range p {
		if k == Record || (reply && k == Body) {
			continue
		}
		s, isStr := v.(string)
		if !isStr {
			return nil, false
		}
		out[k] = s
	}
	return out, true
}

func equalMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
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

// Suggestion is one proposed rule, with its evidence. Spec is a draft of
// the grant intent the owner would make; Text is the owner's line, in
// fixed wording built from broker fields only (ADP-9).
type Suggestion struct {
	Short    string
	Spec     grants.Spec
	Approved int
	Since    time.Time
	// Text is the owner's text (at most 3 SMS segments, CH-12); Detail
	// is the full fixed wording (grants.Describe) for the Wi-Fi page,
	// where the owner confirms the rule.
	Text   string
	Detail string
}

// evidence is the owner-facing run: strict for ADP-9, unedited count for
// replies (which may include edits that did not count).
func evidence(c *class) string {
	since := c.Since.UTC().Format("Jan 2")
	if c.Reply {
		return fmt.Sprintf("You approved %d of the agent's replies on %s unedited since %s.", c.Run, c.Account, since)
	}
	return fmt.Sprintf("You approved %s on %s %d times in a row since %s, never changed.", c.Action, c.Account, c.Run, since)
}

// MaxText is CH-12's three GSM-7 segments.
const MaxText = 3 * 153

// summary is the rule in one clause for the owner's text.
func summary(spec grants.Spec) string {
	r := spec.Rule
	if r.Reply {
		return fmt.Sprintf("let the agent reply in existing threads on %s without asking, up to %d a day.", spec.Account, r.PerDay)
	}
	money := "no money"
	if r.AmountCap > 0 {
		money = "amounts up to " + fmt.Sprintf("%d.%02d", r.AmountCap/100, r.AmountCap%100)
	}
	return fmt.Sprintf("let it run without asking, up to %d a day, %s.", r.PerDay, money)
}

// Suggestions returns the classes that have earned a suggestion, in a
// stable order. A class earns one when its run of unedited, verified
// approvals reaches the threshold (ADP-11's for replies), every approval
// carried the same fixed params, and it is not a user-content service. A
// run with the same recipients every time fixes them in the rule.
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
		out = append(out, Suggestion{})
		if c.Short == "" {
			s, err := o.shortLocked()
			if err != nil {
				return nil, err
			}
			c.Short, dirty = s, true
		}
		r := &grants.Rule{Action: c.Action, PerRecord: 1, PerDay: 1, Reply: c.Reply}
		if len(c.Fixed) > 0 {
			r.Params = c.Fixed
		}
		r.PerDay = max(r.PerDay, median(c.Days))
		if c.SameRcpt && len(c.Recipients) > 0 && !c.Reply {
			r.Recipients = c.Recipients
		}
		if c.MaxAmount > 0 && !c.Reply {
			r.AmountCap, r.HoldDays = c.MaxAmount, 3
		}
		spec := grants.Spec{Account: c.Account, Rule: r}
		out[len(out)-1] = Suggestion{
			Short: c.Short, Spec: spec, Approved: c.Run, Since: c.Since,
			Text: evidence(c) + fmt.Sprintf(" Suggestion: %s To set it up, open the box's Wi-Fi page. Reply NO %s to stop suggesting it.",
				summary(spec), c.Short),
			Detail: grants.Describe(spec),
		}
	}
	if dirty {
		if err := o.save(); err != nil {
			return nil, err
		}
	}
	return out, nil
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
// class had earned a suggestion (a pre-allowance would have covered
// them), necessary ones before.
func (o *Optimizer) Split() (necessary, avoidable int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.st.Necessary, o.st.Avoidable
}
