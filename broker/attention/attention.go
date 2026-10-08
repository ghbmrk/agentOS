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
	// Now supplies the broker clock for evidence retention. Nil: time.Now.
	Now func() time.Time
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

// class is an account/action evidence group. ADP-9 groups hold bounded
// canonical Cohorts; ADP-11 retains its existing single reply history.
type class struct {
	Cohorts map[string]*class `json:"cohorts,omitempty"`
	Last    time.Time         `json:"last,omitempty"`
	Account string            `json:"account"`
	Action  string            `json:"action"`
	Verb    string            `json:"verb"`
	Reply   bool              `json:"reply,omitempty"`
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
	Version       int                  `json:"version"`
	Latest        time.Time            `json:"latest,omitempty"`
	AccountOffers map[string]time.Time `json:"account_offers,omitempty"`
	Classes       map[string]*class    `json:"classes"`
	Seq           int                  `json:"seq"`
	Necessary     int                  `json:"necessary"`
	Avoidable     int                  `json:"avoidable"`
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
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	o := &Optimizer{cfg: cfg, st: state{Version: stateVersion, Classes: map[string]*class{}, AccountOffers: map[string]time.Time{}}}
	raw, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if len(raw) > MaxStateBytes {
			return nil, errors.New("attention: saved state exceeds size limit")
		}
		o.st.Version = 0
		if err := json.Unmarshal(raw, &o.st); err != nil {
			return nil, fmt.Errorf("attention: corrupt state: %w", err)
		}
		if o.st.Classes == nil {
			o.st.Classes = map[string]*class{}
		}
	}
	if err := o.loadState(); err != nil {
		return nil, err
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
	o.advanceLocked(d.At)
	k := key(d.Account, d.Action, reply)
	group := o.st.Classes[k]
	fixed, ok := fixedParams(d.Params, reply)
	cohort, shapeOK := cohortKey(d.Verb, fixed)
	shapeOK = shapeOK && ok && boundedRecipients(d.Recipients)
	var c *class
	if group != nil {
		c = group
		if !reply {
			c = group.Cohorts[cohort]
		}
	}
	if d.Approved && !d.Wrong {
		// A10 uses the already-earned matching evidence, before observing
		// this approval. An unseen shape or a wider bound is necessary.
		if shapeOK && c != nil && d.Verb == c.Verb && eligible(d.Verb) && d.Verified && !d.Edited &&
			equalMap(c.Fixed, fixed) && o.earnedLocked(c) && withinObservedBounds(c, d) {
			o.st.Avoidable++
		} else {
			o.st.Necessary++
		}
	}
	negative := !d.Approved || d.Wrong || (d.Edited && (!reply || o.cfg.ReplyEditPercent <= 0))
	if negative {
		// Do not let a new template, reply marker, unverified decision, or
		// changed verb partition around the owner's negative evidence.
		o.resetActionLocked(d.Account, d.Action, false)
		return o.save()
	}
	if d.Edited && reply {
		// ADP-11's light-edit exception cannot shelter templated siblings
		// sharing the same action from ADP-9's strict edit reset.
		if templates := o.st.Classes[key(d.Account, d.Action, false)]; templates != nil {
			o.resetGroupLocked(templates, false)
		}
	}
	if !eligible(d.Verb) || o.cfg.UserContent(d.Account) || len(d.Account) > 64 || len(d.Action) > 64 || strings.ContainsAny(d.Account+d.Action, "\x00") || d.Amount < 0 {
		return o.save()
	}
	if group == nil {
		if len(o.st.Classes) >= MaxClasses || (!reply && (!d.Verified || d.Edited || !shapeOK)) {
			return o.save()
		}
		group = &class{Account: d.Account, Action: d.Action, Verb: d.Verb, Reply: reply, Last: o.st.Latest}
		o.st.Classes[k] = group
	}
	group.Last = o.st.Latest
	if reply {
		c = group
	} else {
		if !d.Verified || d.Edited || !shapeOK || !d.At.After(o.st.Latest.Add(-EvidenceWindow)) {
			return o.save()
		}
		if c == nil {
			if len(group.Cohorts) >= MaxCohorts {
				return o.save() // never churn earned cohorts for novel shapes
			}
			if group.Cohorts == nil {
				group.Cohorts = map[string]*class{}
			}
			c = &class{Account: d.Account, Action: d.Action, Verb: d.Verb, Snooze: group.Snooze}
			group.Cohorts[cohort] = c
		}
	}
	if reply {
		// Every answered reply, verified or not, is in the edit rate.
		c.Recent = append(c.Recent, d.Edited)
		if len(c.Recent) > EditWindow {
			c.Recent = c.Recent[len(c.Recent)-EditWindow:]
		}
	}
	if !d.Verified || d.Edited || !shapeOK {
		return o.save() // unverified, edited, or oversized evidence never counts
	}
	day := d.At.UTC().Format("2006-01-02")
	if c.Run == 0 {
		c.Since, c.Fixed, c.Templated = d.At, fixed, ok
		c.Recipients, c.SameRcpt = sorted(d.Recipients), true
		c.Days = map[string]int{}
	} else {
		c.Templated = c.Templated && ok && equalMap(c.Fixed, fixed)
		c.SameRcpt = c.SameRcpt && sameRecipients(c.Recipients, d.Recipients)
	}
	c.Last = o.st.Latest
	c.Run++
	if day >= o.st.Latest.Add(-EvidenceWindow).UTC().Format("2006-01-02") {
		c.Days[day]++
	}
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
	return eligible(c.Verb) && !o.cfg.UserContent(c.Account)
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
	if len(b) > MaxStateBytes {
		return errors.New("attention: state exceeds size limit")
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
	return fmt.Sprintf("You approved this template for %s on %s %d times unchanged since %s.", c.Action, c.Account, c.Run, since)
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

// Suggestions returns earned evidence cohorts in stable order, up to the
// available short-ID capacity. ADP-9 cohorts independently earn their
// threshold; ADP-11 retains its reply count and edit-rate window. Returned
// rules are detached drafts, never authority. Matching recipients throughout
// the run fix the recipients in the drafted rule.
func (o *Optimizer) Suggestions() ([]Suggestion, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.advanceLocked(o.cfg.Now())
	return o.suggestionsLocked()
}

// suggestionsLocked snapshots current evidence while the caller owns mu.
func (o *Optimizer) suggestionsLocked() ([]Suggestion, error) {
	var out []Suggestion
	for _, c := range o.candidatesLocked() {
		if !o.earnedLocked(c) {
			continue
		}
		out = append(out, Suggestion{})
		if c.Short == "" {
			s, err := o.shortLocked()
			if errors.Is(err, ErrShortIDs) {
				out = out[:len(out)-1]
				continue // keep the already-addressable drafts usable at capacity
			}
			if err != nil {
				return nil, err
			}
			c.Short = s
		}
		r := &grants.Rule{Action: c.Action, PerRecord: 1, PerDay: 1, Reply: c.Reply}
		if len(c.Fixed) > 0 {
			r.Params = cloneFixed(c.Fixed)
		}
		r.PerDay = max(r.PerDay, median(c.Days))
		if c.SameRcpt && len(c.Recipients) > 0 && !c.Reply {
			r.Recipients = append([]string(nil), c.Recipients...)
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
	if err := o.save(); err != nil {
		return nil, err
	}
	return out, nil
}

func (o *Optimizer) shortLocked() (string, error) {
	taken := func(s string) bool {
		for _, c := range o.candidatesLocked() {
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

// Reoffer is the least time between offers for one account, and
// MaxOffers how many unanswered offers count as a NO.
const (
	Reoffer   = 7 * 24 * time.Hour
	MaxOffers = 2
)

// Due returns the suggestions to send the owner now (in the digest), and
// records them as offered, at most one per account per Reoffer interval.
// After MaxOffers unanswered offers the next due one counts
// as a NO (Decline) instead, so an ignored suggestion stops repeating.
func (o *Optimizer) Due(now time.Time) ([]Suggestion, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.advanceLocked(now)
	// Apply every timed-out NO before snapshotting any sibling. Otherwise
	// an earlier sibling could be returned after its evidence was reset by
	// a later sibling in this very call.
	for _, c := range o.candidatesLocked() {
		if c.Offers >= MaxOffers && now.Sub(c.Offered) >= Reoffer {
			o.resetActionLocked(c.Account, c.Action, true)
		}
	}
	all, err := o.suggestionsLocked()
	if err != nil {
		return nil, err
	}
	var out []Suggestion
	for _, sg := range all {
		var c *class
		for _, x := range o.candidatesLocked() {
			if x.Short == sg.Short {
				c = x
			}
		}
		if c == nil || !o.earnedLocked(c) || (!c.Offered.IsZero() && now.Sub(c.Offered) < Reoffer) {
			continue
		}
		if offered := o.st.AccountOffers[c.Account]; !offered.IsZero() && now.Sub(offered) < Reoffer {
			continue
		}
		o.st.AccountOffers[c.Account] = now
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
	o.advanceLocked(o.cfg.Now())
	for _, c := range o.candidatesLocked() {
		if c.Short != "" && strings.EqualFold(c.Short, short) && o.earnedLocked(c) {
			o.resetActionLocked(c.Account, c.Action, true)
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
