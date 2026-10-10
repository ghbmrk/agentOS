// Package check judges a journal against the floor invariants, from its
// records alone (SIM-check). Each predicate walks the records itself and
// shares no code with the engine's own validation, so a defect in one is
// not hidden by the other.
//
// The same predicates run in property tests over generated journals, after
// the end-to-end journeys, and in the broker as a STATUS line (Note).
package check

import (
	"fmt"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Violation is one place where a journal breaks a rule.
type Violation struct {
	Rule   string // the requirement ID the rule enforces
	Seq    uint64 // the offending record, 0 for the journal as a whole
	ID     string // the intent, if any
	Detail string
}

func (v Violation) String() string {
	s := v.Rule
	if v.Seq > 0 {
		s += fmt.Sprintf(" at record %d", v.Seq)
	}
	if v.ID != "" {
		s += " (" + v.ID + ")"
	}
	return s + ": " + v.Detail
}

// View is a projection built from the journal that could show an intent's
// content: the engine's own status, a recall index, a digest.
type View interface {
	Name() string
	Shows(id string) bool // whether any of the intent's content is readable
}

// Options says how to judge a journal.
type Options struct {
	// Live allows attempts still in flight: a running broker has them, a
	// journal at rest (after Open's restart records) must not.
	Live bool
	// Views are the projections CAP-3 also checks.
	Views []View
}

// Rule is one predicate over a journal.
type Rule struct {
	Name  string // the requirement ID
	check func([]journal.Record, Options) []Violation
}

// Rules are the floor predicates. SIM-owner-hold adds the owner-message rule.
var Rules = []Rule{
	{"OP-3", dispatchGranted},
	{"OP-4", attemptsSettle},
	{"OP-5", trailComplete},
	{"CAP-3", erasedUnreadable},
}

// Journal judges records under every rule.
func Journal(recs []journal.Record, o Options) []Violation { return run(Rules, recs, o) }

func run(rules []Rule, recs []journal.Record, o Options) []Violation {
	var out []Violation
	for _, r := range rules {
		for _, v := range r.check(recs, o) {
			v.Rule = r.Name
			out = append(out, v)
		}
	}
	return out
}

// Engine judges a running engine's journal, with the engine's own status as
// a view. live is false only for an engine that is just opened and idle.
func Engine(e *journal.Engine, live bool) []Violation {
	return Journal(e.Trail(), Options{Live: live, Views: []View{EngineView{e}}})
}

// Note returns a STATUS note source: one line naming the first violation
// and how many there are, or "" while the journal is clean.
func Note(e *journal.Engine) func() string {
	return func() string {
		v := Engine(e, true)
		if len(v) == 0 {
			return ""
		}
		return fmt.Sprintf("Journal check failed (%s): %d violation(s), first %s", v[0].Rule, len(v), v[0])
	}
}

// EngineView is the engine's status of each intent.
type EngineView struct{ E *journal.Engine }

func (EngineView) Name() string { return "engine status" }

func (v EngineView) Shows(id string) bool {
	st, err := v.E.Get(id)
	if err != nil {
		return false
	}
	if st.Intent.Params != nil || st.Intent.Preconditions != nil {
		return true
	}
	for _, a := range st.Attempts {
		if a.Evidence != "" {
			return true
		}
		for _, c := range a.Cancels {
			if c.Detail != "" {
				return true
			}
		}
	}
	return false
}

// submitted maps each submitted ID to its first submission, so OP-3, OP-4
// and CAP-3 judge only records OP-5 accepts as belonging to an intent.
func submitted(recs []journal.Record) map[string]*journal.Intent {
	m := map[string]*journal.Intent{}
	for _, r := range recs {
		if r.Type == journal.RecSubmitted && r.Intent != nil && m[r.ID] == nil {
			m[r.ID] = r.Intent
		}
	}
	return m
}

// trailComplete (OP-5): the journal is one gapless trail, every record is a
// known kind, and every intent record belongs to an earlier submission.
func trailComplete(recs []journal.Record, _ Options) []Violation {
	var out []Violation
	seen := map[string]bool{}
	for i, r := range recs {
		bad := func(f string, a ...any) {
			out = append(out, Violation{Seq: r.Seq, ID: r.ID, Detail: fmt.Sprintf(f, a...)})
		}
		if r.Seq != uint64(i+1) {
			bad("sequence %d, want %d", r.Seq, i+1)
		}
		switch r.Type {
		case journal.RecStop, journal.RecResume, journal.RecEgress, journal.RecSleep:
			if r.ID != "" {
				bad("%s record names an intent", r.Type)
			}
		case journal.RecSubmitted:
			if r.Intent == nil || r.Intent.ID != r.ID || r.ID == "" {
				bad("submission without its intent")
			} else if seen[r.ID] {
				bad("submitted twice")
			}
			seen[r.ID] = true
		case journal.RecAuthorized, journal.RecDenied, journal.RecRecheckFailed, journal.RecDispatched,
			journal.RecObserved, journal.RecCancel, journal.RecQuality, journal.RecErased:
			if !seen[r.ID] {
				bad("%s for an intent never submitted", r.Type)
			}
		default:
			bad("unknown record type %q", r.Type)
		}
	}
	return out
}

// dispatchGranted (OP-3): an effect is dispatched only with a grant valid at
// that moment: an authorization not since withdrawn, no STOP in force
// (narrowing intents excepted), and no earlier successful revocation of the
// grant it names.
func dispatchGranted(recs []journal.Record, _ Options) []Violation {
	var out []Violation
	ins := submitted(recs)
	allowed := map[string]bool{}
	revoked := map[string]uint64{} // grant -> seq of the observation that revoked it
	stopped := false
	for _, r := range recs {
		switch r.Type {
		case journal.RecStop:
			stopped = true
			continue
		case journal.RecResume:
			stopped = false
			continue
		}
		in := ins[r.ID]
		if in == nil {
			continue
		}
		switch r.Type {
		case journal.RecAuthorized:
			allowed[r.ID] = true
		case journal.RecDenied, journal.RecRecheckFailed, journal.RecErased:
			allowed[r.ID] = false
		case journal.RecObserved:
			if r.Result == journal.ResultSucceeded && in.Account == journal.BrokerAccount &&
				in.Action == journal.ActionGrantRevoke && in.GrantRef != "" {
				if _, ok := revoked[in.GrantRef]; !ok {
					revoked[in.GrantRef] = r.Seq
				}
			}
		case journal.RecDispatched:
			bad := func(f string, a ...any) {
				out = append(out, Violation{Seq: r.Seq, ID: r.ID, Detail: fmt.Sprintf(f, a...)})
			}
			if !allowed[r.ID] {
				bad("dispatched without a standing authorization")
			}
			narrow := journal.Narrowing(*in)
			if stopped && !narrow {
				bad("dispatched while stopped")
			}
			if s, ok := revoked[in.GrantRef]; ok && in.GrantRef != "" && !narrow {
				bad("dispatched under grant %s, revoked at record %d", in.GrantRef, s)
			}
		}
	}
	return out
}

// attemptsSettle (OP-4): attempts are numbered in order, a new one starts
// only after the last was shown not applied, each observation follows the
// attempt's lifecycle, and at rest every attempt is settled or explicitly
// unknown.
func attemptsSettle(recs []journal.Record, o Options) []Violation {
	var out []Violation
	ins := submitted(recs)
	att := map[string][]journal.Result{}
	var order []string          // intents in order of first dispatch
	last := map[string]uint64{} // seq of each intent's open dispatch
	for _, r := range recs {
		if ins[r.ID] == nil {
			continue
		}
		bad := func(f string, a ...any) {
			out = append(out, Violation{Seq: r.Seq, ID: r.ID, Detail: fmt.Sprintf(f, a...)})
		}
		as := att[r.ID]
		switch r.Type {
		case journal.RecDispatched:
			if r.Attempt != len(as)+1 {
				bad("attempt %d, want %d", r.Attempt, len(as)+1)
				continue
			}
			if n := len(as); n > 0 && as[n-1] != journal.ResultNotApplied {
				bad("attempt %d started while attempt %d is %s", r.Attempt, n, as[n-1])
			}
			if len(as) == 0 {
				order = append(order, r.ID)
			}
			att[r.ID] = append(as, journal.ResultInFlight)
			last[r.ID] = r.Seq
		case journal.RecObserved:
			if r.Attempt < 1 || r.Attempt > len(as) {
				bad("observation of attempt %d, which was never dispatched", r.Attempt)
				continue
			}
			cur := as[r.Attempt-1]
			switch {
			case r.Result != journal.ResultSucceeded && r.Result != journal.ResultNotApplied && r.Result != journal.ResultUnknown:
				bad("result %q", r.Result)
			case cur == journal.ResultSucceeded || cur == journal.ResultNotApplied:
				bad("attempt %d already %s, observed %s", r.Attempt, cur, r.Result)
			case r.Result == journal.ResultUnknown && cur == journal.ResultUnknown:
				bad("attempt %d unknown twice", r.Attempt)
			default:
				as[r.Attempt-1] = r.Result
			}
		case journal.RecCancel:
			if r.Attempt < 1 || r.Attempt > len(as) {
				bad("cancel of attempt %d, which was never dispatched", r.Attempt)
			}
		}
	}
	if o.Live {
		return out
	}
	for _, id := range order {
		for i, res := range att[id] {
			if res == journal.ResultInFlight {
				out = append(out, Violation{Seq: last[id], ID: id,
					Detail: fmt.Sprintf("attempt %d neither settled nor marked unknown", i+1)})
			}
		}
	}
	return out
}

// erasedUnreadable (CAP-3): once an intent is erased, no record carries its
// content, nothing dispatches it, and no view shows it.
func erasedUnreadable(recs []journal.Record, o Options) []Violation {
	var out []Violation
	ins := submitted(recs)
	erased := map[string]uint64{}
	var order []string
	for _, r := range recs {
		if r.Type == journal.RecErased && ins[r.ID] != nil {
			if _, ok := erased[r.ID]; !ok {
				erased[r.ID] = r.Seq
				order = append(order, r.ID)
			}
		}
	}
	for _, r := range recs {
		at, ok := erased[r.ID]
		if !ok {
			continue
		}
		bad := func(f string, a ...any) {
			out = append(out, Violation{Seq: r.Seq, ID: r.ID, Detail: fmt.Sprintf(f, a...)})
		}
		switch r.Type {
		case journal.RecSubmitted:
			if r.Intent != nil && (r.Intent.Params != nil || r.Intent.Preconditions != nil) {
				bad("erased intent's parameters still in the journal")
			}
		case journal.RecObserved, journal.RecCancel:
			if r.Evidence != "" {
				bad("erased intent's evidence still in the journal")
			}
		case journal.RecDispatched:
			if r.Seq > at {
				bad("dispatched after it was erased")
			}
		}
	}
	for _, id := range order {
		for _, v := range o.Views {
			if v.Shows(id) {
				out = append(out, Violation{Seq: erased[id], ID: id, Detail: "erased intent readable from " + v.Name()})
			}
		}
	}
	return out
}
