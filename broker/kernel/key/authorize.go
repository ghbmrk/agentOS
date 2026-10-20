package key

import (
	"fmt"
	"strconv"
)

// Source says who produced an argument. A bounded argument must come from the
// owner or the clerk, never the planner (KEY-2).
type Source string

const (
	SrcOwner   Source = "owner"
	SrcClerk   Source = "clerk"
	SrcPlanner Source = "planner"
)

// Arg is one typed argument and where it came from.
type Arg struct {
	Value  string
	Source Source
}

// Step is one proposed action, as the clerk sees it.
type Step struct {
	Verb      Verb
	Clerk     string
	Args      map[string]Arg
	Content   string   // content class of what is sent or posted
	Labels    []string // flow labels of the data the step carries
	Amount    int64    // spend, in minor units
	Recipient string
	Task      string
}

// Use is one charged step, recorded in the log.
type Use struct {
	At        int64
	Amount    int64
	Recipient string
	Task      string
}

// Ledger lists the uses charged to a chain prefix. The kernel builds it from
// the log, so the check is the same in the kernel, the clerk and the sim.
type Ledger interface {
	Uses(scope ID) []Use
}

// Changes is the revocation, pause and stop view derived from the log.
type Changes struct {
	Revoked map[ID]bool
	Paused  map[ID]bool
	Stopped bool
}

// Context is everything Authorize reads besides the key and the step.
type Context struct {
	Now     int64 // unix ms
	Changes *Changes
	Ledger  Ledger
}

// Refusal codes.
const (
	RMalformed = "malformed"
	RStopped   = "stopped"
	RRevoked   = "revoked"
	RPaused    = "paused"
	RExpired   = "expired"
	RClerk     = "clerk"
	RVerb      = "verb"
	RArg       = "arg"
	RContent   = "content"
	RLabels    = "labels"
	RSpendTask = "spend-task"
	RSpendDay  = "spend-day"
	RRate      = "rate"
	RUses      = "uses"
)

// Refusal is a closed reason code plus detail for the log.
type Refusal struct {
	Code   string
	Detail string
}

func (r *Refusal) Error() string { return r.Code + ": " + r.Detail }

func refuse(code, f string, a ...any) *Refusal {
	return &Refusal{Code: code, Detail: fmt.Sprintf(f, a...)}
}

func in(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// live checks the parts of a key's state that no step changes: the stop, the
// chain's revocation and pause, and expiry.
func (v *Verified) live(c Context) *Refusal {
	if c.Changes == nil {
		return refuse(RMalformed, "no revocation view")
	}
	if c.Changes.Stopped {
		return refuse(RStopped, "stop is in force")
	}
	for _, id := range v.IDs {
		if c.Changes.Revoked[id] {
			return refuse(RRevoked, "%s", id)
		}
		if c.Changes.Paused[id] {
			return refuse(RPaused, "%s", id)
		}
	}
	if l := v.Limits; l.NotAfter != nil && c.Now >= *l.NotAfter {
		return refuse(RExpired, "expired at %d", *l.NotAfter)
	}
	return nil
}

// Authorize is the whole key check: one pure function, shared by the kernel
// and every clerk (KEY-2). It fails closed on a missing view.
func (v *Verified) Authorize(s Step, c Context) *Refusal {
	if r := v.live(c); r != nil {
		return r
	}
	l := v.Limits
	if s.Clerk != l.Clerk {
		return refuse(RClerk, "key is for %s", l.Clerk)
	}
	if !in(l.Verbs, string(s.Verb)) {
		return refuse(RVerb, "%s", s.Verb)
	}
	if !ArgsDeclared(s) {
		return refuse(RArg, "%s takes exactly %v", s.Verb, argNames[s.Verb])
	}
	if l.Content != nil && !in(l.Content, s.Content) {
		return refuse(RContent, "%q", s.Content)
	}
	if l.Labels != nil {
		for _, x := range s.Labels {
			if !in(l.Labels, x) {
				return refuse(RLabels, "%q", x)
			}
		}
	}
	for name, b := range l.Args {
		a, ok := s.Args[name]
		if !ok || a.Source == SrcPlanner || (a.Source != SrcOwner && a.Source != SrcClerk) {
			return refuse(RArg, "%s missing or not from owner or clerk", name)
		}
		if b.OneOf != nil && !in(b.OneOf, a.Value) {
			return refuse(RArg, "%s outside set", name)
		}
		if b.Min != nil || b.Max != nil {
			n, err := strconv.ParseInt(a.Value, 10, 64)
			if err != nil || (b.Min != nil && n < *b.Min) || (b.Max != nil && n > *b.Max) {
				return refuse(RArg, "%s outside range", name)
			}
		}
	}
	if s.Amount < 0 {
		return refuse(RMalformed, "negative amount")
	}
	return v.caps(s, c, false)
}

// caps checks every cap against the ledger as if s were charged now;
// spendOnly skips the rate and use caps, which count steps, not metered usage.
func (v *Verified) caps(s Step, c Context, spendOnly bool) *Refusal {
	if len(v.Limits.Caps) > 0 && c.Ledger == nil {
		return refuse(RMalformed, "no ledger")
	}
	for _, cp := range v.Limits.Caps {
		if spendOnly && cp.Kind != KSpendTask && cp.Kind != KSpendDay {
			continue
		}
		var n, sum int64
		for _, u := range c.Ledger.Uses(cp.Scope) {
			switch cp.Kind {
			case KSpendTask:
				if u.Task == s.Task {
					sum += u.Amount
				}
			case KSpendDay:
				if u.At > c.Now-DayMS {
					sum += u.Amount
				}
			case KRateDay:
				if u.At > c.Now-DayMS {
					n++
				}
			case KRateRecipient:
				if u.At > c.Now-DayMS && u.Recipient == s.Recipient {
					n++
				}
			case KUses:
				n++
			}
		}
		switch cp.Kind {
		case KSpendTask:
			if sum+s.Amount > cp.N {
				return refuse(RSpendTask, "cap %d", cp.N)
			}
		case KSpendDay:
			if sum+s.Amount > cp.N {
				return refuse(RSpendDay, "cap %d", cp.N)
			}
		case KRateDay, KRateRecipient:
			if n+1 > cp.N {
				return refuse(RRate, "%s cap %d", cp.Kind, cp.N)
			}
		case KUses:
			if n+1 > cp.N {
				return refuse(RUses, "cap %d", cp.N)
			}
		}
	}
	return nil
}

// Spend is the check a metered call (a model call, a paid API call) makes
// before it runs: the key is live and its spend caps hold for amount more
// under task (LOG-7). Spend is authorized by the funding key's spend caveat,
// whatever clerk the key was issued for, and a key with no spend cap funds
// nothing. The same function runs in the clerk and in the kernel that records
// the usage.
func (v *Verified) Spend(task string, amount int64, c Context) *Refusal {
	if r := v.live(c); r != nil {
		return r
	}
	if amount < 0 {
		return refuse(RMalformed, "negative amount")
	}
	capped := false
	for _, cp := range v.Limits.Caps {
		capped = capped || cp.Kind == KSpendTask || cp.Kind == KSpendDay
	}
	if !capped {
		return refuse(RMalformed, "no spend cap")
	}
	return v.caps(Step{Task: task, Amount: amount}, c, true)
}
