package attention

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// These are proposer storage limits, not authority or dispatch limits.
const (
	MaxCohorts     = 8
	MaxClasses     = 256
	EvidenceWindow = 90 * 24 * time.Hour
	MaxShapeBytes  = 4096
	MaxStateBytes  = 32 << 20
	stateVersion   = 2
)

// JSON sorts string-map keys and escapes delimiters, so order and embedded
// separators cannot merge distinct fixed templates. Verb changes do not
// inherit evidence. Record IDs are deliberately absent from fixedParams.
func cohortKey(v string, fixed map[string]string) (string, bool) {
	if fixed == nil {
		fixed = map[string]string{}
	}
	if !utf8.ValidString(v) {
		return "", false
	}
	for k, value := range fixed {
		if !utf8.ValidString(k) || !utf8.ValidString(value) {
			return "", false
		}
	}
	b, err := json.Marshal(struct {
		Verb  string            `json:"verb"`
		Fixed map[string]string `json:"fixed"`
	}{v, fixed})
	return string(b), err == nil && len(b) <= MaxShapeBytes
}

func cloneFixed(p map[string]string) map[string]string {
	out := make(map[string]string, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

func withinObservedBounds(c *class, d Decision) bool {
	if d.Amount < 0 || d.Amount > c.MaxAmount {
		return false
	}
	if !c.Reply && c.SameRcpt && !sameRecipients(c.Recipients, d.Recipients) {
		return false
	}
	return true
}

func (o *Optimizer) candidatesLocked() []*class {
	keys := make([]string, 0, len(o.st.Classes))
	for k := range o.st.Classes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []*class
	for _, k := range keys {
		g := o.st.Classes[k]
		if g.Reply {
			out = append(out, g)
			continue
		}
		shapes := make([]string, 0, len(g.Cohorts))
		for shape := range g.Cohorts {
			shapes = append(shapes, shape)
		}
		sort.Strings(shapes)
		for _, shape := range shapes {
			out = append(out, g.Cohorts[shape])
		}
	}
	return out
}

// Negative evidence applies across every shape and reply/non-reply marker
// for the same account/action. Declines also seed future cohorts' snooze,
// so changing a template cannot bypass the owner's NO to a suggestion.
func (o *Optimizer) resetActionLocked(account, action string, decline bool) {
	for _, g := range o.st.Classes {
		if g.Account != account || g.Action != action {
			continue
		}
		o.resetGroupLocked(g, decline)
	}
}

func (o *Optimizer) resetGroupLocked(g *class, decline bool) {
	if decline {
		g.Declined = true
		g.Snooze = 2 * o.threshold(g)
	}
	g.reset()
	g.Last = o.st.Latest
	for _, c := range g.Cohorts {
		c.reset()
		if decline {
			c.Snooze = 2 * o.threshold(c)
		}
	}
}

// advanceLocked uses the broker's monotonically advancing observation
// clock. Old observations cannot revive expired evidence. ADP-11's count
// and last-30 edit window remain unchanged; only its daily-cap buckets age.
func (o *Optimizer) advanceLocked(now time.Time) {
	if now.After(o.st.Latest) {
		o.st.Latest = now
	}
	cutoff := o.st.Latest.Add(-EvidenceWindow)
	accounts := map[string]bool{}
	for k, g := range o.st.Classes {
		if !g.Reply {
			for shape, c := range g.Cohorts {
				start := c.Since
				if start.IsZero() {
					start = c.Last
				}
				if !start.After(cutoff) {
					delete(g.Cohorts, shape)
				}
			}
			if len(g.Cohorts) == 0 && !g.Declined && g.Snooze == 0 && !g.Last.After(cutoff) {
				delete(o.st.Classes, k)
				continue
			}
		}
		accounts[g.Account] = true
	}
	for _, c := range o.candidatesLocked() {
		for day := range c.Days {
			if day < cutoff.UTC().Format("2006-01-02") {
				delete(c.Days, day)
			}
		}
	}
	for account := range o.st.AccountOffers {
		if !accounts[account] && o.st.Latest.Sub(o.st.AccountOffers[account]) >= Reoffer {
			delete(o.st.AccountOffers, account)
		}
	}
}

func (o *Optimizer) loadState() error {
	legacy := o.st.Version == 0
	if !legacy && o.st.Version != stateVersion {
		return errors.New("attention: unsupported state version")
	}
	if o.st.Seq < 0 || o.st.Necessary < 0 || o.st.Avoidable < 0 {
		return errors.New("attention: invalid saved counters")
	}
	if len(o.st.Classes) > MaxClasses {
		return errors.New("attention: too many saved classes")
	}
	if o.st.AccountOffers == nil {
		o.st.AccountOffers = map[string]time.Time{}
	}
	for k, g := range o.st.Classes {
		if g == nil || k != key(g.Account, g.Action, g.Reply) || len(g.Account) > 64 || len(g.Action) > 64 || strings.ContainsAny(g.Account+g.Action, "\x00") || g.Snooze < 0 || !eligible(g.Verb) {
			return errors.New("attention: invalid saved class")
		}
		// Existing v0/v2 countdowns predate the persistent decline marker.
		// Preserve their account/action floor for a future opposite kind.
		g.Declined = g.Declined || g.Snooze > 0
		if legacy {
			if g.Offered.After(o.st.AccountOffers[g.Account]) {
				o.st.AccountOffers[g.Account] = g.Offered
			}
			// Old IDs name the old combined class; never retain them after
			// migration, even when its homogeneous evidence can be reused.
			g.Short = ""
			g.Last = g.Since
			for day := range g.Days {
				at, err := time.Parse("2006-01-02", day)
				if err == nil && at.After(g.Last) {
					g.Last = at
				}
			}
			if !g.Reply {
				child := *g
				g.Cohorts = map[string]*class{}
				shape, ok := cohortKey(g.Verb, g.Fixed)
				if ok && g.Templated && g.Run > 0 {
					g.Cohorts[shape] = &child
				}
				g.reset()
			}
		}
		if len(g.Cohorts) > MaxCohorts || (g.Reply && len(g.Cohorts) > 0) {
			return errors.New("attention: too many saved cohorts")
		}
		for shape, c := range g.Cohorts {
			if c == nil || c.Reply || len(c.Cohorts) != 0 || c.Account != g.Account || c.Action != g.Action || !eligible(c.Verb) {
				return errors.New("attention: invalid saved cohort")
			}
			if c.Run > 0 {
				canonical, ok := cohortKey(c.Verb, c.Fixed)
				if !ok || canonical != shape || !c.Templated {
					return errors.New("attention: inconsistent saved cohort")
				}
			}
		}
	}
	o.advanceLocked(o.cfg.Now())
	ids := map[string]bool{}
	for _, c := range o.candidatesLocked() {
		if !boundedRecipients(c.Recipients) || c.Run < 0 || c.Snooze < 0 || len(c.Recent) > EditWindow || len(c.Days) > 91 || c.MaxAmount < 0 || c.Offers < 0 || c.Offers > MaxOffers {
			return errors.New("attention: invalid saved evidence")
		}
		if c.Run > 0 && !c.Reply && len(c.Days) == 0 {
			return errors.New("attention: saved cohort has no daily evidence")
		}
		// Reply approval counts outlive daily buckets. JSON omitempty drops
		// an aged-out empty map, so reconstruct it before the next Observe.
		if c.Reply && c.Days == nil {
			c.Days = map[string]int{}
		}
		for day, count := range c.Days {
			if _, err := time.Parse("2006-01-02", day); err != nil || count < 1 {
				return errors.New("attention: invalid saved daily count")
			}
		}
		if c.Short != "" {
			id := strings.ToUpper(c.Short)
			if ids[id] {
				return fmt.Errorf("attention: duplicate saved suggestion ID")
			}
			ids[id] = true
		}
	}
	o.st.Version = stateVersion
	o.advanceLocked(o.cfg.Now())
	if legacy {
		return o.save()
	}
	return nil
}

func sameRecipients(left, right []string) bool {
	a, b := sorted(left), sorted(right)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Verified source facts are still bounded before retaining them. Oversized
// observations may require approval but cannot consume unbounded proposer state.
func boundedRecipients(recipients []string) bool {
	if len(recipients) > 64 {
		return false
	}
	n := 0
	for _, r := range recipients {
		n += len(r)
	}
	return n <= MaxShapeBytes
}
