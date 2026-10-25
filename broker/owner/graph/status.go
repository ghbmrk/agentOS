package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// MaxLine is the most characters a STATUS line may hold: one SMS (CH-12).
const MaxLine = 160

// gsm keeps s within the GSM-7 basic set and MaxLine characters. Printable
// ASCII is kept except the characters GSM-7 lacks or carries only in its
// extension table; anything else becomes '?'. A long line ends in "...".
func gsm(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < ' ' || r > '~' || strings.ContainsRune("`[]{}\\^~|", r) {
			r = '?'
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > MaxLine {
		out = out[:MaxLine-3] + "..."
	}
	return out
}

func (g *Graph) name(id string) string {
	if i, ok := g.index[id]; ok && g.nodes[i].Name != "" {
		return g.nodes[i].Name
	}
	return "an unnamed item"
}

// join lists names as "A", "A and B" or "A, B and C".
func join(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// domainNames names a failure domain by the names of the nodes that carry
// it, never by its label.
func (g *Graph) domainNames(d string) string {
	var names []string
	for _, n := range g.nodes {
		if contains(n.Domains, d) {
			names = append(names, g.name(n.ID))
		}
	}
	sort.Strings(names)
	return join(names)
}

// Line is STATUS's first line: the weakest class, how many failures take
// it, and the next action's text, or that nothing is needed (CH-12). Pass
// the result of Next. It is GSM-7 and at most MaxLine characters.
func (g *Graph) Line(next Proposal, ok bool) string {
	c, any := g.Weakest()
	if !any {
		return gsm("Nothing to protect is recorded yet.")
	}
	var take string
	switch g.Board()[c].ThiefNeed {
	case 1:
		take = "1 failure can take it"
	case 2:
		take = "2 failures together can take it"
	default:
		take = "it takes more than 2 failures"
	}
	act := "Nothing needed now."
	if g.Board()[c].ThiefNeed < 3 {
		act = "No fix is known yet."
	}
	if ok {
		act = "Next: " + next.Text
	}
	return gsm(fmt.Sprintf("Weakest is %s: %s. %s", c, take, act))
}

// singles returns the (asset, domain) pairs of class c where one domain
// takes the asset.
func (g *Graph) singles(c Class) map[[2]string]bool {
	out := map[[2]string]bool{}
	for _, cut := range g.CutSets(c) {
		if len(cut.Domains) == 1 {
			out[[2]string{cut.Asset, cut.Domains[0]}] = true
		}
	}
	return out
}

// Lines are STATUS's lists (A22 Graph, CLK-11), in order: each money,
// identity or safety asset one failure domain takes, with the fix that
// removes that cut where a candidate does without weakening any asset; each unset brake on a money or
// identity asset, with its page; each pair of safeguards required together
// that share a failure domain; each provider whose loss cuts the owner off.
// Lines name assets and things by the owner's names, never by ID or label.
func (g *Graph) Lines(candidates []Proposal) []string {
	var out []string
	add := func(s string) { out = append(out, gsm(s)) }

	ranked := g.rank(candidates)
	after := make([]map[Class]map[[2]string]bool, len(ranked))
	for i, r := range ranked {
		h, _ := g.Apply(r.p) // rank kept only proposals that apply
		after[i] = map[Class]map[[2]string]bool{}
		for _, c := range []Class{Money, Identity, Safety} {
			after[i][c] = h.singles(c)
		}
	}
	done := map[[2]string]bool{}
	for _, c := range []Class{Money, Identity, Safety} {
		var keys [][2]string
		for k := range g.singles(c) {
			if !done[k] {
				keys = append(keys, k)
			}
		}
		sort.Slice(keys, func(i, j int) bool {
			if a, b := g.name(keys[i][0]), g.name(keys[j][0]); a != b {
				return a < b
			}
			return g.domainNames(keys[i][1]) < g.domainNames(keys[j][1])
		})
		for _, k := range keys {
			done[k] = true
			cause := "of " + g.domainNames(k[1])
			switch {
			case k[1] == SelfDomain(k[0]) || g.onlyCarrier(k[1], k[0]):
				cause = "of its own maker or provider"
			case strings.Contains(cause, " and "):
				cause = "shared by " + g.domainNames(k[1])
			}
			s := fmt.Sprintf("%s (%s) is lost to one failure %s.", g.name(k[0]), c, cause)
			for i, r := range ranked {
				if r.acceptable() && !after[i][c][k] {
					s += " Fix: " + r.p.Text
					break
				}
			}
			add(s)
		}
	}

	type brake struct{ asset, brake, page string }
	var brakes []brake
	for _, e := range g.edges {
		if e.Kind != Brake {
			continue
		}
		b := g.nodes[g.index[e.From[0]]]
		a := g.nodes[g.index[e.To]]
		if b.Set || !(hasClass(a, Money) || hasClass(a, Identity)) {
			continue
		}
		brakes = append(brakes, brake{g.name(a.ID), g.name(b.ID), b.Page})
	}
	sort.Slice(brakes, func(i, j int) bool {
		if brakes[i].asset != brakes[j].asset {
			return brakes[i].asset < brakes[j].asset
		}
		return brakes[i].brake < brakes[j].brake
	})
	for _, b := range brakes {
		where := "with the provider"
		if b.page != "" {
			where = "at " + b.page
		}
		add(fmt.Sprintf("%s: %s is off. Turn it on %s.", b.asset, b.brake, where))
	}

	var pairs []string
	seen := map[string]bool{}
	for _, e := range g.edges {
		if !control(e.Kind) || len(e.From) < 2 {
			continue
		}
		for i, x := range e.From {
			for _, y := range e.From[i+1:] {
				if !g.shareDomain(x, y) {
					continue
				}
				names := []string{g.name(x), g.name(y)}
				sort.Strings(names)
				s := fmt.Sprintf("%s and %s fail together, so needing both does not protect %s. Use two that fail separately.",
					names[0], names[1], g.name(e.To))
				if !seen[s] {
					seen[s] = true
					pairs = append(pairs, s)
				}
			}
		}
	}
	sort.Strings(pairs)
	for _, s := range pairs {
		add(s)
	}

	cutBy := map[string]map[string]bool{}
	for _, c := range Classes {
		cut, _ := g.CutOffs(c)
		for _, x := range cut {
			for _, p := range x.Providers {
				if cutBy[p] == nil {
					cutBy[p] = map[string]bool{}
				}
				cutBy[p][g.name(x.Asset)] = true
			}
		}
	}
	var provs []string
	for p := range cutBy {
		provs = append(provs, p)
	}
	sort.Slice(provs, func(i, j int) bool { return g.name(provs[i]) < g.name(provs[j]) })
	for _, p := range provs {
		add(fmt.Sprintf("Losing %s cuts you off from %s.", g.name(p), join(sortedKeys(cutBy[p]))))
	}
	return out
}

func hasClass(n Node, c Class) bool {
	for _, a := range n.Assets {
		if a == c {
			return true
		}
	}
	return false
}

func (g *Graph) shareDomain(x, y string) bool {
	for _, d := range g.nodes[g.index[x]].Domains {
		if contains(g.nodes[g.index[y]].Domains, d) {
			return true
		}
	}
	return false
}

// DefaultIdle is how long an account may go unused before it is listed as
// idle (D-152): twelve months.
const DefaultIdle = 365 * 24 * time.Hour

// Idle lists the accounts whose LastUse is set and older than threshold
// (DefaultIdle when threshold is zero or less), oldest first (D-152).
func (g *Graph) Idle(now time.Time, threshold time.Duration) []string {
	if threshold <= 0 {
		threshold = DefaultIdle
	}
	var idle []Node
	for _, n := range g.nodes {
		if n.Kind == Account && !n.LastUse.IsZero() && now.Sub(n.LastUse) > threshold {
			idle = append(idle, n)
		}
	}
	sort.Slice(idle, func(i, j int) bool {
		if !idle[i].LastUse.Equal(idle[j].LastUse) {
			return idle[i].LastUse.Before(idle[j].LastUse)
		}
		return idle[i].ID < idle[j].ID
	})
	out := make([]string, len(idle))
	for i, n := range idle {
		out[i] = n.ID
	}
	return out
}

// Counts is how many accounts and devices the graph holds.
type Counts struct{ Accounts, Devices int }

// Count counts the graph's accounts and devices (D-152).
func (g *Graph) Count() Counts {
	var c Counts
	for _, n := range g.nodes {
		switch n.Kind {
		case Account:
			c.Accounts++
		case Device:
			c.Devices++
		}
	}
	return c
}

func plural(n int, one string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %ss", n, one)
}

// CountLine reads like "12 accounts, 4 devices (+2 this month)", the change
// taken against start, the month's starting count the caller keeps.
func (g *Graph) CountLine(start Counts) string {
	c := g.Count()
	d := c.Accounts + c.Devices - start.Accounts - start.Devices
	change := "no change this month"
	if d != 0 {
		change = fmt.Sprintf("%+d this month", d)
	}
	return gsm(fmt.Sprintf("%s, %s (%s)", plural(c.Accounts, "account"), plural(c.Devices, "device"), change))
}

// Span is a stretch of time, From inclusive, To exclusive.
type Span struct{ From, To time.Time }

// Downtime is the length of the union of every gap between consecutive log
// entries longer than gap and every failed-connection span, clipped to
// [from, to) (D-152). The window's edges count as entries only on a side
// with no entry at or beyond them, so a quiet stretch at either end counts
// when it is longer than gap. A window with no entries at all is all
// downtime.
func Downtime(entries []time.Time, failed []Span, from, to time.Time, gap time.Duration) time.Duration {
	if !to.After(from) {
		return 0
	}
	if len(entries) == 0 {
		return to.Sub(from)
	}
	pts := append([]time.Time(nil), entries...)
	sort.Slice(pts, func(i, j int) bool { return pts[i].Before(pts[j]) })
	if pts[0].After(from) {
		pts = append([]time.Time{from}, pts...)
	}
	if pts[len(pts)-1].Before(to) {
		pts = append(pts, to)
	}
	var spans []Span
	for i := 1; i < len(pts); i++ {
		if pts[i].Sub(pts[i-1]) > gap {
			spans = append(spans, Span{pts[i-1], pts[i]})
		}
	}
	spans = append(spans, failed...)
	var clipped []Span
	for _, s := range spans {
		if s.From.Before(from) {
			s.From = from
		}
		if s.To.After(to) {
			s.To = to
		}
		if s.To.After(s.From) {
			clipped = append(clipped, s)
		}
	}
	sort.Slice(clipped, func(i, j int) bool { return clipped[i].From.Before(clipped[j].From) })
	var total time.Duration
	var cur Span
	for i, s := range clipped {
		if i == 0 {
			cur = s
			continue
		}
		if s.From.After(cur.To) {
			total += cur.To.Sub(cur.From)
			cur = s
		} else if s.To.After(cur.To) {
			cur.To = s.To
		}
	}
	if len(clipped) > 0 {
		total += cur.To.Sub(cur.From)
	}
	return total
}

// onlyCarrier reports whether node id is the only node carrying domain d.
func (g *Graph) onlyCarrier(d, id string) bool {
	for _, n := range g.nodes {
		if contains(n.Domains, d) && n.ID != id {
			return false
		}
	}
	return true
}
