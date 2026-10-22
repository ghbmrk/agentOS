package browser

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/owner"
)

// Approval is what the owner approves for one action the gate refuses
// unsent (CLK-3 unknown submits, CH-10). Every field is one the gate read:
// from the page's snapshot, from what the agent typed on that page, or the
// canonical request itself, filtered like any output. Site text is quoted
// and capped, with its CH-12 fold beside it. The owner approves it as a
// key for a post whose content is Print, or as the task's approval over
// Site and Print, which covers the task's later submits on Site (D-147).
type Approval struct {
	Origin string `json:"origin"` // the page's origin, scheme://host:port
	// Site is the site the request reaches (site), which a task approval
	// names: one tap covers the task's later submits there (CLK-3).
	Site   string `json:"site"`
	Page   string `json:"page"` // the page the action is on
	Verb   string `json:"verb"`
	Role   string `json:"role,omitempty"`   // the control's role
	Label  string `json:"label,omitempty"`  // its visible name, quoted and capped
	Folded string `json:"folded,omitempty"` // the name's CH-12 fold, capped
	Target string `json:"target,omitempty"` // where a link or navigate goes
	Option string `json:"option,omitempty"` // quoted and capped
	// Text is what the agent typed and submits with it, quoted and capped:
	// agent text, never the owner's or the site's wording.
	Text string `json:"text,omitempty"`
	// Fields is what the agent typed on this page, per field.
	Fields []Field `json:"fields,omitempty"`
	// FieldsOmitted counts typed fields past maxFields, which Print still
	// covers.
	FieldsOmitted int `json:"fields_omitted,omitempty"`
	// Secret is the word that marks the request's screen as one that may
	// reveal or create a secret (VRB-1, CLK-5 "Secret screens"), "" if
	// none. No task approval covers such a request, so the card asks only
	// for this exact approval, never the task's tap.
	Secret string `json:"secret,omitempty"`
	// Unknown names what the gate cannot read and the prompt must say is
	// unknown: the accessibility snapshot shows no method, hidden fields
	// or untyped fields, those the agent did not type (K15).
	Unknown []string `json:"unknown"`
	// Request is the canonical request the gate would send, capped.
	Request string `json:"request"`
	// To is what the approved post's to must name: the control and its
	// target, then the print, so two different submits are two effects
	// to the kernel's duplicate guard (KRN-8).
	To string `json:"to"`
	// Print is a keyed hash of the raw values behind every field and the
	// canonical request, apart from the declared token values. The key is
	// random and held only by this gate, so a print cannot be matched
	// across targets the filter shows alike, nor guessed.
	Print string `json:"print"`
}

// Field is one field the agent typed into. Value is agent text, quoted
// and capped.
type Field struct {
	Ref   string `json:"ref"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// withheld stands for page text the agent was not shown.
const withheld = "[withheld]"

// unknown is what no approval can show yet (K15).
var unknown = []string{"method", "hidden fields", "untyped fields"}

// printPrefix marks an approval print, versioned.
const printPrefix = "ap1:"

// Bounds on what an approval shows.
const (
	maxLabel   = 200
	maxFields  = 32
	maxRequest = 8192
)

// approval builds the approval for req, which reaches l, under g.mu. The
// print covers the raw page; what the approval shows is the page as the
// agent saw it (shown: after omission and the filter, a ref the agent never
// saw is withheld), filtered again, then quoted, capped and folded, so no
// copy of a value the gate removes survives in another form.
func (g *Gate) approval(req Request, l link) Approval {
	show := func(s string, n int) string { t, _ := g.filter.text(s); return capText(t, n) }
	quote := func(s string) string { return strconv.Quote(show(s, maxLabel)) }
	target := g.untoken(l.target)
	shown := link{target: target}
	if req.Ref != "" {
		var seen bool
		if shown, seen = g.shown[req.Ref]; !seen {
			shown = link{role: l.role, name: withheld, target: withheld}
		}
		if l.target == "" {
			shown.target = ""
		} else if seen {
			shown.target = g.untoken(shown.target)
		}
	}
	if req.Verb == "navigate" {
		req.URL = g.untoken(req.URL)
	}
	origin, _ := originKey(g.page)
	// A control that names no target, or only script, acts on the page's own
	// site. Any other target is the site it names, and one with no http(s)
	// site (a URL a browser reads differently from url.Parse) has none, so
	// no task approval covers it (CLK-3).
	reach := l.target
	if reach == "" || strings.HasPrefix(strings.ToLower(strings.TrimSpace(reach)), "javascript:") {
		reach = g.page
	}
	a := Approval{Origin: origin, Site: site(reach), Page: show(g.untoken(g.page), MaxURL), Verb: req.Verb, Role: show(shown.role, maxLabel),
		Target: show(shown.target, MaxURL), Unknown: unknown, Request: show(string(req.Encode()), maxRequest)}
	a.Secret = g.secretScreen(l)
	if shown.name != "" {
		a.Label = quote(shown.name)
		a.Folded = capText(owner.SkeletonFold(show(shown.name, maxLabel), true), maxLabel)
	}
	if req.Option != "" {
		a.Option = quote(req.Option)
	}
	if req.Text != "" {
		a.Text = quote(req.Text)
	}
	h := hmac.New(sha256.New, g.secret)
	put := func(s string) { h.Write([]byte(strconv.Itoa(len(s)) + ":" + s)) }
	for _, s := range []string{g.untoken(g.page), req.Verb, l.role, l.name, target, string(req.Encode())} {
		put(s)
	}
	var refs []string
	for ref, f := range g.typed {
		if f.url == g.page {
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	for i, ref := range refs {
		name, text := g.refs[ref].name, g.typed[ref].text
		put(ref)
		put(name)
		put(text)
		if i >= maxFields {
			a.FieldsOmitted++
			continue
		}
		label := withheld
		if f, ok := g.shown[ref]; ok {
			label = f.name
		}
		a.Fields = append(a.Fields, Field{Ref: ref, Label: quote(label), Value: quote(text)})
	}
	a.Print = printPrefix + hex.EncodeToString(h.Sum(nil))
	a.To = show(shown.to(), MaxURL+maxLabel) + " · " + a.Print
	return a
}

// untoken blanks the values of the recipe's token parameters in a URL's
// query, so a rotated session or anti-forgery token is the same request
// (CLK-3). It edits the raw query in place and keeps every other byte, so
// the print covers exactly what is sent. A value with anything but plain
// token characters is kept: blanking it could hide a pair a server splits
// out of it (";to=…").
func (g *Gate) untoken(raw string) string {
	if len(g.tokens) == 0 {
		return raw
	}
	end := len(raw)
	if h := strings.IndexByte(raw, '#'); h >= 0 {
		end = h
	}
	q := strings.IndexByte(raw[:end], '?')
	if q < 0 {
		return raw
	}
	pairs := strings.Split(raw[q+1:end], "&")
	for i, p := range pairs {
		k, v, _ := strings.Cut(p, "=")
		if g.tokens[k] && tokenValue.MatchString(v) {
			pairs[i] = k + "="
		}
	}
	return raw[:q+1] + strings.Join(pairs, "&") + raw[end:]
}

// tokenValue is a value untoken may blank.
var tokenValue = regexp.MustCompile(`^[A-Za-z0-9._~-]*$`)

// capText cuts s to at most n bytes on a rune boundary, marking the cut.
func capText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
