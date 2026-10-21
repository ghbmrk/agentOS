package browser

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/owner"
)

// Approval is what the owner approves for one action the gate refuses
// unsent (CLK-3 unknown submits, CH-10). Every field is one the gate read:
// from the page's snapshot, from what the agent typed on that page, or the
// canonical request itself, filtered like any output. Site text is quoted
// and capped, with its CH-12 fold beside it. The owner's approval is a key
// for a post whose content is Print (one tap per task may list several),
// so the kernel checks it and its log counts it (D-147).
type Approval struct {
	Origin string `json:"origin"` // the page's origin, scheme://host:port
	Page   string `json:"page"`   // the page the action is on
	Verb   string `json:"verb"`
	Role   string `json:"role,omitempty"`   // the control's role
	Label  string `json:"label,omitempty"`  // its visible name, quoted and capped
	Folded string `json:"folded,omitempty"` // the name's CH-12 fold, capped
	Target string `json:"target,omitempty"` // where a link or navigate goes
	Option string `json:"option,omitempty"`
	Text   string `json:"text,omitempty"` // typed and submitted
	// Fields is what the agent typed on this page, per field.
	Fields []Field `json:"fields,omitempty"`
	// FieldsOmitted counts typed fields past maxFields, which Print still
	// covers.
	FieldsOmitted int `json:"fields_omitted,omitempty"`
	// FieldsComplete is false while the snapshot shows no method, form
	// fields or hidden fields: the executor does not report them yet.
	FieldsComplete bool `json:"fields_complete"`
	// Request is the canonical request the gate would send.
	Request string `json:"request"`
	// To is what the approved post's to must name.
	To string `json:"to"`
	// Print is a keyed hash of the raw values behind every field and the
	// canonical request, apart from the declared token parameters. The
	// key is random and held only by this gate, so a print cannot be
	// matched across targets the filter shows alike, nor guessed.
	Print string `json:"print"`
}

// Field is one field the agent typed into.
type Field struct {
	Ref   string `json:"ref"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// printPrefix marks an approval print, versioned.
const printPrefix = "ap1:"

// Bounds on what an approval shows.
const (
	maxLabel  = 200
	maxFields = 32
)

// approval builds the approval for req, which reaches l, under g.mu.
func (g *Gate) approval(req Request, l link) Approval {
	show := func(s string) string { t, _ := g.filter.text(s); return t }
	target := g.untoken(l.target)
	shown := l
	shown.target = target
	if req.Verb == "navigate" {
		req.URL = g.untoken(req.URL)
	}
	origin, _ := originKey(g.page)
	a := Approval{Origin: origin, Page: show(g.page), Verb: req.Verb, Role: l.role,
		Target: show(target), Option: show(capText(req.Option, maxLabel)), Text: show(req.Text),
		Request: show(string(req.Encode())), To: show(shown.to())}
	if l.name != "" {
		a.Label = strconv.Quote(capText(l.name, maxLabel))
		a.Folded = capText(owner.SkeletonFold(l.name, true), maxLabel)
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
		a.Fields = append(a.Fields, Field{Ref: ref, Label: show(strconv.Quote(capText(name, maxLabel))),
			Value: show(capText(text, maxLabel))})
	}
	a.Print = printPrefix + hex.EncodeToString(h.Sum(nil))
	return a
}

// untoken drops the values of the recipe's token parameters from a URL,
// so a rotated session or anti-forgery token is the same request (CLK-3).
func (g *Gate) untoken(raw string) string {
	if len(g.tokens) == 0 {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	hit := false
	for k := range q {
		if g.tokens[k] {
			q[k], hit = []string{""}, true
		}
	}
	if !hit {
		return raw
	}
	u.RawQuery = q.Encode()
	return u.String()
}

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
