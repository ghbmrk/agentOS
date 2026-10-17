package browser

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// ADP-14 holds a submit by method, but a site can change state on a GET:
// an unsubscribe or confirm link, a one-click cancel. The gate holds a
// credentialed GET to a URL that reads as such an action for the owner's
// approval, like a POST (ADP-14-get). The patterns are a heuristic that
// fails closed; part 2's network egress gate is the boundary (AS1).

// actionWords are path or query words that name a state change.
var actionWords = wordSet(`unsubscribe unsub subscribe resubscribe optout optin confirm confirmation
	verify verification activate deactivate cancel cancellation delete remove approve accept decline
	reject revoke logout signout rsvp unfollow disable enable reset archive unlink disconnect claim
	redeem vote`)

// tokenWords in a query key mark a one-time or anti-forgery token, which a
// link carries when following it does something.
var tokenWords = wordSet(`token nonce csrf xsrf sig signature hmac otp`)

func wordSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// words splits s on punctuation, letter-digit boundaries and camelCase,
// lower-cased.
func words(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(s)
	for i, r := range rs {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if len(cur) > 0 {
			p := cur[len(cur)-1]
			upperStart := unicode.IsUpper(r) && (unicode.IsLower(p) ||
				unicode.IsUpper(p) && i+1 < len(rs) && unicode.IsLower(rs[i+1]))
			if upperStart || unicode.IsDigit(r) != unicode.IsDigit(p) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return out
}

// actionStems catch inflected and run-together forms of the action words
// ("unsubscribed", "oneclickunsubscribe", "canceled", "deletion"). A stem
// inside an unrelated word over-matches, which fails closed (AS2).
var actionStems = strings.Fields(`unsub optout cancel delet remov confirm verif revok`)

// hasWord reports whether a word, or two adjacent words joined ("opt-out"),
// is in set.
func hasWord(ws []string, set map[string]bool) bool {
	for i, w := range ws {
		if set[w] || i+1 < len(ws) && set[w+ws[i+1]] {
			return true
		}
	}
	return false
}

// hasAction reports whether ws name a state change: an action word, a
// word containing an action stem, or two adjacent words that start with
// one ("un subscribed"). A stem that only spans the joint ("explo|re mov|ies")
// does not count.
func hasAction(ws []string) bool {
	if hasWord(ws, actionWords) {
		return true
	}
	for i, w := range ws {
		for _, s := range actionStems {
			if strings.Contains(w, s) || i+1 < len(ws) && strings.HasPrefix(w+ws[i+1], s) {
				return true
			}
		}
	}
	return false
}

type stateLinks struct {
	prefixes []prefix
}

type prefix struct{ origin, path string }

// newStateLinks validates a recipe's own patterns: absolute URL prefixes,
// with a path and no query, on a declared origin. They only add to the
// defaults.
func newStateLinks(list []string, origins Origins) (stateLinks, error) {
	var s stateLinks
	for _, p := range list {
		u, err := url.Parse(p)
		key, ok := originKey(p)
		if err != nil || !ok || !origins[key] || !strings.HasPrefix(u.Path, "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return stateLinks{}, errors.New("browser: state link pattern must be a URL path prefix on a declared origin")
		}
		s.prefixes = append(s.prefixes, prefix{key, u.Path})
	}
	return s, nil
}

// match reports whether a GET to raw may change state. A URL that cannot
// be parsed matches (fail closed). A hash-routed app keeps its route in the
// fragment ("/#/unsubscribe?token=…"), so the fragment is checked like a
// path and query too.
func (s stateLinks) match(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	key, _ := originKey(raw)
	for _, p := range s.prefixes {
		if key == p.origin && strings.HasPrefix(u.Path, p.path) {
			return true
		}
	}
	fpath, fquery, _ := strings.Cut(u.Fragment, "?")
	return pathQueryMatch(u.Path, u.RawQuery) || pathQueryMatch(fpath, fquery)
}

// pathQueryMatch applies the word rules to a decoded path and a raw query.
func pathQueryMatch(path, rawQuery string) bool {
	if hasAction(words(path)) {
		return true
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return true
	}
	for k, vs := range q {
		kw := words(k)
		if hasAction(kw) || hasWord(kw, tokenWords) {
			return true
		}
		for _, v := range vs {
			if hasAction(words(v)) {
				return true
			}
		}
	}
	return false
}

// link is what the last snapshot showed for one ref: its role, the name a
// click on it acts under and the URL it follows, if any. A click on any
// part of a clickable element (a link, a button, an element with a pointer
// cursor) activates the outermost one, so name is the text of that
// element's whole subtree: its accessible name, nested names and text
// lines ("[icon] Unsubscribe"). target is the ref's own `/url:` or, inside
// a link, the nearest enclosing link's, resolved against the page.
type link struct {
	role   string
	name   string
	target string
	// clickable is set inside a clickable element. A form field or
	// container outside one ("Confirm password") is not judged by name.
	clickable bool
	// dismiss is set for a dialog's "Cancel" or "Close" with no target.
	dismiss bool
}

// held reports whether a click on l may change state at the site.
func (l link) held(s stateLinks) bool {
	if l.target != "" && s.match(l.target) {
		return true
	}
	return l.clickable && !l.dismiss && hasAction(words(l.name))
}

// clickRoles are the roles whose activation is the click itself.
var clickRoles = wordSet(`link button menuitem menuitemcheckbox menuitemradio tab option checkbox
	radio switch treeitem`)

// dismissNames close a dialog without acting on it.
var dismissNames = wordSet(`cancel close dismiss no notnow nothanks`)

// node is one line of a snapshot in its tree.
type node struct {
	depth     int
	role      string
	ref       string
	text      []string // the line's own name and text, then its children's
	url       string
	pointer   bool
	parent    *node
	childText *[]string
}

// parseRefs maps each element ref in a raw snapshot to a link. A ref is
// read only from the attributes after the element's name, never from a
// name or text value (page text), and a ref seen twice is left out; a
// left-out ref is refused at click (CRED-4). A line that cannot be parsed
// keeps its place in the tree and its raw text counts toward the
// enclosing element's name, which can only add holds.
func parseRefs(snapshot, page string) map[string]link {
	base, _ := url.Parse(page)
	root := &node{depth: -1}
	var all []*node
	stack := []*node{root}
	for _, line := range strings.Split(snapshot, "\n") {
		body := strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(body, "- ") {
			continue
		}
		depth := len(indent(line))
		for stack[len(stack)-1].depth >= depth {
			stack = stack[:len(stack)-1]
		}
		parent := stack[len(stack)-1]
		n := &node{depth: depth, parent: parent}
		if c := childRE.FindStringSubmatch(line); c != nil && strings.HasPrefix(strings.TrimSpace(c[1]), "- /") {
			// A property line. Only a direct `/url:` child names a target.
			if strings.TrimSpace(c[1]) == "- /url" && parent.url == "" {
				if href, err := url.Parse(yamlValue(c[2])); err == nil && base != nil {
					parent.url = base.ResolveReference(href).String()
				} else {
					parent.url = page + "#unparsed"
				}
			}
			continue
		}
		if end, ok := nameEnd(line); ok {
			head := strings.TrimLeft(unquoteKey(line[:end]), " \t")
			role, quoted, _ := strings.Cut(strings.TrimPrefix(head, "- "), " ")
			n.role = role
			if name, err := strconv.Unquote(quoted); err == nil {
				n.text = append(n.text, name)
			}
			rest := line[end:]
			attrs := attrsRE.FindString(rest)
			if m := refToken.FindStringSubmatch(attrs); m != nil {
				n.ref = m[1]
			}
			n.pointer = strings.Contains(attrs, "[cursor=pointer]")
			if v, ok := strings.CutPrefix(rest[len(attrs):], ":"); ok {
				if v = yamlValue(v); v != "" {
					n.text = append(n.text, v)
				}
			}
		} else {
			n.text = append(n.text, body[2:])
		}
		all = append(all, n)
		stack = append(stack, n)
	}
	// Each node's subtree text, children after the node's own.
	sub := map[*node][]string{}
	for i := len(all) - 1; i >= 0; i-- {
		n := all[i]
		sub[n] = append(append([]string{}, n.text...), sub[n]...)
		if p := n.parent; p != root {
			sub[p] = append(append([]string{}, sub[n]...), sub[p]...)
		}
	}
	refs := map[string]link{}
	seen := map[string]bool{}
	for _, n := range all {
		if n.ref == "" {
			continue
		}
		if seen[n.ref] {
			delete(refs, n.ref)
			continue
		}
		seen[n.ref] = true
		l := link{role: n.role}
		outer, dialog := n, false
		for a := n; a != root; a = a.parent {
			if clickRoles[a.role] || a.pointer {
				outer, l.clickable = a, true
			}
			if l.target == "" && a.role == "link" {
				l.target = a.url
			}
			dialog = dialog || a.role == "dialog" || a.role == "alertdialog"
		}
		l.name = strings.Join(strings.Fields(strings.Join(sub[outer], " ")), " ")
		l.dismiss = dialog && l.target == "" && dismissNames[strings.Join(words(l.name), "")]
		refs[n.ref] = l
	}
	return refs
}

// Hold is a request the gate keeps for the owner's approval instead of
// sending: a GET to URL on Origin, from a navigate or from a click or
// download on Ref. A click on an element that shows no target (a button
// named "Unsubscribe") is held with an empty URL, Origin and Method, and is
// bound to the ref's Role and Name.
type Hold struct {
	Verb   string
	Ref    string
	Role   string
	Name   string
	Origin string
	Method string
	URL    string
	req    Request
}

// maxHolds bounds the store; the oldest hold is dropped first, and
// approving a dropped hold sends nothing (AS4).
const maxHolds = 32

func (g *Gate) hold(req Request, l link) Result {
	var b [16]byte
	_, _ = rand.Read(b[:])
	id := "h" + hex.EncodeToString(b[:])
	h := Hold{Verb: req.Verb, Ref: req.Ref, Role: l.role, Name: l.name, URL: l.target, req: req}
	if l.target != "" {
		h.Origin, _ = originKey(l.target)
		h.Method = "GET"
	}
	if len(g.holdOrder) >= maxHolds {
		delete(g.holds, g.holdOrder[0])
		g.holdOrder = g.holdOrder[1:]
	}
	g.holds[id] = h
	g.holdOrder = append(g.holdOrder, id)
	return Result{Error: "held", Hold: id,
		Detail: "this link may change state at the site; held for the owner's approval (ADP-14)"}
}

func (g *Gate) dropHold(id string) {
	delete(g.holds, id)
	for i, h := range g.holdOrder {
		if h == id {
			g.holdOrder = append(g.holdOrder[:i:i], g.holdOrder[i+1:]...)
			break
		}
	}
}

// Held returns a held request for the broker's approval prompt.
func (g *Gate) Held(id string) (Hold, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	h, ok := g.holds[id]
	return h, ok
}

var errNotHeld = Result{Error: "not_held", Detail: "no such hold, or the URL is not the held one"}

// Release sends a held request once, on the owner's approval. It is the
// broker's call, not a protocol verb, so an agent cannot reach it. url
// must equal the held URL; any other value sends nothing and keeps the
// hold. A held click or download is sent only if a fresh snapshot shows
// the ref with the same role, name and target; otherwise the hold is void.
func (g *Gate) Release(ctx context.Context, id, url string) Result {
	g.mu.Lock()
	defer g.mu.Unlock()
	h, ok := g.holds[id]
	if !ok || url != h.URL {
		return errNotHeld
	}
	g.dropHold(id)
	if g.stopped {
		return stoppedResult
	}
	if h.Verb != "navigate" {
		snap, ok := g.roundtrip(ctx, Request{Verb: "snapshot"})
		if !ok {
			return snap
		}
		if l, seen := g.refs[h.Ref]; !snap.OK || !seen || l.role != h.Role || l.name != h.Name || l.target != h.URL {
			return Result{Error: "not_held", Detail: "the link changed since it was held; nothing was sent"}
		}
	}
	return g.send(ctx, h.req)
}
