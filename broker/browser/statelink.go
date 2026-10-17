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

// hasAction reports whether ws name a state change: an action word, or a
// word or adjacent pair containing an action stem.
func hasAction(ws []string) bool {
	if hasWord(ws, actionWords) {
		return true
	}
	for i, w := range ws {
		if i+1 < len(ws) {
			w += ws[i+1]
		}
		for _, s := range actionStems {
			if strings.Contains(w, s) {
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

// link is what the last snapshot showed for one ref. Only a link, or an
// element inside one, has a target; any other element is recorded with its
// role and name so its ref is known and a held click on it can be bound.
type link struct {
	isLink bool
	role   string
	name   string
	target string
}

// parseRefs maps each element ref in a raw snapshot to its role, name and,
// for a link, the target from its `/url:` child resolved against page.
// The first ref after the quoted name is the element's own (a ref inside
// the name is page text); refs on a line that cannot be parsed are left
// out, so a click on them is refused. A click on an element inside a link
// follows the link, so a nested element takes the nearest enclosing link's
// target and adds its own name to that link's.
func parseRefs(snapshot, page string) map[string]link {
	base, _ := url.Parse(page)
	refs := map[string]link{}
	type open struct {
		depth int
		l     link
	}
	var links []open
	lines := strings.Split(snapshot, "\n")
	for i, line := range lines {
		end, ok := nameEnd(line)
		if !ok {
			continue
		}
		m := refToken.FindStringSubmatch(line[end:])
		if m == nil {
			continue
		}
		head := strings.TrimLeft(unquoteKey(line[:end]), " \t")
		role, quoted, _ := strings.Cut(strings.TrimPrefix(head, "- "), " ")
		name, err := strconv.Unquote(quoted)
		if err != nil {
			name = ""
		}
		depth := len(indent(line))
		for len(links) > 0 && links[len(links)-1].depth >= depth {
			links = links[:len(links)-1]
		}
		l := link{isLink: role == "link", role: role, name: name}
		if l.isLink {
			// Only a direct child names the target, not a nested element's.
			child := -1
			for j := i + 1; j < len(lines) && len(indent(lines[j])) > depth; j++ {
				if child < 0 {
					child = len(indent(lines[j]))
				}
				if len(indent(lines[j])) != child {
					continue
				}
				c := childRE.FindStringSubmatch(lines[j])
				if c != nil && strings.TrimSpace(c[1]) == "- /url" {
					if href, err := url.Parse(yamlValue(c[2])); err == nil && base != nil {
						l.target = base.ResolveReference(href).String()
					}
					break
				}
			}
		}
		if len(links) > 0 {
			outer := links[len(links)-1].l
			if !l.isLink || l.target == "" {
				l.target = outer.target
			}
			l.isLink, l.name = true, strings.TrimSpace(outer.name+" "+l.name)
		}
		if role == "link" {
			links = append(links, open{depth, l})
		}
		refs[m[1]] = l
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
