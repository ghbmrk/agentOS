package inbox

import (
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/text/unicode/norm"
)

// World is what VRB-2 reads besides the message: the DKIM key records, the
// provider table, earlier deliveries, the owner's contacts, and the owner's
// last opens of each sender's mail; and what the alert guard reads (isAlert):
// the provider's authserv-id and the owner's alert senders. JSON names follow
// the eval's world.json.
type World struct {
	DKIMKeys      map[string]string `json:"dkim_keys"`
	ProviderTable []string          `json:"provider_table"`
	History       []Delivery        `json:"history"`
	Contacts      []string          `json:"contacts"`
	KnownSenders  []string          `json:"known_senders"`
	Today         string            `json:"today"`
	LastOpened    map[string]string `json:"last_opened"`
	AuthServ      string            `json:"authserv"`
	AlertSenders  []string          `json:"alert_senders"`
}

// unopenedDays is how long a sender's mail must have gone unopened, and how old
// its first mail must be, before the clerk may unsubscribe (D-141). It is a
// constant of the clerk: no world, planner or fixture sets it.
const unopenedDays = 90

// Delivery is one earlier message: who sent it, to which folder, and when.
type Delivery struct {
	From   string `json:"from"`
	Folder string `json:"folder"`
	Date   string `json:"date"`
}

// VRB-2 reasons, in the order the clauses run; the first that fails names it.
const (
	ROK                = "ok"
	RDuplicateHeader   = "duplicate-header"
	RNoListUnsubscribe = "no-list-unsubscribe"
	RMailtoOnly        = "mailto-only"
	RDKIMNone          = "dkim-none"
	RDKIMFail          = "dkim-fail"
	RDKIMNotCurrent    = "dkim-not-current"
	RDKIMUnaligned     = "dkim-unaligned"
	RNotOverSigned     = "not-over-signed"
	RDKIML             = "dkim-l-tag"
	RURLHost           = "url-host"
	RNoHistory         = "no-history"
	RLookalike         = "lookalike"
	RFirstMailRecent   = "first-mail-recent"
	RRecentlyOpened    = "recently-opened"
	RBadDate           = "bad-date"
)

var listed = []string{"from", "list-unsubscribe", "list-unsubscribe-post"}

// alabel is domain in IDNA A-label form, lower case and without a trailing
// dot, so a Unicode name and its punycode compare equal; "" when it is no
// valid IDNA name (MIG-3-R3, #2602). The registration profile maps nothing,
// so a name written with fullwidth or other mapped characters has none.
func alabel(domain string) string {
	d := strings.TrimRight(strings.ToLower(domain), ".")
	a, err := idna.Registration.ToASCII(d)
	if err != nil || d == "" {
		return ""
	}
	return a
}

// ulabel is domain in IDNA U-label form, "" when it is no valid IDNA name.
func ulabel(domain string) string {
	u, err := idna.Registration.ToUnicode(alabel(domain))
	if err != nil {
		return ""
	}
	return u
}

// canonAddr is an address with its domain in A-label form, "" when the
// domain is no valid IDNA name.
func canonAddr(a string) string {
	local, d, ok := strings.Cut(strings.ToLower(a), "@")
	if d = alabel(d); !ok || local == "" || d == "" {
		return ""
	}
	return local + "@" + d
}

// openedAddr is canonAddr for a last_opened key, falling back to IDNA's
// lookup mapping (fullwidth to ASCII and the like), so an open recorded under
// a From written that way still counts for the sender: counting more opens
// only refuses more.
func openedAddr(a string) string {
	if c := canonAddr(a); c != "" {
		return c
	}
	local, d, ok := strings.Cut(strings.ToLower(a), "@")
	d, err := idna.Lookup.ToASCII(strings.TrimRight(d, "."))
	if !ok || local == "" || d == "" || err != nil {
		return ""
	}
	return local + "@" + d
}

// org is the organizational domain, in A-label form: the public suffix, by
// the Public Suffix List with its private part, and one label more, so
// a.co.uk and b.co.uk, or a.github.io and b.github.io, are two
// organizations. A domain that is a public suffix itself, an IP address,
// empty or no valid IDNA name has none: "" (MIG-3-R1, #2600; MIG-3-R3).
func org(domain string) string {
	d := alabel(domain)
	o, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil || net.ParseIP(strings.Trim(d, "[]")) != nil {
		return ""
	}
	return o
}

// aligned reports whether a and b share an organizational domain; one with
// none aligns with nothing.
func aligned(a, b string) bool { return org(a) != "" && org(a) == org(b) }

// lookalike reports whether domain, of another organization than known,
// reads as known's organizational domain or a name under it once confusable
// characters are folded. The whole domain is folded, not its own
// organizational domain, which can stop short of the part that imitates:
// shop.rnyshopify.com against shop.myshopify.com, or barclays.c0.uk against
// barclays.co.uk (#2756). Both the domain as written, in its own case, and
// its U-label are folded, so neither punycode nor lower-casing hides a
// homoglyph (MIG-3-R4, #2603).
func lookalike(domain, known string) bool {
	k := org(known)
	if k == "" || org(domain) == k {
		return false
	}
	sk := skeleton(ulabel(k))
	for _, f := range []string{strings.TrimRight(domain, "."), ulabel(domain)} {
		if d := skeleton(f); f != "" && (d == sk || strings.HasSuffix(d, "."+sk)) {
			return true
		}
	}
	return false
}

// readAlike are look-alike letter pairs that confusables.txt leaves out,
// folded the way it folds m to rn.
var readAlike = strings.NewReplacer("w", "vv", "d", "cl")

// skeleton is UTS #39's skeleton (NFD, each code point to its prototype in
// confusables.txt, NFD) made case-blind and widened by readAlike: lower case
// after the mapping, so 0 (to O) meets o and I (to l) meets l, and repeated
// until nothing changes, since lower-casing a prototype can give a code point
// that maps again.
func skeleton(domain string) string {
	s := domain
	for range 4 {
		var b strings.Builder
		for _, r := range norm.NFD.String(s) {
			if p, ok := confusables[r]; ok {
				b.WriteString(p)
			} else {
				b.WriteRune(r)
			}
		}
		next := norm.NFD.String(readAlike.Replace(strings.ToLower(b.String())))
		if next == s {
			break
		}
		s = next
	}
	return s
}

var (
	angleAddr = regexp.MustCompile(`<([^<>@\s]+@[^<>@\s]+)>`)
	bareAddr  = regexp.MustCompile(`([^\s<>@]+@[^\s<>@]+)`)
	angleURL  = regexp.MustCompile(`<([^<>]+)>`)
)

func addr(value []byte) string { return strings.ToLower(rawAddr(value)) }

// rawAddr is the address in value as written, case kept.
func rawAddr(value []byte) string {
	m := angleAddr.FindSubmatch(value)
	if m == nil {
		m = bareAddr.FindSubmatch(value)
	}
	if m == nil {
		return ""
	}
	return string(m[1])
}

// FromAddress is the lower-case address of raw's From header, "" when none.
func FromAddress(raw []byte) string {
	hs, _ := splitMessage(raw)
	for _, h := range hs {
		if h.key() == "from" {
			return addr(h.value)
		}
	}
	return ""
}

func httpsURL(value []byte) string {
	for _, m := range angleURL.FindAllSubmatch(value, -1) {
		if strings.HasPrefix(strings.ToLower(string(m[1])), "https://") {
			return string(m[1])
		}
	}
	return ""
}

// urlHost is the host of an https URL that httpsURL returned.
func urlHost(u string) string {
	h := u[len("https://"):]
	if i := strings.IndexAny(h, "/:?#"); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

// day parses a date; ok is false for anything else, and the caller refuses.
func day(s string) (t time.Time, ok bool) {
	t, err := time.Parse("2006-01-02", s)
	return t, err == nil
}

// Evaluate is VRB-2: whether raw may be unsubscribed from, as a reason (ROK when
// it may) and the List-Unsubscribe https URL when one exists. The clerk alone runs
// it, on the message it reads itself; the planner never supplies the verdict or
// the URL.
func Evaluate(raw []byte, w World) (reason, url string) {
	hs, _ := splitMessage(raw)
	count := map[string]int{}
	values := map[string][]byte{}
	for _, h := range hs {
		if k := h.key(); contains(listed, k) {
			count[k]++
			values[k] = h.value
		}
	}
	if v, ok := values["list-unsubscribe"]; ok {
		url = httpsURL(v)
	}
	for _, k := range listed {
		if count[k] > 1 {
			return RDuplicateHeader, url
		}
	}
	for _, k := range listed {
		if count[k] == 0 {
			return RNoListUnsubscribe, url
		}
	}
	if url == "" {
		return RMailtoOnly, ""
	}
	// The sender is compared in A-label form, so a Unicode domain and its
	// punycode are one sender for alignment, history and opens (MIG-3-R3).
	sender := canonAddr(rawAddr(values["from"]))
	_, domain, _ := strings.Cut(sender, "@")
	_, shown, _ := strings.Cut(rawAddr(values["from"]), "@")
	sigs := VerifyDKIM(raw, w.DKIMKeys)
	if len(sigs) == 0 {
		return RDKIMNone, url
	}
	var pass, good, over, noL []Sig
	for _, s := range sigs {
		if s.Pass {
			pass = append(pass, s)
		}
	}
	if len(pass) == 0 {
		return RDKIMFail, url
	}
	// A signature counts only while current (RFC 6376 t= and x=, MIG-3-R3):
	// signed by the end of today and not expiring before it, so one that
	// expires or was signed at any hour of today is judged as harshly as the
	// day allows.
	var current []Sig
	today, todayOK := day(w.Today)
	for _, s := range pass {
		if s.T < 0 && s.X < 0 {
			current = append(current, s)
			continue
		}
		if !todayOK {
			return RBadDate, url
		}
		end := today.Unix() + 24*60*60
		if s.T < end && (s.X < 0 || s.X >= end) {
			current = append(current, s)
		}
	}
	if len(current) == 0 {
		return RDKIMNotCurrent, url
	}
	for _, s := range current {
		if domain != "" && aligned(s.D, domain) {
			good = append(good, s)
		}
	}
	if len(good) == 0 {
		return RDKIMUnaligned, url
	}
	for _, s := range good {
		ok := true
		for _, k := range listed {
			n := 0
			for _, x := range s.H {
				if x == k {
					n++
				}
			}
			ok = ok && n > count[k]
		}
		if ok {
			over = append(over, s)
		}
	}
	if len(over) == 0 {
		return RNotOverSigned, url
	}
	for _, s := range over {
		if !s.L {
			noL = append(noL, s)
		}
	}
	if len(noL) == 0 {
		return RDKIML, url
	}
	host := urlHost(url)
	hostOK := false
	for _, p := range w.ProviderTable {
		hostOK = hostOK || (org(host) != "" && alabel(p) == org(host))
	}
	for _, s := range noL {
		hostOK = hostOK || aligned(host, s.D)
	}
	if !hostOK {
		return RURLHost, url
	}
	var first time.Time
	for _, h := range w.History {
		if d, ok := day(h.Date); ok && canonAddr(h.From) == sender && h.Folder != "junk" {
			if first.IsZero() || d.Before(first) {
				first = d
			}
		}
	}
	if first.IsZero() {
		return RNoHistory, url
	}
	for _, a := range append(append([]string(nil), w.Contacts...), w.KnownSenders...) {
		_, d, _ := strings.Cut(a, "@")
		if lookalike(shown, d) {
			return RLookalike, url
		}
	}
	if !todayOK {
		return RBadDate, url
	}
	if int(today.Sub(first).Hours()/24) < unopenedDays {
		return RFirstMailRecent, url
	}
	// No entry means the owner has never opened the sender's mail; an entry
	// that is not a date is not evidence of that. Every entry for the sender,
	// in either domain form and any case, with surrounding space or not,
	// counts (#2618).
	for a, o := range w.LastOpened {
		if openedAddr(strings.TrimSpace(a)) != sender {
			continue
		}
		opened, ok := day(o)
		if !ok {
			return RBadDate, url
		}
		if int(today.Sub(opened).Hours()/24) < unopenedDays {
			return RRecentlyOpened, url
		}
	}
	return ROK, url
}
