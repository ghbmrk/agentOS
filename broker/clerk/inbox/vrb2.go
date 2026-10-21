package inbox

import (
	"regexp"
	"strings"
	"time"
)

// World is what VRB-2 reads besides the message: the DKIM key records, the
// provider table, earlier deliveries, the owner's contacts, and the owner's
// last opens of each sender's mail. JSON names follow the eval's world.json.
type World struct {
	DKIMKeys      map[string]string `json:"dkim_keys"`
	ProviderTable []string          `json:"provider_table"`
	History       []Delivery        `json:"history"`
	Contacts      []string          `json:"contacts"`
	KnownSenders  []string          `json:"known_senders"`
	Today         string            `json:"today"`
	LastOpened    map[string]string `json:"last_opened"`
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

// org is the organizational domain: the last two labels. Every fixture domain is
// under the reserved single-label TLD .test, where that is exact; a public-suffix
// list replaces it before real mail does (ASSUMPTIONS.md).
func org(domain string) string {
	l := strings.Split(strings.TrimRight(strings.ToLower(domain), "."), ".")
	if len(l) > 2 {
		l = l[len(l)-2:]
	}
	return strings.Join(l, ".")
}

func aligned(a, b string) bool { return org(a) == org(b) }

// skeleton folds confusable pairs from Unicode's confusables.txt (UTS #39).
func skeleton(domain string) string {
	return strings.NewReplacer("rn", "m", "0", "o", "1", "l").Replace(strings.ToLower(domain))
}

var (
	angleAddr = regexp.MustCompile(`<([^<>@\s]+@[^<>@\s]+)>`)
	bareAddr  = regexp.MustCompile(`([^\s<>@]+@[^\s<>@]+)`)
	angleURL  = regexp.MustCompile(`<([^<>]+)>`)
)

func addr(value []byte) string {
	m := angleAddr.FindSubmatch(value)
	if m == nil {
		m = bareAddr.FindSubmatch(value)
	}
	if m == nil {
		return ""
	}
	return strings.ToLower(string(m[1]))
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
	sender := addr(values["from"])
	_, domain, _ := strings.Cut(sender, "@")
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
	for _, s := range pass {
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
	hostOK := contains(w.ProviderTable, org(host))
	for _, s := range noL {
		hostOK = hostOK || aligned(host, s.D)
	}
	if !hostOK {
		return RURLHost, url
	}
	var first time.Time
	for _, h := range w.History {
		if d, ok := day(h.Date); ok && h.From == sender && h.Folder != "junk" {
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
		if k := org(d); org(domain) != k && skeleton(org(domain)) == skeleton(k) {
			return RLookalike, url
		}
	}
	today, ok := day(w.Today)
	if !ok {
		return RBadDate, url
	}
	if int(today.Sub(first).Hours()/24) < unopenedDays {
		return RFirstMailRecent, url
	}
	// No entry means the owner has never opened the sender's mail; an entry
	// that is not a date is not evidence of that.
	if o, seen := w.LastOpened[sender]; seen {
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
