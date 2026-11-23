package owner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// REQ: CH-12, CH-13

var nextMoreRe = regexp.MustCompile(`Next: MORE ([A-Z][A-Z0-9]{0,2}) ([0-9]{1,2})\.$`)
var pageItemRe = regexp.MustCompile(`[:.?] ([0-9]{1,2}) `)

// longItem is a texted item whose fields are each at their longest: a
// valid recipient set of MaxRecipientChars, the longest verb, object,
// detail, amount and undo wording, and every notice an item line can
// carry.
func longItem(i int, worst bool) Item {
	rcpt := "a" + strings.Repeat("b", 30) + "@" + strings.Repeat("c", 20) + ".example"
	for len(rcpt)+len(",x@y.example") <= MaxRecipientChars {
		rcpt += ",x@y.example"
	}
	it := Item{Ref: fmt.Sprint(i), Object: fmt.Sprintf("o%02d", i) + strings.Repeat("O", 37),
		Recipient: rcpt, Amount: "$" + strings.Repeat("9", 15),
		Facts: Facts{Verb: "transmitting", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true, HasAmount: true, Amount: 25000}}
	if worst {
		t := time.Date(2026, 10, 4, 11, 0, 0, 0, time.UTC)
		it.Detail = strings.Repeat("D", 40)
		it.UndoBy = strings.Repeat("U", 24)
		it.Unverified = true
		it.Asked, it.Sent, it.SentErased = t, t, true
	}
	return it
}

// walk follows MORE pages from MORE id to the last one, checking each
// page's form, and returns the item numbers shown in order.
// textReplies is the valid replies that request text sms ends with.
func textReplies(t *testing.T, sms string) string {
	t.Helper()
	if i := strings.Index(sms, "Approve or deny on my Wi-Fi page"); i >= 0 {
		return sms[i:]
	}
	m := expiresRe.FindAllStringIndex(sms, -1)
	if m == nil {
		t.Fatalf("no replies in %q", sms)
	}
	return sms[m[len(m)-1][1]:]
}

var (
	expiresRe  = regexp.MustCompile(` Expires [0-9]{2}:[0-9]{2}\. `)
	lowBatchRe = regexp.MustCompile(`^Reply YES (\S+) ([0-9]{6}) for all, .* or NO (\S+)\.$`)
	nextTailRe = regexp.MustCompile(` Next: MORE \S+ [0-9]{1,2}\.$`)
)

// pageReplies checks that page p ends with the request text's replies
// word for word, then the next MORE while items remain: a page never
// offers a reply the text does not, or a shorter one that hides what it
// does (L3 step back on #6610).
func pageReplies(t *testing.T, p, sms string) {
	t.Helper()
	full := textReplies(t, sms)
	if got := nextTailRe.ReplaceAllString(p, ""); !strings.HasSuffix(got, " "+full) {
		t.Fatalf("page %q does not end with the text's replies %q", p, full)
	}
}

var pageHeadRe = regexp.MustCompile(`^([A-Z][A-Z0-9]{0,2}) items? ([0-9]{1,2})(?:-[0-9]{1,2})? of ([0-9]{1,2}):`)

func walk(t *testing.T, r *rig, id string, items []Item, sms string) []int {
	n := len(items)
	t.Helper()
	var seen []int
	cmd := "MORE " + id
	for pages := 0; cmd != ""; pages++ {
		if pages > n {
			t.Fatalf("more pages than items: %v", seen)
		}
		p := r.say(cmd) // r.say holds every page to three GSM-7 segments
		if again := r.say(cmd); again != p {
			t.Fatalf("%s is not stable: %q then %q", cmd, p, again)
		}
		if !strings.HasPrefix(p, id+" item") || !strings.Contains(p, fmt.Sprintf(" of %d:", n)) ||
			!strings.Contains(p, " Expires ") && !strings.Contains(p, " before ") || !strings.Contains(p, "NO "+id+".") {
			t.Fatalf("%s page lacks request, range, expiry or replies: %q", cmd, p)
		}
		pageReplies(t, p, sms)
		body, _, _ := strings.Cut(p, " Expires ")
		for _, m := range pageItemRe.FindAllStringSubmatch(body, -1) {
			k, _ := strconv.Atoi(m[1])
			wantFields(t, p, items[k-1])
			seen = append(seen, k)
		}
		cmd = ""
		if m := nextMoreRe.FindStringSubmatch(p); m != nil {
			if m[1] != id {
				t.Fatalf("next names another request: %q", p)
			}
			cmd = "MORE " + id + " " + m[2]
		}
	}
	return seen
}

// wantFields checks that page p states the fields CH-12 lists for a
// texted item: its exact canonical recipients (CH-10) and its amount
// (L3 on #6625). A shorter line drops other fields first.
func wantFields(t *testing.T, p string, it Item) {
	t.Helper()
	if rc, ok := recipientText(it.Recipient); ok && !strings.Contains(p, " to "+rc) {
		t.Fatalf("page drops the recipients %q: %q", rc, p)
	}
	if it.Amount != "" && !strings.Contains(p, field(it.Amount, 16)) {
		t.Fatalf("page drops the amount %q: %q", it.Amount, p)
	}
	// A field left out is pointed to the Wi-Fi page.
	dropped := it.Detail != "" && !strings.Contains(p, field(it.Detail, 40)) || !it.Asked.IsZero() && !strings.Contains(p, "restart")
	if dropped && !strings.Contains(p, ", more on my Wi-Fi page") {
		t.Fatalf("page drops a field without saying so: %q", p)
	}
}

func wantAll(t *testing.T, seen []int, n int) {
	t.Helper()
	if len(seen) != n {
		t.Fatalf("items reached %v, want 1..%d", seen, n)
	}
	for i, k := range seen {
		if k != i+1 {
			t.Fatalf("items reached %v, want 1..%d", seen, n)
		}
	}
}

// Acceptance 1 (UX3-6): 1-, 4-, 10- and 20-item batches with long valid
// targets, low and high tier. Every item is reachable by MORE paging,
// each page within three segments and the same each time it is asked
// for, and reading approves nothing.
func TestMorePagesReachEveryBatchItem(t *testing.T) {
	for _, worst := range []bool{false, true} {
		for _, n := range []int{1, 4, 10, 20} {
			for _, high := range []bool{false, true} {
				t.Run(fmt.Sprintf("n%d-high%v-worst%v", n, high, worst), func(t *testing.T) {
					r := newRig(t, nil)
					var items []Item
					for i := 1; i <= n; i++ {
						it := longItem(i, worst)
						if !high {
							it.Amount, it.Facts.HasAmount, it.Facts.Amount = "", false, 0
						}
						items = append(items, it)
					}
					id, err := r.ch.Request(items, 0)
					if err != nil {
						t.Fatal(err)
					}
					wantAll(t, walk(t, r, id, items, r.inbox()), n)
					if d := r.decisions(); len(d) != 0 {
						t.Fatalf("reading decided %v", d)
					}
					if got := r.say("NO " + id); !strings.Contains(got, "Denied") && !strings.Contains(got, "denied") {
						t.Fatalf("request not open after reading: %q", got)
					}
				})
			}
		}
	}
}

// MORE id n starts at item n; a number past the batch names its size.
func TestMoreStartsAtTheNamedItem(t *testing.T) {
	r := newRig(t, nil)
	var items []Item
	for i := 1; i <= 20; i++ {
		items = append(items, longItem(i, false))
	}
	id, _ := r.ch.Request(items, 0)
	r.inbox()
	p := r.say("MORE " + id + " 17")
	if !strings.HasPrefix(p, id+" item") || !strings.Contains(p, " 17 transmitting o17") || strings.Contains(p, " o16") {
		t.Fatalf("MORE %s 17: %q", id, p)
	}
	if p := r.say("more " + strings.ToLower(id) + ", 20"); !strings.HasPrefix(p, id+" item 20 of 20:") || strings.Contains(p, "Next:") {
		t.Fatalf("last page: %q", p)
	}
	if p := r.say("MORE " + id + " 21"); !strings.Contains(p, "it has 20") || strings.Contains(p, "o20") {
		t.Fatalf("past the end: %q", p)
	}
}

// A request that is answered, expired or reissued has no earlier view:
// its ID gets no page, and a reissue's new ID pages only its own items.
func TestMoreHasNoStaleView(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.Request([]Item{lowItem("a"), lowItem("b")}, 0)
	r.inbox()
	if p := r.say("MORE " + id); !strings.Contains(p, "items 1-2 of 2") {
		t.Fatalf("open: %q", p)
	}
	r.say("NO " + id)
	if p := r.say("MORE " + id); p != "No open request "+id+"." {
		t.Fatalf("answered: %q", p)
	}
	id2, _ := r.ch.Request([]Item{lowItem("c")}, 0)
	r.inbox()
	r.advance(r.ch.cfg.CodeTTL)
	if p := r.say("MORE " + id2); p != "No open request "+id2+"." {
		t.Fatalf("expired: %q", p)
	}
}

// A local-only request's page offers only the page or NO by text, never
// a texted YES (CH-3, tier separation), and its item is exactly the
// request text's question: every notice the text carries and no fact it
// leaves to the page (Security D4), in every local branch.
func TestMoreLocalRequestOffersNoTextedYes(t *testing.T) {
	tm := time.Date(2026, 10, 4, 11, 0, 0, 0, time.UTC)
	branches := map[string]func(*Item){
		"recipients":   func(it *Item) {},
		"page-confirm": func(it *Item) { it.Recipient = "" },
		"sent":         func(it *Item) { it.Sent = tm },
		"sent-erased":  func(it *Item) { it.Sent, it.SentErased = tm, true },
		"retried":      func(it *Item) { it.Retried = tm },
	}
	for name, set := range branches {
		for _, worst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-worst%v", name, worst), func(t *testing.T) {
				r := newRig(t, nil)
				it := longItem(1, false)
				it.Recipient = "not a canonical recipient, " + strings.Repeat("r,", 40) + "z"
				if worst {
					it.Detail, it.UndoBy, it.Unverified, it.Asked = "DETAILWITHHELD", "UNDOWITHHELD", true, tm
				}
				set(&it)
				id, err := r.ch.RequestLocal(it, 0)
				if err != nil {
					t.Fatal(err)
				}
				sms := r.inbox()
				// Each repeat notice keeps its warning (L3 release on #6610).
				notice := map[string]string{
					"sent":        " again? It was already sent 11:00 Oct 4.",
					"sent-erased": "? It may repeat a send whose record was erased (11:00 Oct 4).",
					"retried":     " again? It may go twice; first tried 11:00 Oct 4.",
				}[name]
				if !strings.Contains(sms, notice) {
					t.Fatalf("text %q lacks %q", sms, notice)
				}
				p := r.say("MORE " + id)
				if strings.Contains(p, "YES") || !strings.HasSuffix(p, "NO "+id+".") {
					t.Fatalf("local page: %q", p)
				}
				pageReplies(t, p, sms)
				ask, _, ok := strings.Cut(sms, " Approve or deny on my Wi-Fi page")
				head := id + " item 1 of 1: 1 "
				item, _, _ := strings.Cut(strings.TrimPrefix(p, head), " Approve or deny on my Wi-Fi page")
				if !ok || !strings.HasPrefix(p, head) || item != ask || strings.Contains(p, " Expires ") {
					t.Fatalf("page item %q, text question %q (page %q)", item, ask, p)
				}
			})
		}
	}
}

func TestParseMoreItem(t *testing.T) {
	if r, ok := parseReply("MORE K3 12"); !ok || r.id != "K3" || len(r.items) != 1 || r.items[0] != 12 {
		t.Fatalf("MORE K3 12: %+v %v", r, ok)
	}
	for _, s := range []string{"MORE K3 0", "MORE K3 100", "MORE K3 1 2", "MORE K3 X", "UNDO K3 2", "MORE STATUS"} {
		if r, ok := parseReply(s); ok {
			t.Fatalf("%q parsed: %+v", s, r)
		}
	}
}

// Acceptance 4: interleaved batches page their own items, a partial YES
// closes its batch's view and leaves the other's unchanged, and a
// restart leaves no stale view under the old ID.
func TestMoreInterleavedRestartAndPartialYes(t *testing.T) {
	r := newRig(t, nil)
	var a, b []Item
	for i := 1; i <= 10; i++ {
		a = append(a, longItem(i, false))
		it := lowItem(fmt.Sprint("b", i))
		it.Object = fmt.Sprintf("bill %02d", i)
		b = append(b, it)
	}
	ida, _ := r.ch.Request(a, 0)
	r.inbox()
	idb, _ := r.ch.Request(b, 0)
	code := lowCodeRe.FindStringSubmatch(r.inbox())
	pa, pb := r.say("MORE "+ida+" 3"), r.say("MORE "+idb+" 3")
	if strings.Contains(pa, "bill") || strings.Contains(pb, "transmitting") || !strings.Contains(pb, " 3 send bill 03") {
		t.Fatalf("interleaved: %q | %q", pa, pb)
	}
	if code == nil || code[1] != idb {
		t.Fatalf("no texted code for %s", idb)
	}
	r.say("YES " + idb + " 2 4 " + code[2])
	if p := r.say("MORE " + idb + " 3"); p != "No open request "+idb+"." {
		t.Fatalf("after partial YES: %q", p)
	}
	if again := r.say("MORE " + ida + " 3"); again != pa {
		t.Fatalf("other batch changed: %q", again)
	}
	// A restart re-issues an open request under a new ID (GR10), so the
	// old ID's view is gone rather than served stale.
	r.ch = r.open()
	if p := r.say("MORE " + ida + " 3"); p != "No open request "+ida+"." {
		t.Fatalf("after restart: %q", p)
	}
}

// MORE STATUS reaches the control handler through the owner channel and
// needs the same proof as STATUS (CH-12): locked, it gets the unlock
// prompt, never status lines.
func TestMoreStatusThroughTheChannelNeedsProof(t *testing.T) {
	r := newRig(t, nil)
	if locked := r.say("MORE STATUS"); !strings.HasPrefix(locked, "This needs an unlocked session.") {
		t.Fatalf("locked MORE STATUS: %q", locked)
	}
	r.unlock()
	if p := r.say("MORE STATUS"); p != "STATUS fits one text; nothing more to show." {
		t.Fatalf("unlocked MORE STATUS: %q", p)
	}
}

// moreLocked refuses a request past its expiry itself, even before
// expireLocked has closed it.
func TestMoreRefusesAnExpiredRequestItself(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.Request([]Item{lowItem("a"), lowItem("b")}, 0)
	r.inbox()
	r.ch.mu.Lock()
	exp := r.ch.open[id].expires
	before := r.ch.moreLocked(id, 1, exp.Add(-time.Second))
	at := r.ch.moreLocked(id, 1, exp)
	r.ch.mu.Unlock()
	if !strings.Contains(before, "items 1-2 of 2") || at != "No open request "+id+"." {
		t.Fatalf("before expiry %q, at expiry %q", before, at)
	}
}

// The long-item fallback (L3 step back on #6610): with every field at
// its bound and the longest request ID and grid cell, every page of a 2-
// to 20-item batch, low and high tier, fits three segments with the
// request text's replies word for word. It uses the longest item line
// that fits, never the Wi-Fi form at today's bounds.
func TestMoreWorstPageFitsWithTheLongestID(t *testing.T) {
	// "unchecked": high tier by an unverified recipient, with no amount
	// (the L3 repro on #6625), where the recipient is the reason for
	// the code.
	for _, kind := range []string{"low", "high", "unchecked"} {
		for _, n := range []int{2, 4, 20} {
			t.Run(fmt.Sprintf("n%d-%s", n, kind), func(t *testing.T) {
				r := newRig(t, nil)
				// The longest grid cell, in the text and on every page.
				cell := ""
				for _, l := range GridLabels() {
					if len(l) > len(cell) {
						cell = l
					}
				}
				r.ch.mu.Lock()
				r.ch.codes.challenge = cell
				r.ch.mu.Unlock()
				var items []Item
				for i := 1; i <= n; i++ {
					it := longItem(i, true)
					if kind != "high" {
						it.Amount, it.Facts.HasAmount, it.Facts.Amount = "", false, 0
					}
					if kind == "unchecked" {
						it.Facts.RecipientExists = false
					}
					items = append(items, it)
				}
				id, err := r.ch.Request(items, 0)
				if err != nil {
					t.Fatal(err)
				}
				sms := r.inbox()
				// The longest ID: three characters, in the text too.
				long := id + strings.Repeat("9", 3-len(id))
				r.ch.mu.Lock()
				req := r.ch.open[id]
				delete(r.ch.open, id)
				req.id = long
				r.ch.open[long] = req
				var pages []string
				for k := 1; k <= n; k++ {
					p := r.ch.moreLocked(long, k, r.clock())
					left := []int{}
					for i := k - 1; i < n; i++ {
						left = append(left, i)
					}
					// The longest form that fits, and no longer one.
					var lv int
					for lv = lineFull; lv < pageWiFi; lv++ {
						if fits(r.ch.pageLocked(req, left, 1, lv)) {
							break
						}
					}
					if lv == pageWiFi || p != r.ch.pageLocked(req, left, 1, lv) {
						t.Errorf("page %d: form %d, got %q", k, lv, p)
					}
					pages = append(pages, p)
				}
				r.ch.mu.Unlock()
				sms = strings.ReplaceAll(sms, " "+id+" ", " "+long+" ")
				sms = strings.ReplaceAll(sms, " "+id+".", " "+long+".")
				for k, p := range pages {
					r.checkFormat(p)
					wantFields(t, p, items[k])
					if kind != "low" && !strings.Contains(p, "grid cell "+cell+" ") {
						t.Fatalf("page %d lacks the longest cell %s: %q", k+1, cell, p)
					}
					if !strings.HasPrefix(p, fmt.Sprintf("%s item %d of %d: %d ", long, k+1, n, k+1)) {
						t.Fatalf("page %d: %q", k+1, p)
					}
					pageReplies(t, p, sms)
				}
			})
		}
	}
}

// The reviewer's repro on #6610: page 2 of a 20-item worst batch says,
// as the request text does, that a YES naming some items denies the
// rest; and that YES then approves item 2 alone and denies the rest,
// as said.
func TestMorePageSaysThePartialYesDeniesTheRest(t *testing.T) {
	r := newRig(t, nil)
	var items []Item
	for i := 1; i <= 20; i++ {
		it := longItem(i, true)
		it.Amount, it.Facts.HasAmount, it.Facts.Amount = "", false, 0
		items = append(items, it)
	}
	id, _ := r.ch.Request(items, 0)
	sms := r.inbox()
	p := r.say("MORE " + id + " 2")
	pageReplies(t, p, sms)
	if !strings.Contains(p, " for some (the rest are denied), or NO "+id+".") {
		t.Fatalf("page 2 hides the denial: %q", p)
	}
	code := lowCodeRe.FindStringSubmatch(sms)
	r.say("YES " + id + " 2 " + code[2])
	d := r.decisions()
	if len(d) != 20 {
		t.Fatalf("decided %d items: %+v", len(d), d)
	}
	for _, x := range d {
		if x.Approved != (x.Item == 2) {
			t.Fatalf("partial YES decided %+v", x)
		}
	}
}

// The Wi-Fi form, a bound should a field ever outgrow the shorter lines,
// keeps the head, names the item and leaves its fields to the page, and
// ends with page-or-NO and the next MORE, never a texted YES; a local
// request keeps its question and its text's replies in every form.
func TestMoreWiFiFormKeepsHeadAndReplies(t *testing.T) {
	for _, high := range []bool{false, true} {
		r := newRig(t, nil)
		mk := lowItem
		if high {
			mk = highItem
		}
		id, _ := r.ch.Request([]Item{mk("a"), mk("b"), mk("c"), mk("d")}, 0)
		sms := r.inbox()
		r.ch.mu.Lock()
		p := r.ch.pageLocked(r.ch.open[id], []int{1, 2, 3}, 1, pageWiFi)
		r.ch.mu.Unlock()
		// It states no item, so it offers no texted YES (L3 on #6625).
		want := id + " item 2 of 4: 2 is too long to text; see it on my Wi-Fi page. Approve or deny on my Wi-Fi page before "
		if !strings.HasPrefix(p, want) || strings.Contains(p, "YES") || !strings.HasSuffix(p, ", or reply NO "+id+". Next: MORE "+id+" 3.") || !strings.Contains(sms, "YES") {
			t.Fatalf("high %v Wi-Fi form: %q", high, p)
		}
	}
	r := newRig(t, nil)
	id, _ := r.ch.RequestLocal(longItem(1, true), 0)
	sms := r.inbox()
	r.ch.mu.Lock()
	p := r.ch.pageLocked(r.ch.open[id], []int{0}, 1, pageWiFi)
	r.ch.mu.Unlock()
	if p != id+" item 1 of 1: 1 "+sms {
		t.Fatalf("local Wi-Fi form %q, text %q", p, sms)
	}
}

// The request text's pointer names the first item it left out, so the
// owner's first MORE page is new to them, and one item left is "Item n".
func TestTextPointsMoreAtTheFirstItemLeftOut(t *testing.T) {
	r := newRig(t, nil)
	var items []Item
	for i := 1; i <= 20; i++ {
		items = append(items, longItem(i, false))
	}
	id, _ := r.ch.Request(items, 0)
	sms := r.inbox()
	m := regexp.MustCompile(` Items ([0-9]+)-20: MORE ` + id + ` ([0-9]+)\.`).FindStringSubmatch(sms)
	if m == nil || m[1] != m[2] || m[1] == "1" {
		t.Fatalf("pointer: %q", sms)
	}
	if p := r.say("MORE " + id + " " + m[2]); !regexp.MustCompile(`^` + id + ` items? ` + m[2] + `[-0-9]* of 20: ` + m[2] + ` `).MatchString(p) {
		t.Fatalf("pointer %q leads to %q", m[0], p)
	}
}
