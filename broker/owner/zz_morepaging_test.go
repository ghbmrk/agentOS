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
var pageItemRe = regexp.MustCompile(`[:.] ([0-9]{1,2}) `)

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
func walk(t *testing.T, r *rig, id string, n int) []int {
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
			!strings.Contains(p, " Expires ") || !strings.Contains(p, "NO "+id+".") {
			t.Fatalf("%s page lacks request, range, expiry or replies: %q", cmd, p)
		}
		body, _, _ := strings.Cut(p, " Expires ")
		for _, m := range pageItemRe.FindAllStringSubmatch(body, -1) {
			k, _ := strconv.Atoi(m[1])
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
					r.inbox()
					wantAll(t, walk(t, r, id, n), n)
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
// a texted YES (CH-3, tier separation).
func TestMoreLocalRequestOffersNoTextedYes(t *testing.T) {
	r := newRig(t, nil)
	it := lowItem("l")
	it.Recipient = "not a canonical recipient"
	id, err := r.ch.RequestLocal(it, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.inbox()
	p := r.say("MORE " + id)
	if strings.Contains(p, "YES") || !strings.Contains(p, "Wi-Fi page") || !strings.HasSuffix(p, "NO "+id+".") {
		t.Fatalf("local page: %q", p)
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
