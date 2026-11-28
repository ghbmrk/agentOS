package owner

import (
	"strings"
	"testing"
	"time"
)

// REQ: CH-12, CH-13

// Each item line form states each repeat notice, the Detail field and the
// unverified mark in its own words: the full form says when, the short
// form says it in fewer words with the time, and the lean form keeps the
// warning and points to the Wi-Fi page (OWN-17, D-116, OP2-ER-2; mutgate
// on #6625).
func TestMoreItemLineFormsWordEachNotice(t *testing.T) {
	r := newRig(t, nil)
	tm := time.Date(2026, 10, 14, 11, 0, 0, 0, time.UTC)
	const head, tail = "send invoice 1042 to billing@acme.example, cannot be undone", ", more on my Wi-Fi page"
	for name, c := range map[string]struct {
		set  func(*Item)
		want [3]string // lineFull, lineShort, lineLean
	}{
		"sent-erased": {func(it *Item) { it.Sent, it.SentErased = tm, true }, [3]string{
			head + ", may repeat a send whose record was erased (it went 11:00 Oct 14); send it?",
			head + ", may repeat an erased send (11:00 Oct 14)",
			head + ", may repeat an erased send" + tail}},
		"sent": {func(it *Item) { it.Sent = tm }, [3]string{
			head + ", already sent 11:00 Oct 14; send it again?",
			head + ", sent 11:00 Oct 14; again?",
			head + ", already sent; send again?" + tail}},
		"retried": {func(it *Item) { it.Retried = tm }, [3]string{
			head + ", may go twice, first tried 11:00 Oct 14",
			head + ", may go twice, tried 11:00 Oct 14",
			head + ", may go twice" + tail}},
		"unverified": {func(it *Item) { it.Unverified = true }, [3]string{
			"UNVERIFIED, details on the Wi-Fi page: " + head,
			"UNVERIFIED, see my Wi-Fi page: " + head,
			"UNVERIFIED: " + head + tail}},
		"detail": {func(it *Item) { it.Detail = "the detail" }, [3]string{
			"send invoice 1042, the detail to billing@acme.example, cannot be undone",
			"send invoice 1042, the detail to billing@acme.example, cannot be undone",
			head + tail}},
	} {
		it := lowItem("a")
		c.set(&it)
		for lv := lineFull; lv <= lineLean; lv++ {
			if got := r.ch.itemLineAs(it, lv); got != c.want[lv] {
				t.Errorf("%s form %d: %q, want %q", name, lv, got, c.want[lv])
			}
		}
	}
}

// MORE from item 0 or below is MORE from item 1, and a page whose replies
// alone would not fit three segments in any line form falls to the Wi-Fi
// form, still naming the item it shows (moreTextLocked's last bound).
func TestMoreTextLockedBounds(t *testing.T) {
	r := newRig(t, nil)
	id, err := r.ch.Request([]Item{lowItem("a"), lowItem("b"), lowItem("c"), lowItem("d")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.ch.mu.Lock()
	defer r.ch.mu.Unlock()
	p1, n1 := r.ch.moreTextLocked(id, 1, r.clock())
	for _, from := range []int{0, -3} {
		if p, n := r.ch.moreTextLocked(id, from, r.clock()); p != p1 || n != n1 || n != 1 {
			t.Fatalf("MORE from %d: %q (%d), want %q (%d)", from, p, n, p1, n1)
		}
	}
	r.ch.open[id].code = strings.Repeat("9", 500)
	p, n := r.ch.moreTextLocked(id, 2, r.clock())
	if n != 2 || !strings.HasPrefix(p, id+" item 2 of 4: 2 is too long to text; see it on my Wi-Fi page.") || strings.Contains(p, "YES") {
		t.Fatalf("over-long page: %q (%d)", p, n)
	}
}
