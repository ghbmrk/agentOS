package owner

import (
	"strings"
	"testing"
	"time"
)

// REQ: OP-2, CH-10, CH-12

// Confirm repeats (D-116): a repeat of a send known to have gone says
// plainly that it was already sent and when, and asks whether to send it
// again. Its tier is its own (CH-10): a low-risk send takes a texted
// code, money above the owner-set limit the code generator. The mark is
// not part of ItemSum.
func TestARepeatSaysItWasAlreadySentAndAsks(t *testing.T) {
	r := newRig(t, nil)
	sent := r.clock().Add(-2 * time.Hour)
	stamp := "already sent " + sent.In(r.ch.cfg.Location).Format("15:04 Jan 2") + "; send it again?"

	low := lowItem("i1")
	low.Sent = sent
	if ItemSum(low) != ItemSum(lowItem("i1")) {
		t.Fatal("the mark changes ItemSum")
	}
	if _, err := r.ch.Request([]Item{low}, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	text := r.inbox()
	if !strings.Contains(text, stamp) || !lowCodeRe.MatchString(text) || strings.Contains(text, "may go twice") {
		t.Fatalf("low repeat %q", text)
	}

	high := highItem("i2")
	high.Sent = sent
	if _, err := r.ch.Request([]Item{high}, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	text = r.inbox()
	if !strings.Contains(text, stamp) || lowCodeRe.MatchString(text) || !strings.Contains(text, "code generator") {
		t.Fatalf("high repeat %q", text)
	}

	// On the page, the notice says so too.
	loc := localItem("i3")
	loc.Sent = sent
	if _, err := r.ch.RequestLocalEach([]Item{loc}, []time.Time{{}}); err != nil {
		t.Fatal(err)
	}
	text = r.inbox()
	if !strings.Contains(text, "was already sent "+sent.In(r.ch.cfg.Location).Format("15:04 Jan 2")+". Send it again?") {
		t.Fatalf("page repeat notice %q", text)
	}
}

// REQ: OP2-ER-2
// A repeat whose only known success was erased (CAP-3) cannot be said to
// have been sent: its record and recipient are gone. The text and the
// page notice say it may repeat a send whose record was erased, never
// "already sent". The mark is not part of ItemSum.
func TestAnErasedOnlyRepeatSaysItMayRepeat(t *testing.T) {
	r := newRig(t, nil)
	sent := r.clock().Add(-2 * time.Hour)
	at := sent.In(r.ch.cfg.Location).Format("15:04 Jan 2")

	low := lowItem("i1")
	low.Sent, low.SentErased = sent, true
	if ItemSum(low) != ItemSum(lowItem("i1")) {
		t.Fatal("the mark changes ItemSum")
	}
	if _, err := r.ch.Request([]Item{low}, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	text := r.inbox()
	if !strings.Contains(text, "may repeat a send whose record was erased (it went "+at+"); send it?") ||
		strings.Contains(text, "already sent") || !lowCodeRe.MatchString(text) {
		t.Fatalf("low erased repeat %q", text)
	}

	loc := localItem("i2")
	loc.Sent, loc.SentErased = sent, true
	if _, err := r.ch.RequestLocalEach([]Item{loc}, []time.Time{{}}); err != nil {
		t.Fatal(err)
	}
	text = r.inbox()
	if strings.Contains(text, "your agent wants") || !strings.Contains(text, "Can I ") || !strings.Contains(text, "\"? It may repeat a send whose record was erased ("+at+"). Approve or deny") ||
		strings.Contains(text, "already sent") {
		t.Fatalf("page erased repeat notice %q", text)
	}
}
