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
	if _, err := r.ch.RequestLocalEach([]Item{loc}, []time.Duration{0}); err != nil {
		t.Fatal(err)
	}
	text = r.inbox()
	if !strings.Contains(text, "was already sent "+sent.In(r.ch.cfg.Location).Format("15:04 Jan 2")+". Send it again?") {
		t.Fatalf("page repeat notice %q", text)
	}
}
