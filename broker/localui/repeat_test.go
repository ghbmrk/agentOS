package localui

import (
	"html"
	"strings"
	"testing"
	"time"
)

// REQ: OP-2, CH-12

// Confirm repeats (D-116): the page says a repeat was already sent and
// when, as the text does; an owner retry of one that may have gone still
// warns it may happen twice.
func TestThePageSaysARepeatWasAlreadySent(t *testing.T) {
	a := newApprovalRig(t)
	sent := a.clock().Add(-90 * time.Minute)
	it := pageItem("i1")
	it.Sent = sent
	if _, err := a.ch.RequestLocal(it, 0); err != nil {
		t.Fatal(err)
	}
	tried := pageItem("i2")
	tried.Retried = sent
	if _, err := a.ch.RequestLocal(tried, 0); err != nil {
		t.Fatal(err)
	}
	p := html.UnescapeString(a.get("/approvals/"))
	want := "Already sent " + sent.In(a.clock().Location()).Format("15:04 Jan 2") + ". Approve only to send it again."
	if strings.Count(p, want) != 1 || strings.Count(p, "Tried before and may have gone") != 1 {
		t.Fatalf("page:\n%s", p)
	}
}
