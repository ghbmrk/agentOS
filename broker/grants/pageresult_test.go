package grants

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CH-10, CH-12

// L3 SHOULD on #178 (P2-2a f1): the page has already told the owner
// "Approved ... Your agent can go ahead." when the gate denies a
// page-approved item because it changed since the page showed it, so the
// owner is told it did not run, and what to do, in one GSM-7 segment.
func TestAPageApprovalOfAChangedItemTellsTheOwnerItDidNotRun(t *testing.T) {
	r := newRig(t, nil)
	sub := func(id string) {
		r.submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount, Action: journal.ActionGrantChange,
			Params: specParams(mailGrant()), Executor: ExecutorName})
	}
	notes := func() []string {
		r.own.mu.Lock()
		defer r.own.mu.Unlock()
		return append([]string(nil), r.own.notes...)
	}

	sub("local/c1")
	r.g.Flush()
	req, _ := r.own.last(t)
	before := len(notes())
	r.pageDecide(strings.Repeat("0", 64))
	if st := r.state("local/c1"); st.State != journal.Denied {
		t.Fatalf("changed item: %s %q", st.State, st.Permission.Reason)
	}
	got := notes()[before:]
	if len(got) != 1 {
		t.Fatalf("want one notice, got %q", got)
	}
	n := got[0]
	if !strings.HasPrefix(n, req+" did not run") || !strings.Contains(n, "Wi-Fi page") || !strings.Contains(n, "Ask your agent again") {
		t.Fatalf("notice: %q", n)
	}
	if len(n) > 160 {
		t.Fatalf("notice is %d characters, over one segment: %q", len(n), n)
	}
	for _, c := range n {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("notice has %U: %q", c, n)
		}
	}

	// An unchanged item approved on the page gets no such notice.
	sub("local/c2")
	r.g.Flush()
	before = len(notes())
	r.pageDecide("")
	if st := r.state("local/c2"); st.State == journal.Denied {
		t.Fatalf("unchanged item: %s %q", st.State, st.Permission.Reason)
	}
	for _, n := range notes()[before:] {
		if strings.Contains(n, "did not run") {
			t.Fatalf("unchanged item told: %q", n)
		}
	}
}
