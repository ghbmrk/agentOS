package grants

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-10, OP-4

// GR-reissue-deadline (#1317): a restart re-issues a texted intent and a
// page intent in one flush. The texted send is slow and crosses their
// original deadline. The page intent is asked under that absolute
// deadline, so the owner channel refuses it as expired and the gate
// closes it as expired: it never gets a fresh expiry.
func TestASlowTextSendCrossingTheDeadlineClosesThePageIntent(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Verifiers = nil })
	r.grant(mailGrant())
	r.own.local, r.own.localCalls = nil, 0 // the grant was asked there
	ok := r.effect("agent/p1", "message.send", map[string]any{"body": "hi"}, "mom@example.com")
	bad := r.effect("agent/p2", "message.send", map[string]any{"body": "yo"},
		"mom@example.com", "dad@example.com", "sis@example.com", "bro@example.com", "gran@example.com", "x@attacker.example")
	r.g.Flush()
	if len(r.own.local) != 1 || len(r.own.order) < 2 {
		t.Fatalf("requests %v, local %v", r.own.order, r.own.local)
	}
	texted := r.own.order[len(r.own.order)-2]
	if texted == r.own.local[0] {
		texted = r.own.order[len(r.own.order)-1]
	}
	r.own.mu.Lock()
	tItem, pItem := r.own.reqs[texted][0], r.own.reqs[r.own.local[0]][0]
	r.own.mu.Unlock()
	deadline := r.now().Add(5 * time.Minute)
	r.boot = []owner.Carried{
		{Ref: ok.Intent.ID, Request: texted, Asked: r.now(), Expires: deadline, Sum: owner.ItemSum(tItem)},
		{Ref: bad.Intent.ID, Request: r.own.local[0], Asked: r.now(), Expires: deadline, Sum: owner.ItemSum(pItem)},
	}
	r.open()
	r.own.slow = func() { r.advance(6 * time.Minute) } // the texted send outlasts the deadline
	r.g.Flush()

	if len(r.own.deadlines) != 2 || !r.own.deadlines[0].Equal(deadline) || !r.own.deadlines[1].Equal(deadline) {
		t.Fatalf("deadlines passed %v, want both %v", r.own.deadlines, deadline)
	}
	if len(r.own.local) != 0 {
		t.Fatalf("the page intent was asked past its deadline: %v", r.own.local)
	}
	if st := r.state(bad.Intent.ID); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "expired") {
		t.Fatalf("page intent: %s %q", st.State, st.Permission.Reason)
	}
}

// A re-issued page intent asked in time is asked under its original
// deadline, never a fresh one.
func TestAReissuedPageIntentKeepsItsDeadline(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Verifiers = nil })
	r.grant(mailGrant())
	r.own.local, r.own.localCalls = nil, 0
	bad := r.effect("agent/p2", "message.send", map[string]any{"body": "yo"},
		"mom@example.com", "dad@example.com", "sis@example.com", "bro@example.com", "gran@example.com", "x@attacker.example")
	r.g.Flush()
	r.own.mu.Lock()
	pItem := r.own.reqs[r.own.local[0]][0]
	r.own.mu.Unlock()
	deadline := r.now().Add(5 * time.Minute)
	r.boot = []owner.Carried{{Ref: bad.Intent.ID, Request: r.own.local[0], Asked: r.now(), Expires: deadline, Sum: owner.ItemSum(pItem)}}
	r.open()
	r.advance(2 * time.Minute)
	r.g.Flush()
	if len(r.own.local) != 1 || len(r.own.deadlines) != 1 || !r.own.deadlines[0].Equal(deadline) {
		t.Fatalf("local %v, deadlines %v, want %v", r.own.local, r.own.deadlines, deadline)
	}
	if st := r.state(bad.Intent.ID); st.State != journal.Pending {
		t.Fatalf("page intent: %s %q", st.State, st.Permission.Reason)
	}
}
