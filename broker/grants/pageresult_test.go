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
	if !strings.HasPrefix(n, req+" did not run") || !strings.Contains(n, "Wi-Fi page") || !strings.HasSuffix(n, " Make the request again if still needed.") {
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

// UX lens on #329 (CH-12): the notice names a step the item's origin can
// take. Only page-confirmed items get it, and agent and guest origins never
// get one: only broker actions set it, and evaluateBroker denies them every
// broker action (their other actions can be asked on the page, but are not
// page-confirmed). So the notice must not send the owner back to their
// agent. (A release adoption the pipeline proposes is also page-confirmed;
// its notice is BOARD row P2-2a f2.)
func TestAPageChangeNoticeNamesAStepEachOriginCanTake(t *testing.T) {
	agent := func(in journal.Intent) journal.Intent { in.Origin = "guest:agent"; return in }
	digest := strings.Repeat("a", 64)
	for _, tc := range []struct {
		origin string
		rig    func(*testing.T) *rig
		in     journal.Intent
	}{
		{"agent", func(t *testing.T) *rig {
			return newRigExecs(t, nil, map[string]journal.Executor{FollowExecutor: &fakeExec{ran: map[string]int{}}})
		}, journal.Intent{}},
		{"evidence", func(t *testing.T) *rig { r, _ := evidenceRig(t, nil); return r },
			EvidenceIntent("local/e1", originLocal, ownAddr, "mail")},
		{"follow", func(t *testing.T) *rig {
			return newRigExecs(t, nil, map[string]journal.Executor{FollowExecutor: &fakeExec{ran: map[string]int{}}})
		}, FollowIntent("local/f1", "Acme", digest)},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			r := tc.rig(t)
			if tc.origin == "agent" {
				// The agent cannot ask for any page-confirmed item, so
				// none of its requests ever gets this notice.
				for _, in := range []journal.Intent{
					agent(journal.Intent{ID: "guest/c1", Account: journal.BrokerAccount, Action: journal.ActionGrantChange,
						Params: specParams(mailGrant()), Executor: ExecutorName}),
					agent(EvidenceIntent("guest/e1", "", ownAddr, "mail")),
					agent(FollowIntent("guest/f1", "Acme", digest)),
				} {
					if st := r.submit(in); st.State != journal.Denied {
						t.Fatalf("agent's %s: %s", in.Action, st.State)
					}
				}
				return
			}
			if st := r.submit(tc.in); st.State != journal.Pending {
				t.Fatalf("submit: %s %q", st.State, st.Permission.Reason)
			}
			r.g.Flush()
			req, _ := r.own.last(t)
			r.own.mu.Lock()
			before := len(r.own.notes)
			r.own.mu.Unlock()
			r.pageDecide(strings.Repeat("0", 64))
			if st := r.state(tc.in.ID); st.State != journal.Denied {
				t.Fatalf("changed item: %s %q", st.State, st.Permission.Reason)
			}
			r.own.mu.Lock()
			got := append([]string(nil), r.own.notes[before:]...)
			r.own.mu.Unlock()
			want := req + " did not run: it changed after my Wi-Fi page showed it. Make the request again if still needed."
			if len(got) != 1 || got[0] != want {
				t.Fatalf("notices %q, want %q", got, want)
			}
			if strings.Contains(got[0], "agent") {
				t.Fatalf("%s item comes only from the owner, but the notice points at the agent: %q", tc.origin, got[0])
			}
			if len(got[0]) > 160 {
				t.Fatalf("notice is %d characters, over one segment", len(got[0]))
			}
		})
	}
}
