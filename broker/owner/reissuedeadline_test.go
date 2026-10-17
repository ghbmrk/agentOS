package owner

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// REQ: CH-10, OP-4

// GR-reissue-deadline (#1317): a re-issued request is opened under the
// absolute deadline it was first given, however long its caller took to
// get here, and one whose deadline has passed is refused, never given the
// default expiry. Its approval is refused once that deadline passes.
func TestAReissuedRequestKeepsItsDeadline(t *testing.T) {
	r := newRig(t, nil)
	deadline := r.clock().Add(7 * time.Minute)
	r.advance(3 * time.Minute) // the caller was slow (a text send before this one)

	a := lowItem("a")
	a.Asked = r.clock().Add(-10 * time.Minute)
	ids, err := r.ch.RequestEach([]Item{a}, []time.Time{deadline})
	if err != nil || ids[0] == "" {
		t.Fatalf("ids %v: %v", ids, err)
	}
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	if m == nil || m[1] != ids[0] {
		t.Fatal("no code for the re-issued request")
	}
	if p := r.pending(ids[0]); p == nil || !p.Expires.Equal(deadline) {
		t.Fatalf("texted request expires %+v, want %v", p, deadline)
	}

	loc := localItem("b")
	loc.Asked = a.Asked
	lids, err := r.ch.RequestLocalEach([]Item{loc}, []time.Time{deadline})
	if err != nil || lids[0] == "" {
		t.Fatalf("local ids %v: %v", lids, err)
	}
	r.inbox()
	if p := r.pending(lids[0]); p == nil || !p.Expires.Equal(deadline) {
		t.Fatalf("page request expires %+v, want %v", p, deadline)
	}

	// A zero deadline is a fresh request: the default expiry from now.
	fids, err := r.ch.RequestEach([]Item{lowItem("c")}, []time.Time{{}})
	if err != nil || fids[0] == "" {
		t.Fatalf("fresh ids %v: %v", fids, err)
	}
	r.inbox()
	if p := r.pending(fids[0]); p == nil || !p.Expires.Equal(r.clock().Add(r.ch.cfg.CodeTTL)) {
		t.Fatalf("fresh request expires %+v", p)
	}

	// Final approval: past the deadline the code no longer approves.
	r.advance(5 * time.Minute)
	if got := r.say("YES " + m[1] + " " + m[2]); strings.HasPrefix(got, "Approved") {
		t.Fatalf("approved past its deadline: %q", got)
	}
	expired := false
	for _, d := range r.decisions() {
		if d.Ref == "a" {
			if d.Approved || d.Why != "expired" {
				t.Fatalf("decision %+v", d)
			}
			expired = true
		}
	}
	if !expired {
		t.Fatal("no expired decision for the re-issued request")
	}
}

// A re-issued request whose deadline has passed by the time it is opened
// is refused with ErrExpired: no request, no text, no default expiry.
func TestAPassedDeadlineIsRefusedNotRenewed(t *testing.T) {
	r := newRig(t, nil)
	before := len(r.carrier.Log())
	pending := len(r.ch.codes.st.Pending)
	for _, local := range []bool{false, true} {
		it, each := lowItem("a"), r.ch.RequestEach
		if local {
			it, each = localItem("b"), r.ch.RequestLocalEach
		}
		ids, err := each([]Item{it}, []time.Time{r.clock()})
		if !errors.Is(err, ErrExpired) || ids[0] != "" {
			t.Fatalf("local=%v: ids %v err %v", local, ids, err)
		}
	}
	if n := len(r.carrier.Log()) - before; n != 0 || len(r.ch.codes.st.Pending) != pending || len(r.ch.open) != 0 {
		t.Fatalf("%d texts, %d pending, %d open", n, len(r.ch.codes.st.Pending)-pending, len(r.ch.open))
	}
	if _, err := r.ch.RequestEach([]Item{lowItem("c")}, nil); err == nil {
		t.Fatal("deadlines must match items")
	}
}

func (r *rig) pending(id string) *PendingRef {
	r.ch.mu.Lock()
	defer r.ch.mu.Unlock()
	for _, p := range r.ch.codes.st.Pending {
		if p.ID == id {
			p := p
			return &p
		}
	}
	return nil
}
