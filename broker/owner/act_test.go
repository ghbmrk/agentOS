package owner

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// REQ: CH-4, CH-10, ADP-9, ADP-10

func actItem(ref, act string) Item {
	it := highItem(ref)
	it.Act = act
	return it
}

// A strong code approves at the checker exactly the acts of the items the
// owner approved: a partial YES passes only the chosen items' acts, and
// the checker records them only when the code matches (CH-4, CH-10).
func TestStrongApprovalCarriesTheApprovedItemsActs(t *testing.T) {
	r, f := newVerifierRig(t)
	id, err := r.ch.Request([]Item{actItem("a", "act-a"), actItem("b", "act-b"), highItem("c")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.inbox()
	if got := r.say("YES " + id + " 1 3 " + r.totp()); got != "Approved "+id+" item 1, 3. Denied 2." {
		t.Fatalf("partial YES: %q", got)
	}
	if got := f.acts[len(f.acts)-1]; !reflect.DeepEqual(got, []string{"act-a"}) {
		t.Fatalf("acts sent with the code: %q", got)
	}
	if !reflect.DeepEqual(f.approved, []string{"act-a"}) {
		t.Fatalf("approved acts: %q", f.approved)
	}
	r.decisions()

	// A wrong code approves nothing.
	id, _ = r.ch.Request([]Item{actItem("d", "act-d")}, 0)
	r.inbox()
	if got := r.say("YES " + id + " 000000"); !strings.HasPrefix(got, "Wrong code") {
		t.Fatalf("wrong code: %q", got)
	}
	if !reflect.DeepEqual(f.approved, []string{"act-a"}) {
		t.Fatalf("approved acts after a wrong code: %q", f.approved)
	}
	if got := r.say("YES " + id + " " + r.totp()); got != "Approved "+id+"." {
		t.Fatalf("YES: %q", got)
	}
	if !reflect.DeepEqual(f.approved, []string{"act-a", "act-d"}) {
		t.Fatalf("approved acts: %q", f.approved)
	}
}

// Only the checker records acts, so with acts to approve neither a local
// seed nor a grid cell approves: nothing is checked or counted, and the
// item stays open (CH-4, CH-10).
func TestActsNeedTheChecker(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.Request([]Item{actItem("a", "act-a")}, 0)
	r.inbox()
	if got := r.say("YES " + id + " " + r.totp()); !strings.Contains(got, "did not count") {
		t.Fatalf("local seed with acts: %q", got)
	}
	if ds := r.decisions(); len(ds) != 0 {
		t.Fatalf("decided %+v", ds)
	}
	if r.ch.codes.st.LastStep != 0 {
		t.Fatal("a step was spent")
	}

	// The grid cannot bind an act either.
	r.ch.mu.Lock()
	cell := r.ch.codes.gridChallenge()
	r.ch.mu.Unlock()
	if cell == "" {
		t.Fatal("no grid")
	}
	if got := r.say("YES " + id + " " + GridCell(testSecrets.GridSeed, cell)); !strings.Contains(got, "did not count") {
		t.Fatalf("grid cell with acts: %q", got)
	}
	if ds := r.decisions(); len(ds) != 0 {
		t.Fatalf("decided %+v", ds)
	}
}

// A texted low-tier code is checked by the channel, not the checker, so
// its acts reach the checker as allowed approvals, which serve no secret
// act (CH-4, ADP-9).
func TestTextedCodeAllowsItsActs(t *testing.T) {
	r, f := newVerifierRig(t)
	it := lowItem("a")
	it.Act = "act-a"
	r.ch.Request([]Item{it}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	calls := f.calls()
	if got := r.say("YES " + m[1] + " " + m[2]); got != "Approved "+m[1]+"." {
		t.Fatalf("texted YES: %q", got)
	}
	if f.calls() != calls || len(f.approved) != 0 {
		t.Fatalf("texted code reached the checker: %d calls, approved %q", f.calls()-calls, f.approved)
	}
	if !reflect.DeepEqual(f.allowed, []CheckerAct{{Act: "act-a"}}) {
		t.Fatalf("allowed %+v", f.allowed)
	}
	ds := r.decisions()
	if len(ds) != 1 || !ds[0].Approved || !ds[0].Allowed {
		t.Fatalf("decided %+v", ds)
	}
}

// A texted YES on an item with no act allows nothing and is not marked
// allowed.
func TestTextedCodeWithoutAnActAllowsNothing(t *testing.T) {
	r, f := newVerifierRig(t)
	r.ch.Request([]Item{lowItem("a")}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	if got := r.say("YES " + m[1] + " " + m[2]); got != "Approved "+m[1]+"." {
		t.Fatalf("texted YES: %q", got)
	}
	if len(f.allowed) != 0 {
		t.Fatalf("allowed %+v", f.allowed)
	}
	if ds := r.decisions(); len(ds) != 1 || !ds[0].Approved || ds[0].Allowed {
		t.Fatalf("decided %+v", ds)
	}
}

// When the checker does not record the allowed approval, the texted YES
// approves nothing, does not count as wrong, and the same code still
// works once the checker does (CH-4, ADP-9).
func TestTextedCodeFailsClosedWhenTheAllowFails(t *testing.T) {
	r, f := newVerifierRig(t)
	it := lowItem("a")
	it.Act = "act-a"
	r.ch.Request([]Item{it}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	f.allowErr = errors.New("checker down")
	if got := r.say("YES " + m[1] + " " + m[2]); got != allowErr {
		t.Fatalf("YES with a failed allow: %q", got)
	}
	if ds := r.decisions(); len(ds) != 0 {
		t.Fatalf("decided %+v", ds)
	}
	if len(r.ch.codes.st.Wrong) != 0 {
		t.Fatalf("counted as wrong: %v", r.ch.codes.st.Wrong)
	}
	f.allowErr = nil
	if got := r.say("YES " + m[1] + " " + m[2]); got != "Approved "+m[1]+"." {
		t.Fatalf("retry: %q", got)
	}
	if ds := r.decisions(); len(ds) != 1 || !ds[0].Allowed {
		t.Fatalf("decided %+v", ds)
	}
}

// The act is part of what the owner approved, so a re-issue over other
// bytes is not the same item (OP-3).
func TestItemSumCoversTheAct(t *testing.T) {
	a, b := actItem("a", "act-a"), actItem("a", "act-b")
	if ItemSum(a) == ItemSum(b) {
		t.Fatal("digest ignores the act")
	}
}
