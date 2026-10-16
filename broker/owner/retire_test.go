package owner

import (
	"slices"
	"testing"
)

// REQ: OP-11, OP-12, CH-10, SM-AJ-4
//
// Retiring a request's ID after its last item is answered is a save of
// the restart record. A failed save fails closed: the ID is retired in
// memory anyway, the failure is reported, no new code is issued while
// the record cannot be saved, and the first save that works carries the
// retirement, so a restart neither re-asks the answered request nor
// reuses its ID.

// approveLow opens a low-tier request for ref and returns its ID and code.
func approveLow(t *testing.T, r *rig, ref string) (id, code string) {
	t.Helper()
	if _, err := r.ch.Request([]Item{lowItem(ref)}, 0); err != nil {
		t.Fatal(err)
	}
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	return m[1], m[2]
}

func pendingIDs(s State) []string {
	var ids []string
	for _, p := range s.Pending {
		ids = append(ids, p.ID)
	}
	return ids
}

func TestRetireSaveFailureFailsClosed(t *testing.T) {
	fs := &flakyStore{}
	r := newRig(t, fs)
	id, code := approveLow(t, r, "a")
	fs.setFail(true)
	if got := r.say("YES " + id + " " + code); got != "Approved "+id+"." {
		t.Fatalf("approve: %q", got)
	}
	if ds := r.decisions(); len(ds) != 1 || ds[0].Ref != "a" || !ds[0].Approved {
		t.Fatalf("decisions %+v", ds)
	}
	// The failure is observable.
	if r.ch.RetireErr() == nil {
		t.Fatal("a retire whose save failed reported no error")
	}
	// The ID is retired in memory: no longer pending, kept from reuse,
	// and its code approves nothing again.
	if slices.Contains(pendingIDs(r.ch.codes.st), id) {
		t.Fatalf("answered request %s still pending in memory", id)
	}
	if _, ok := r.ch.codes.st.Retired[id]; !ok {
		t.Fatalf("answered request %s not retired in memory", id)
	}
	r.say("YES " + id + " " + code)
	if ds := r.decisions(); len(ds) != 0 {
		t.Fatalf("a retired code decided again: %+v", ds)
	}
	// No new code while the record cannot be saved.
	if _, err := r.ch.Request([]Item{lowItem("b")}, 0); err == nil {
		t.Fatal("a new request was issued while the restart record could not be saved")
	}
	// The first save that works carries the retirement and clears the
	// error.
	fs.setFail(false)
	if _, err := r.ch.Request([]Item{lowItem("b")}, 0); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	if err := r.ch.RetireErr(); err != nil {
		t.Fatalf("error still reported after a save worked: %v", err)
	}
	saved, _ := fs.MemStore.Load()
	if slices.Contains(pendingIDs(saved), id) {
		t.Fatalf("answered request %s saved as pending", id)
	}
	if _, ok := saved.Retired[id]; !ok {
		t.Fatalf("answered request %s not saved as retired", id)
	}
}

func TestRetiredCodeStaysRetiredAfterRestart(t *testing.T) {
	fs := &flakyStore{}
	r := newRig(t, fs)
	id, code := approveLow(t, r, "a")
	fs.setFail(true)
	if got := r.say("YES " + id + " " + code); got != "Approved "+id+"." {
		t.Fatalf("approve: %q", got)
	}
	fs.setFail(false)
	other, _ := approveLow(t, r, "b")
	r.decisions()

	var carried []Carried
	r.reissue = func(cs []Carried) { carried = append(carried, cs...) }
	r.ch = r.open() // reboot
	r.ch.Boot()
	r.inbox()
	for _, c := range carried {
		if c.Ref == "a" || c.Request == id {
			t.Fatalf("the answered request was carried for a re-ask: %+v", c)
		}
	}
	if len(carried) != 1 || carried[0].Request != other {
		t.Fatalf("carried %+v, want only %s", carried, other)
	}
	for _, d := range r.decisions() {
		if d.Ref == "a" {
			t.Fatalf("the answered request was decided again at boot: %+v", d)
		}
	}
	if _, ok := r.ch.codes.st.Retired[id]; !ok {
		t.Fatalf("%s not retired after restart", id)
	}
}
