package change

// How an owner's request for a release closed, for Loop 3 (P2-2a-f4).
// REQ: P2-2a-f4a

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// P2-2a-f4a: Closed reports once how a release proposal's request closed:
// unanswered, the owner's NO, left out of a partial YES, or approved and
// not installed. An adopted release, a local change, one still waiting and
// one already reported read "". Lapsed still reports only a lapse.
func TestClosedReportsHowARequestClosed(t *testing.T) {
	tg := &fakeTarget{ns: "host-image", cur: Tree{}}
	e := newEnv(t, func(c *Config) { c.Targets = map[string]Target{"host-image": tg} })
	e.p.Attach(holdJournal{e.eng})
	img := func(s string) map[string][]byte { return map[string][]byte{"host-image/release": []byte(s)} }
	get := func(id string) journal.Status {
		t.Helper()
		st, err := e.eng.Get(adoptID(id))
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	// Unanswered.
	r := e.release(release(t, 30, true, img("h")))
	if r.State != StateAwaitingOwner || e.p.Closed(r.ID) != "" {
		t.Fatalf("closed before the request closed: %+v", r)
	}
	e.p.Decided(bg, get(r.ID).Intent, "expired")
	if got := e.p.Closed(r.ID); got != ClosedLapsed {
		t.Fatalf("lapse reads %q", got)
	}
	if got := e.p.Closed(r.ID); got != "" {
		t.Fatalf("a lapse is reported twice: %q", got)
	}

	// Lapsed keeps its contract: true once, for a lapse only.
	r = e.release(release(t, 31, true, img("i")))
	e.p.Decided(bg, get(r.ID).Intent, "")
	if !e.p.Lapsed(r.ID) || e.p.Lapsed(r.ID) || e.p.Closed(r.ID) != "" {
		t.Fatal("Lapsed does not report a lapse once")
	}

	// The owner's NO.
	r = e.release(release(t, 32, true, img("j")))
	e.eng.Authorize(bg, adoptID(r.ID))
	if st := get(r.ID); st.State != journal.Denied {
		t.Fatal(st.State)
	}
	e.p.Decided(bg, get(r.ID).Intent, "owner")
	if e.p.Lapsed(r.ID) {
		t.Fatal("the owner's no reads as a lapse")
	}
	if got := e.p.Closed(r.ID); got != ClosedDeclined {
		t.Fatalf("the owner's no reads %q", got)
	}

	// Left out of a partial YES.
	r = e.release(release(t, 33, true, img("k")))
	e.eng.Authorize(bg, adoptID(r.ID))
	e.p.Decided(bg, get(r.ID).Intent, "not chosen")
	if got := e.p.Closed(r.ID); got != ClosedLeftOut {
		t.Fatalf("left out reads %q", got)
	}

	// Approved, then not installed.
	e.owner.approve = true
	tg.fail = errors.New("disk full")
	r = e.release(release(t, 34, true, img("l")))
	if _, err := e.eng.Authorize(bg, adoptID(r.ID)); err != nil {
		t.Fatal(err)
	}
	st, _ := e.eng.Dispatch(bg, adoptID(r.ID))
	if st.State != journal.NotApplied {
		t.Fatalf("dispatch: %s", st.State)
	}
	e.p.Decided(bg, st.Intent, "")
	if e.p.Waiting(r.ID) {
		t.Fatal("a failed install is still waiting")
	}
	if got := e.p.Closed(r.ID); got != ClosedFailed {
		t.Fatalf("a failed install reads %q", got)
	}

	// Approved and installed.
	tg.fail = nil
	r = e.release(release(t, 35, true, img("m")))
	e.eng.Authorize(bg, adoptID(r.ID))
	st, _ = e.eng.Dispatch(bg, adoptID(r.ID))
	if st.State != journal.Succeeded {
		t.Fatalf("dispatch: %s", st.State)
	}
	e.p.Decided(bg, st.Intent, "")
	if got := e.p.Closed(r.ID); got != "" {
		t.Fatalf("an adopted release reads %q", got)
	}

	// A local change is not a release.
	e.owner.approve = false
	e.cases(12, ClassSkill, "skills/greet", "hello")
	l := e.propose(Candidate{Source: Local, Files: Tree{"config/a": []byte("1")}})
	if l.State != StateAwaitingOwner {
		t.Fatal(l)
	}
	e.p.Decided(bg, get(l.ID).Intent, "expired")
	if e.p.Waiting(l.ID) || e.p.Closed(l.ID) != "" {
		t.Fatal("a local change reads as a closed release")
	}
	if e.p.Closed("c999") != "" {
		t.Fatal("an unknown proposal reads as closed")
	}
}
