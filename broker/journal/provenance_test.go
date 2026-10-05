package journal

import (
	"testing"
	"time"
)

// REQ: OP-1, REV-5, ADP-9

// TestProvenanceIsRecordedNotFingerprinted: the submitting machine and its
// label are kept from the first submission. A repeat from a fork whose
// label has since risen is the same intent, since the effect is fixed by
// its parameters.
func TestProvenanceIsRecordedNotFingerprinted(t *testing.T) {
	e := mustOpen(t, &MemStore{}, newPolicy(), newService())
	in := intent("a", "acct")
	in.Machine, in.Label = "m1", "public"
	must(e.Submit(in))
	in.Machine, in.Label = "m1-fork", "private"
	st, err := e.Submit(in)
	if err != nil {
		t.Fatalf("repeat from a fork: %v", err)
	}
	if st.Intent.Machine != "m1" || st.Intent.Label != "public" {
		t.Fatalf("provenance %q %q", st.Intent.Machine, st.Intent.Label)
	}
}

// TestAuthorizedSinceCountsLiveAuthorizations: scope bounds see
// authorized intents of one operation in the window, not denied ones.
func TestAuthorizedSinceCountsLiveAuthorizations(t *testing.T) {
	pol := newPolicy()
	e := mustOpen(t, &MemStore{}, pol, newService())
	for _, id := range []string{"a", "b", "c"} {
		must(e.Submit(intent(id, "acct")))
	}
	must(e.Authorize(ctx, "a"))
	must(e.Authorize(ctx, "b"))
	if _, err := e.Dispatch(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	got := e.AuthorizedSince("acct", intent("a", "acct").Action, time.Now().Add(-time.Hour))
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Fatalf("authorized %+v", got)
	}
	if n := len(e.AuthorizedSince("acct", intent("a", "acct").Action, time.Now().Add(time.Hour))); n != 0 {
		t.Fatalf("future window counted %d", n)
	}
	if n := len(e.AuthorizedSince("other", intent("a", "acct").Action, time.Time{})); n != 0 {
		t.Fatalf("other account counted %d", n)
	}
}
