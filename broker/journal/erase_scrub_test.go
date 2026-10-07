package journal

// REQ: CAP-3, OP-5

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// quotingPolicy denies the intents it is told to, with a reason that quotes
// the intent's body, as a real policy's error text may (#59 L3).
type quotingPolicy struct {
	*testPolicy
	deny map[string]bool
}

func (p quotingPolicy) Check(ctx context.Context, phase Phase, in Intent) error {
	if p.deny[in.ID] {
		// canaryIntent's body, quoted.
		return errors.New("body quoting zebracorn-" + in.ID + " is not allowed")
	}
	return p.testPolicy.Check(ctx, phase, in)
}

// An erase also removes what a decision reason or a quality note quoted
// from the intent (#59 L3: Permission.Reason and RecQuality notes), in
// memory and in the file, while the decision, its phase, the verdict and
// its source stay for the audit trail (OP-5). A note recorded after the
// erase is not kept either.
func TestEraseScrubsReasonsAndQualityNotes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	st, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pol := quotingPolicy{newPolicy(), map[string]bool{}}
	e := mustOpen(t, st, pol, newService())
	for _, id := range []string{"a", "p", "r"} {
		must(e.Submit(canaryIntent(id, "guest:L")))
	}
	must(e.Authorize(ctx, "a"))
	must(e.Dispatch(ctx, "a"))
	must(e.RecordQuality("a", Quality{Verdict: VerdictWrong, Source: "owner", Note: "owner said zebracorn-a was wrong"}))
	pol.deny["p"] = true
	if s := must(e.Authorize(ctx, "p")); s.State != Denied {
		t.Fatalf("policy did not deny p: %+v", s)
	}
	pol.deny["p"] = false
	must(e.Authorize(ctx, "r"))
	pol.deny["r"] = true
	e.Dispatch(ctx, "r")
	if s := must(e.Get("r")); s.State != Denied || s.Permission.Phase != PhaseDispatch {
		t.Fatalf("recheck did not fail r: %+v", s)
	}
	data, _ := os.ReadFile(path)
	for _, id := range []string{"a", "p", "r"} {
		if strings.Count(string(data), "zebracorn-"+id) < 2 {
			t.Fatalf("test needs %s's reason or note to quote it:\n%s", id, data)
		}
	}
	if _, _, err := e.Erase([]string{"a", "p", "r"}); err != nil {
		t.Fatal(err)
	}
	check := func(e *Engine, when string) {
		t.Helper()
		a := must(e.Get("a"))
		if a.Quality.Note != "" || a.Quality.Verdict != VerdictWrong || a.Quality.Source != "owner" {
			t.Fatalf("%s: quality %+v", when, a.Quality)
		}
		for id, phase := range map[string]Phase{"p": PhaseAuthorize, "r": PhaseDispatch} {
			s := must(e.Get(id))
			if s.Permission.Decision != "denied" || s.Permission.Phase != phase || s.Permission.Reason != ErasedDetail {
				t.Fatalf("%s: %s permission %+v", when, id, s.Permission)
			}
		}
	}
	check(e, "after erase")
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "zebracorn") {
		t.Fatalf("a quoted value remains in the journal file:\n%s", data)
	}
	// A late note on an erased intent keeps its verdict, not its words.
	must(e.RecordQuality("a", Quality{Verdict: VerdictWrong, Source: "owner", Note: "again zebracorn-a"}))
	check(e, "after a late note")
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "zebracorn") {
		t.Fatalf("a late note on an erased intent was journaled:\n%s", data)
	}
	st.Close()
	st2, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	check(mustOpen(t, st2, pol, newService()), "after reopen")
}

// A denial whose reason quotes the intent is content a crash-cut rewrite
// may leave behind: Open finishes the erase for it too.
func TestEraseOfQuotedReasonFinishedOnOpen(t *testing.T) {
	st := &failingRewrite{}
	pol := quotingPolicy{newPolicy(), map[string]bool{"p": true}}
	e := mustOpen(t, st, pol, newService())
	// No params or preconditions: only the reason carries the value.
	in := canaryIntent("p", "guest:L")
	in.Params, in.Preconditions = nil, nil
	must(e.Submit(in))
	if s := must(e.Authorize(ctx, "p")); s.State != Denied {
		t.Fatalf("policy did not deny p: %+v", s)
	}
	st.fail = true
	if _, _, err := e.Erase([]string{"p"}); err == nil {
		t.Fatal("failed rewrite not reported")
	}
	st.fail = false
	data, _ := st.ReadAll()
	if !strings.Contains(string(data), "zebracorn-p is not allowed") {
		t.Fatal("test needs the reason left behind")
	}
	e2 := mustOpen(t, st, pol, newService())
	data, _ = st.ReadAll()
	if strings.Contains(string(data), "zebracorn-p") {
		t.Fatalf("open did not finish the erase:\n%s", data)
	}
	if s := must(e2.Get("p")); s.Permission.Reason != ErasedDetail {
		t.Fatalf("reason after open: %q", s.Permission.Reason)
	}
}
