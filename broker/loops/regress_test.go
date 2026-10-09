package loops

// REQ: LOOP-7, LOOP-9

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func fuzzFinding() Finding {
	return Finding{Check: CheckFuzz, Subject: "sockets.FuzzRequest", Severity: High,
		Detail: "crash input sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}
}

// P3-4b-3 (LOOP-7, LOOP-9): a fuzz or probe failure has no tree rule, so
// Report takes it without one: evidence saved, owner texted, no case and
// no fix request (the fix comes with an update), and STATUS says so. It
// stays open across passes until its regression replays clean and the
// caller resolves it; then it closes as cleared.
func TestARuleLessFuzzFindingIsReportedAndResolved(t *testing.T) {
	fx := &scriptFixer{}
	r := newReportRig(t, fx)
	before := r.p.SecurityCount()
	rec := r.report(t, fuzzFinding())
	id := rec.Finding.ID
	if id == "" || rec.Fix != "" || rec.Fixture != "" || r.p.SecurityCount() != before {
		t.Fatalf("record %+v, suite %d -> %d", rec, before, r.p.SecurityCount())
	}
	if e := r.evidenceFor(t, id); e.Finding.Detail != fuzzFinding().Detail {
		t.Fatalf("evidence %+v", e)
	}
	if len(r.texts) != 1 || !strings.Contains(r.texts[0], "Fuzz test sockets.FuzzRequest") {
		t.Fatalf("texts %q", r.texts)
	}
	if s := r.g.Status(); !strings.Contains(s, waitUpdate) || strings.Contains(s, waitNoTest) {
		t.Fatalf("status %q", s)
	}
	if again := r.report(t, fuzzFinding()); again.Finding.ID != id || len(r.texts) != 1 {
		t.Fatalf("a repeat report acted again: %+v %q", again, r.texts)
	}
	r.g.Trigger()
	r.pass(t)
	if _, open := r.open(id); !open {
		t.Fatal("closed before its regression passed")
	}
	if len(fx.got) != 0 {
		t.Fatal("the fixer was called for a rule-less finding")
	}
	if got := r.g.OpenReported(CheckFuzz); len(got) != 1 || got[0].ID != id {
		t.Fatalf("open fuzz findings %+v", got)
	}
	if got := r.g.OpenReported(CheckProbe); len(got) != 0 {
		t.Fatalf("open probe findings %+v", got)
	}
	if err := r.g.Resolve(id); err != nil {
		t.Fatal(err)
	}
	if got := r.g.OpenReported(CheckFuzz); len(got) != 0 {
		t.Fatalf("resolved but listed %+v", got)
	}
	if _, open := r.open(id); open {
		t.Fatal("resolved finding still open")
	}
	if s := r.g.Status(); strings.Contains(s, waitForAFixOf) {
		t.Fatalf("status still waits: %q", s)
	}
	if err := r.g.Resolve(id); !errors.Is(err, ErrFinding) {
		t.Fatalf("resolving a closed finding: %v", err)
	}
}

// Resolve closes only rule-less reported findings: one with linked cases
// clears when they hold (passedReported), never on a caller's word.
func TestResolveRefusesAFindingWithATreeRule(t *testing.T) {
	r := newReportRig(t, nil)
	rec := r.report(t, seedFinding())
	if err := r.g.Resolve(rec.Finding.ID); !errors.Is(err, ErrFinding) {
		t.Fatalf("resolved a rule finding: %v", err)
	}
	if _, open := r.open(rec.Finding.ID); !open {
		t.Fatal("closed")
	}
}

// A fuzz or probe finding carrying a rule, or a rule-less finding of any
// other check, is refused before anything acts.
func TestRuleLessOnlyForFuzzAndProbe(t *testing.T) {
	r := newReportRig(t, nil)
	bad := []Finding{fuzzFinding(), {Check: CheckSeeded, Subject: "x", Severity: High}, {Check: CheckProbe, Subject: "p", Severity: High}}
	bad[0].Rule = seedFinding().Rule
	for _, f := range bad {
		if _, err := r.g.Report(context.Background(), f); !errors.Is(err, ErrFinding) {
			t.Fatalf("%+v: %v", f, err)
		}
	}
	if len(r.g.Evidence()) != 0 {
		t.Fatal("acted on a refused finding")
	}
}
