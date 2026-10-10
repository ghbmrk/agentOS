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
		Detail:   "crash input sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		Producer: binA}
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
	if len(r.texts) != 1 || !strings.Contains(r.texts[0], "a crash in the check that reads agent requests") {
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
	passed := Replay{Evidence: fuzzFinding().Detail, Passed: true, Binary: binB}
	if err := r.g.Resolve(id, passed); err != nil {
		t.Fatal(err)
	}
	if want := (Replay{Evidence: passed.Evidence, Passed: true, Binary: binB, Produced: binA}); r.evidenceFor(t, id).Replay == nil || *r.evidenceFor(t, id).Replay != want {
		t.Fatalf("replay not recorded: %+v", r.evidenceFor(t, id).Replay)
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
	if err := r.g.Resolve(id, passed); !errors.Is(err, ErrFinding) {
		t.Fatalf("resolving a closed finding: %v", err)
	}
}

// Resolve closes only rule-less reported findings: one with linked cases
// clears when they hold (passedReported), never on a caller's word.
func TestResolveRefusesAFindingWithATreeRule(t *testing.T) {
	r := newReportRig(t, nil)
	rec := r.report(t, seedFinding())
	if err := r.g.Resolve(rec.Finding.ID, Replay{Evidence: rec.Finding.Detail, Passed: true, Binary: binB}); !errors.Is(err, ErrFinding) {
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

// Coordinator condition on P3-4b-3: Resolve clears a fuzz or probe
// finding only on a passing replay of its own stored input. A failed
// replay, or a passing one of another input, leaves it open and changes
// nothing.
func TestResolveWithoutAPassingReplayDoesNothing(t *testing.T) {
	r := newReportRig(t, nil)
	rec := r.report(t, fuzzFinding())
	id := rec.Finding.ID
	texts := len(r.texts)
	for name, rp := range map[string]Replay{
		"no replay":     {},
		"failed":        {Evidence: rec.Finding.Detail},
		"another input": {Evidence: "crash input sha256:ff", Passed: true},
	} {
		if err := r.g.Resolve(id, rp); !errors.Is(err, ErrFinding) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, open := r.open(id); !open {
			t.Fatalf("%s: closed", name)
		}
		if e := r.evidenceFor(t, id); e.Replay != nil {
			t.Fatalf("%s: replay recorded %+v", name, e.Replay)
		}
	}
	if _, cleared := r.g.st.Cleared[id]; cleared || len(r.texts) != texts {
		t.Fatalf("acted: cleared %v, texts %q", cleared, r.texts)
	}
}

// The new wait wording is owner text in a scanned file and passes the
// scan (S18).
func TestTheUpdateWaitWordingIsScanned(t *testing.T) {
	if !contains(ownerTables, "report.go") {
		t.Fatal("report.go is not scanned")
	}
	if banned.MatchString(waitUpdate) || banned.MatchString(findingText(fuzzFinding())) {
		t.Fatalf("wording %q", waitUpdate)
	}
}
