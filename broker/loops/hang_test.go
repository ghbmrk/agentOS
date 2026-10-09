package loops

// REQ: LOOP-7, LOOP-9
//
// P3-4b-3r-fuzz: a fuzz finding for a hang (an engine past its bound, or
// a step whose exec count never moved) has no stored input, so Resolve
// never closes it; CloseTarget does, on a good step of a different
// release binary, saved as not a replay. Its owner text says hang, and
// its open record hides no input finding's cleared text.

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	binA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	binB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func hangFinding(detail string) Finding {
	return Finding{Check: CheckFuzz, Subject: "sockets.FuzzRequest", Severity: High, Detail: detail}
}

func goodStep() Closure {
	return Closure{Kind: ClosureStep, Binary: binB, Produced: binA, Execs: 5000, Baseline: 3, At: t0}
}

// A hang finding is never resolved by a "replay": it has no stored input.
func TestResolveRefusesAHangFinding(t *testing.T) {
	for _, d := range []string{FuzzOverrunDetail, FuzzStallDetail} {
		r := newReportRig(t, nil)
		id := r.report(t, hangFinding(d)).Finding.ID
		if err := r.g.Resolve(id, Replay{Evidence: d, Passed: true}); !errors.Is(err, ErrFinding) {
			t.Fatalf("%s: resolved by a replay: %v", d, err)
		}
		if _, open := r.open(id); !open {
			t.Fatalf("%s: closed", d)
		}
	}
}

// A good step of a different binary closes a hang finding, saves the
// closure on its evidence marked as not a replay, and texts "Cleared"
// once, since the finding was texted.
func TestAGoodStepOfANewBinaryClosesAHangFinding(t *testing.T) {
	for _, d := range []string{FuzzOverrunDetail, FuzzStallDetail} {
		r := newReportRig(t, nil)
		rec := r.report(t, hangFinding(d))
		id := rec.Finding.ID
		if !rec.Texted {
			t.Fatalf("%s: not texted: %+v", d, rec)
		}
		before := len(r.texts)
		if err := r.g.CloseTarget(id, goodStep()); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if _, open := r.open(id); open {
			t.Fatalf("%s: still open", d)
		}
		e := r.evidenceFor(t, id)
		if e.Closure == nil || e.Closure.Replayed || e.Closure.Binary != binB || e.Closure.Produced != binA || e.Replay != nil {
			t.Fatalf("%s: evidence %+v closure %+v", d, e, e.Closure)
		}
		if got := r.texts[before:]; len(got) != 1 || !strings.Contains(got[0], "Cleared: the check that reads agent requests responds to test inputs again.") {
			t.Fatalf("%s: texts %q", d, got)
		}
		for _, u := range r.urgent[before:] {
			if u {
				t.Fatalf("%s: the cleared text was urgent", d)
			}
		}
		if err := r.g.CloseTarget(id, goodStep()); !errors.Is(err, ErrFinding) {
			t.Fatalf("%s: closed twice: %v", d, err)
		}
		if len(r.texts) != before+1 {
			t.Fatalf("%s: texted again: %q", d, r.texts[before:])
		}
	}
}

// Only a good step of a different binary is evidence; nothing else closes
// a hang finding, and CloseTarget never closes an input finding or
// another check's.
func TestCloseTargetRefusesAnythingElse(t *testing.T) {
	r := newReportRig(t, nil)
	hang := r.report(t, hangFinding(FuzzStallDetail)).Finding.ID
	input := r.report(t, fuzzFinding()).Finding.ID
	noInput := r.report(t, hangFinding(FuzzNoInputDetail)).Finding.ID
	probe := hostile(CheckProbe)
	probeID := r.report(t, probe).Finding.ID
	texts := len(r.texts)
	same, stalled, kind, short, empty, replayed := goodStep(), goodStep(), goodStep(), goodStep(), goodStep(), goodStep()
	same.Binary = same.Produced
	stalled.Execs = stalled.Baseline
	kind.Kind = "replay"
	short.Binary = "abc"
	empty.Produced = ""
	replayed.Replayed = true
	for name, c := range map[string]struct {
		id string
		c  Closure
	}{
		"the same binary":       {hang, same},
		"no progress":           {hang, stalled},
		"not a step":            {hang, kind},
		"a malformed digest":    {hang, short},
		"no producing binary":   {hang, empty},
		"a closure as a replay": {hang, replayed},
		"an input finding":      {input, goodStep()},
		"a no-input finding":    {noInput, goodStep()},
		"a probe finding":       {probeID, goodStep()},
		"an unknown finding":    {"fuzz:nothing", goodStep()},
	} {
		if err := r.g.CloseTarget(c.id, c.c); !errors.Is(err, ErrFinding) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, id := range []string{hang, input, noInput, probeID} {
		if _, open := r.open(id); !open {
			t.Fatalf("%s closed", id)
		}
	}
	if len(r.texts) != texts {
		t.Fatalf("texted %q", r.texts[texts:])
	}
}

// The cleared line names what cleared, and is keyed on it (L3 on #586
// point 1): a crash fix and a hang closing on one target are told
// apart, so "Cleared" is never ambiguous with a finding still open.
func TestClearedNamesTheCrashOrTheHang(t *testing.T) {
	const crashCleared = "Cleared: the crash in the check that reads agent requests. Nothing more is needed from you."
	const hangCleared = "Cleared: the check that reads agent requests responds to test inputs again. Nothing more is needed from you."
	t.Run("hang open, crash resolves", func(t *testing.T) {
		r := newReportRig(t, nil)
		r.report(t, hangFinding(FuzzStallDetail))
		crash := r.report(t, fuzzFinding()).Finding
		before := len(r.texts)
		if err := r.g.Resolve(crash.ID, Replay{Evidence: crash.Detail, Passed: true}); err != nil {
			t.Fatal(err)
		}
		if got := r.texts[before:]; len(got) != 1 || !strings.HasSuffix(got[0], crashCleared) {
			t.Fatalf("texts %q", got)
		}
	})
	t.Run("no-input open, input crash resolves", func(t *testing.T) {
		r := newReportRig(t, nil)
		r.report(t, hangFinding(FuzzNoInputDetail))
		crash := r.report(t, fuzzFinding()).Finding
		before := len(r.texts)
		if err := r.g.Resolve(crash.ID, Replay{Evidence: crash.Detail, Passed: true}); err != nil {
			t.Fatal(err)
		}
		if got := r.texts[before:]; len(got) != 0 {
			t.Fatalf("cleared while a crash in the same target is open: %q", got)
		}
	})
	t.Run("crash open, hang closes", func(t *testing.T) {
		r := newReportRig(t, nil)
		hang := r.report(t, hangFinding(FuzzOverrunDetail)).Finding
		r.report(t, fuzzFinding())
		before := len(r.texts)
		if err := r.g.CloseTarget(hang.ID, goodStep()); err != nil {
			t.Fatal(err)
		}
		if got := r.texts[before:]; len(got) != 1 || !strings.HasSuffix(got[0], hangCleared) {
			t.Fatalf("texts %q", got)
		}
	})
}

// A3-r6, 3h: the owner hears that a self-test stopped responding, not
// that it crashed; an input finding and a no-input finding keep the crash
// wording.
func TestAHangFindingSaysHangNotCrash(t *testing.T) {
	for _, d := range []string{FuzzOverrunDetail, FuzzStallDetail} {
		got := findingText(hangFinding(d))
		if want := "My self-test of the check that reads agent requests stopped responding to a test input. The fix comes with an update."; got != want {
			t.Errorf("%s: %q", d, got)
		}
	}
	for _, f := range []Finding{fuzzFinding(), hangFinding(FuzzNoInputDetail)} {
		if got := findingText(f); got != "My self-test found a crash in the check that reads agent requests. The fix comes with an update." {
			t.Errorf("%s: %q", f.Detail, got)
		}
	}
}

// A hang that returns within ReText after its texted "responds to test
// inputs again" is texted again, not left as a digest-only Again (delta
// L3 on #586): CloseTarget marks the told close as Pass does.
func TestAHangBackSoonAfterItsClearedTextIsTextedAgain(t *testing.T) {
	for _, d := range []string{FuzzOverrunDetail, FuzzStallDetail} {
		r := newReportRig(t, nil)
		id := r.report(t, hangFinding(d)).Finding.ID
		if err := r.g.CloseTarget(id, goodStep()); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		before := len(r.texts)
		r.now = r.now.Add(time.Hour)
		again := r.report(t, hangFinding(d))
		if !again.Again || !again.Texted || len(r.texts) != before+1 || strings.Contains(r.texts[before], "Cleared") {
			t.Fatalf("%s: back soon: %+v texts %q", d, again, r.texts[before:])
		}
		// As Again, its own close is digest-only: a flap ends on "it is back".
		before = len(r.texts)
		if err := r.g.CloseTarget(id, goodStep()); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if got := r.texts[before:]; len(got) != 0 {
			t.Fatalf("%s: an Again close was texted: %q", d, got)
		}
	}
}
