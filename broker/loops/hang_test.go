package loops

// REQ: LOOP-7, LOOP-9
//
// P3-4b-3r-fuzz: a fuzz finding for a hang (an engine past its bound, or
// a step whose exec count never moved) has no stored input, so Resolve
// never closes it; CloseTarget does, on a good step of a different
// release binary, saved as not a replay. Its owner text says hang, and
// its open record hides no input finding's cleared text.
//
// P3-4b-3h-r2: the producing binary is held on the finding's own record,
// set by Report and replaced by a re-report, never taken from
// CloseTarget's caller or from a file the fuzz child can write.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	binA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	binB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

const binC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// hangFinding is a hang of detail reported from binary A; a no-input
// detail carries no producer.
func hangFinding(detail string) Finding {
	f := Finding{Check: CheckFuzz, Subject: "sockets.FuzzRequest", Severity: High, Detail: detail}
	if hangDetail(detail) {
		f.Producer = binA
	}
	return f
}

// goodStep is a good step of binary B; its caller names no producer.
func goodStep() Closure {
	return Closure{Kind: ClosureStep, Binary: binB, Execs: 5000, Baseline: 3, At: t0}
}

// stepOf is a good step of binary bin.
func stepOf(bin string) Closure { c := goodStep(); c.Binary = bin; return c }

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
	same, stalled, kind, short, forged, replayed := goodStep(), goodStep(), goodStep(), goodStep(), goodStep(), goodStep()
	same.Binary = binA
	stalled.Execs = stalled.Baseline
	kind.Kind = "replay"
	short.Binary = "abc"
	// The caller names another producer for a step of the record's own.
	forged.Binary, forged.Produced = binA, binB
	replayed.Replayed = true
	for name, c := range map[string]struct {
		id string
		c  Closure
	}{
		"the same binary":       {hang, same},
		"no progress":           {hang, stalled},
		"not a step":            {hang, kind},
		"a malformed digest":    {hang, short},
		"a caller's producer":   {hang, forged},
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
// L3 on #586): CloseTarget marks the told close as Pass does, through
// the one close routine (P3-4b-3r-told).
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
		if !again.Again || !again.Back || len(r.texts) != before+1 || !strings.HasPrefix(r.texts[before], "Security checks: It is back: ") {
			t.Fatalf("%s: back soon: %+v texts %q", d, again, r.texts[before:])
		}
		// As Back, its own close is texted once and not marked, so a flap
		// never ends on "it is back" after it closed (P3-4b-3r-text) and
		// the next return within ReText is digest-only.
		before = len(r.texts)
		if err := r.g.CloseTarget(id, goodStep()); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if got := r.texts[before:]; len(got) != 1 || !strings.Contains(got[0], "Cleared: ") {
			t.Fatalf("%s: a Back close: %q", d, got)
		}
		before = len(r.texts)
		r.now = r.now.Add(time.Hour)
		if third := r.report(t, hangFinding(d)); third.Texted || len(r.texts) != before {
			t.Fatalf("%s: third return: %+v texts %q", d, third, r.texts[before:])
		}
	}
}

// 3h-r2: a hang finding is reported with the SHA-256 of the binary that
// produced it, and only a hang carries one, so no finding is opened that
// no step can close.
func TestAHangFindingIsReportedWithItsProducer(t *testing.T) {
	r := newReportRig(t, nil)
	none, short, upper := hangFinding(FuzzStallDetail), hangFinding(FuzzStallDetail), hangFinding(FuzzOverrunDetail)
	none.Producer, short.Producer, upper.Producer = "", "abc", strings.ToUpper(binA)
	input, noInput, probe := fuzzFinding(), hangFinding(FuzzNoInputDetail), hostile(CheckProbe)
	input.Producer, noInput.Producer, probe.Producer = binA, binA, binA
	for name, f := range map[string]Finding{"no producer": none, "a malformed producer": short, "an uppercase producer": upper,
		"an input finding": input, "a no-input finding": noInput, "a probe finding": probe} {
		if _, err := r.g.Report(context.Background(), f); !errors.Is(err, ErrFinding) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(r.g.Evidence()); n != 0 {
		t.Fatalf("%d records kept", n)
	}
	rec := r.report(t, hangFinding(FuzzStallDetail))
	if rec.Producer != binA || rec.Finding.Producer != "" {
		t.Fatalf("record %+v", rec)
	}
	if e := r.evidenceFor(t, rec.Finding.ID); e.Producer != binA {
		t.Fatalf("evidence %+v", e)
	}
}

// 3h-r2: CloseTarget compares the step's binary against the producer on
// the finding's own record, never one its caller names: a good step of
// A stays open whatever producer the caller claims, and a good step of B
// closes it with the closure naming A.
func TestCloseTargetTakesTheProducerFromItsRecord(t *testing.T) {
	for _, d := range []string{FuzzOverrunDetail, FuzzStallDetail} {
		r := newReportRig(t, nil)
		id := r.report(t, hangFinding(d)).Finding.ID
		claimB := stepOf(binA)
		claimB.Produced = binB
		for name, c := range map[string]Closure{"a good step of A": stepOf(binA), "a good step of A claiming B": claimB} {
			if err := r.g.CloseTarget(id, c); !errors.Is(err, ErrFinding) {
				t.Fatalf("%s: %s: %v", d, name, err)
			}
		}
		if _, open := r.open(id); !open {
			t.Fatalf("%s: closed by a step of its producer", d)
		}
		claimSelf := stepOf(binB)
		claimSelf.Produced = binB
		if err := r.g.CloseTarget(id, claimSelf); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if e := r.evidenceFor(t, id); e.Closure == nil || e.Closure.Binary != binB || e.Closure.Produced != binA {
			t.Fatalf("%s: closure %+v", d, e.Closure)
		}
	}
}

// 3h-r2 (F13): an open hang reported again from another binary records
// that binary as its producer, so a good step of it closes nothing; a
// third binary's does, and its closure names the newer producer.
func TestAReReportedHangRecordsTheNewerProducer(t *testing.T) {
	r := newReportRig(t, nil)
	f := hangFinding(FuzzStallDetail)
	id := r.report(t, f).Finding.ID
	texts := len(r.texts)
	f.Producer = binB
	if rec := r.report(t, f); rec.Producer != binB || rec.Finding.ID != id {
		t.Fatalf("re-reported %+v", rec)
	}
	if len(r.texts) != texts {
		t.Fatalf("a re-report texted %q", r.texts[texts:])
	}
	if e := r.evidenceFor(t, id); e.Producer != binB {
		t.Fatalf("evidence producer %q", e.Producer)
	}
	r.reopen(t)
	if err := r.g.CloseTarget(id, stepOf(binB)); !errors.Is(err, ErrFinding) {
		t.Fatalf("a good step of the newer producer closed it: %v", err)
	}
	if err := r.g.CloseTarget(id, stepOf(binC)); err != nil {
		t.Fatal(err)
	}
	if e := r.evidenceFor(t, id); e.Closure == nil || e.Closure.Produced != binB {
		t.Fatalf("closure %+v", e.Closure)
	}
}

// 3h-r2: the producer is loops' own state, so it survives a restart.
func TestAHangProducerSurvivesARestart(t *testing.T) {
	r := newReportRig(t, nil)
	id := r.report(t, hangFinding(FuzzOverrunDetail)).Finding.ID
	r.reopen(t)
	if err := r.g.CloseTarget(id, stepOf(binA)); !errors.Is(err, ErrFinding) {
		t.Fatalf("after a restart a step of the producer closed it: %v", err)
	}
	if err := r.g.CloseTarget(id, stepOf(binB)); err != nil {
		t.Fatalf("after a restart: %v", err)
	}
	if e := r.evidenceFor(t, id); e.Closure == nil || e.Closure.Produced != binA {
		t.Fatalf("closure %+v", e.Closure)
	}
}

// 3h-r2 (requirement 2): a hang record with no producer, as one saved
// before this package, is refused by CloseTarget and stays open until it
// is reported again, which records the producer.
func TestAHangRecordWithNoProducerStaysOpenUntilReportedAgain(t *testing.T) {
	r := newReportRig(t, nil)
	f := hangFinding(FuzzStallDetail)
	id := r.report(t, f).Finding.ID
	b, err := r.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	old := strings.ReplaceAll(string(b), `"producer":"`+binA+`",`, "")
	if old == string(b) || strings.Contains(old, binA) {
		t.Fatalf("no producer to strip from %s", b)
	}
	if err := r.store.Save([]byte(old)); err != nil {
		t.Fatal(err)
	}
	r.reopen(t)
	for _, bin := range []string{binA, binB} {
		if err := r.g.CloseTarget(id, stepOf(bin)); !errors.Is(err, ErrFinding) {
			t.Fatalf("closed with no producer on record: %v", err)
		}
	}
	if _, open := r.open(id); !open {
		t.Fatal("closed")
	}
	r.report(t, f)
	if err := r.g.CloseTarget(id, stepOf(binB)); err != nil {
		t.Fatalf("after a re-report: %v", err)
	}
}

// P3-4b-3r-told requirement 1 (#586 L3 point 4): with an overrun and a
// stall of one target both open and texted, the stall's close says no
// "Cleared" (the overrun holds the line) and so is not marked; its return
// within ReText is digest-only, not a "back" the owner never heard
// cleared. Once the overrun's own "Cleared" is said, it is marked.
func TestAStallBackAfterAHeldClearIsNotTexted(t *testing.T) {
	r := newReportRig(t, nil)
	over := r.report(t, hangFinding(FuzzOverrunDetail)).Finding.ID
	stall := r.report(t, hangFinding(FuzzStallDetail)).Finding.ID
	before := len(r.texts)
	if err := r.g.CloseTarget(stall, goodStep()); err != nil {
		t.Fatal(err)
	}
	if got := r.texts[before:]; len(got) != 0 || r.g.st.ToldCleared[stall] {
		t.Fatalf("held close: texts %q, marked %v", got, r.g.st.ToldCleared[stall])
	}
	r.now = r.now.Add(time.Hour)
	if back := r.report(t, hangFinding(FuzzStallDetail)); back.Texted || back.Back || len(r.texts) != before {
		t.Fatalf("return after a held clear: %+v texts %q", back, r.texts[before:])
	}
	if err := r.g.CloseTarget(stall, goodStep()); err != nil {
		t.Fatal(err)
	}
	if err := r.g.CloseTarget(over, goodStep()); err != nil {
		t.Fatal(err)
	}
	if got := r.texts[before:]; len(got) != 1 || !strings.Contains(got[0], "Cleared: ") || !r.g.st.ToldCleared[over] {
		t.Fatalf("the overrun's close: texts %q, marked %v", got, r.g.st.ToldCleared[over])
	}
}
