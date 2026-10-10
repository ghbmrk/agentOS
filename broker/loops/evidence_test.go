package loops

import (
	"context"
	"errors"
	"testing"
)

// REQ: LOOP-9, LOOP-7
// P3-4b-3r-evidence requirement 1: a fuzz finding with a stored input
// clears only on a replay from a binary other than the one that produced
// it, so nothing the producing target prints clears its own finding. A
// record with no producer is refused until it is reported again with
// one; the oversize finding, which has no input and no producer, is
// exempt; probe findings are not fuzz findings.
func TestResolveNeedsANewBinary(t *testing.T) {
	withProducer := func(f Finding, p string) Finding { f.Producer = p; return f }
	pass := func(f Finding, bin string) Replay { return Replay{Evidence: f.Detail, Passed: true, Binary: bin} }

	t.Run("same binary", func(t *testing.T) {
		for _, f := range []Finding{fuzzFinding(), hangFinding(FuzzNoInputDetail)} {
			r := newReportRig(t, nil)
			id := r.report(t, withProducer(f, binA)).Finding.ID
			for _, bin := range []string{binA, "", "not a digest"} {
				if err := r.g.Resolve(id, pass(f, bin)); !errors.Is(err, ErrFinding) {
					t.Fatalf("%s: cleared on binary %q: %v", f.Detail, bin, err)
				}
			}
			if _, open := r.open(id); !open {
				t.Fatalf("%s: closed", f.Detail)
			}
		}
	})
	t.Run("no producer on record", func(t *testing.T) {
		r := newReportRig(t, nil)
		f := withProducer(fuzzFinding(), "")
		id := r.report(t, f).Finding.ID
		if err := r.g.Resolve(id, pass(f, binB)); !errors.Is(err, ErrFinding) {
			t.Fatalf("cleared a finding with no producer: %v", err)
		}
		// Adoption: reported again with a producer, it clears on another.
		r.report(t, withProducer(f, binA))
		if got := r.g.OpenReported(CheckFuzz); len(got) != 1 || got[0].Producer != binA {
			t.Fatalf("open findings do not name the producer: %+v", got)
		}
		if err := r.g.Resolve(id, pass(f, binA)); !errors.Is(err, ErrFinding) {
			t.Fatalf("cleared on the adopting binary: %v", err)
		}
		if err := r.g.Resolve(id, pass(f, binB)); err != nil {
			t.Fatal(err)
		}
		if e := r.evidenceFor(t, id); e.Replay == nil || e.Replay.Binary != binB || e.Replay.Produced != binA {
			t.Fatalf("replay %+v", e.Replay)
		}
	})
	t.Run("a new failure moves the producer", func(t *testing.T) {
		r := newReportRig(t, nil)
		f := fuzzFinding()
		id := r.report(t, f).Finding.ID
		r.report(t, withProducer(f, binB))
		if err := r.g.Resolve(id, pass(f, binB)); !errors.Is(err, ErrFinding) {
			t.Fatalf("cleared on the binary that failed last: %v", err)
		}
		if err := r.g.Resolve(id, pass(f, binA)); err != nil {
			t.Fatalf("an older binary is still not the producer: %v", err)
		}
	})
	t.Run("oversize exempt", func(t *testing.T) {
		r := newReportRig(t, nil)
		f := Finding{Check: CheckFuzz, Subject: "sockets.FuzzRequest", Severity: High, Detail: FuzzOversizeDetail}
		id := r.report(t, f).Finding.ID
		if err := r.g.Resolve(id, pass(f, "")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("probe has no producer", func(t *testing.T) {
		r := newReportRig(t, nil)
		f := hostile(CheckProbe)
		if _, err := r.g.Report(context.Background(), withProducer(f, binA)); !errors.Is(err, ErrFinding) {
			t.Fatalf("a probe finding named a producer: %v", err)
		}
		id := r.report(t, f).Finding.ID
		if err := r.g.Resolve(id, pass(f, "")); err != nil {
			t.Fatal(err)
		}
	})
}
