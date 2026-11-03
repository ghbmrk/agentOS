package attention

// REQ: KEY-5

import (
	"math"
	"strconv"
	"testing"
	"time"
)

// pay is a verified, templated send on a clerk newOpt gives no record.
func pay(i int, at time.Time) Decision {
	d := invoice(i)
	d.Clerk, d.At = "pay", at
	return d
}

func recordAll(t *testing.T, o *Optimizer, xs ...Outcome) {
	t.Helper()
	for _, x := range xs {
		if err := o.Record(x); err != nil {
			t.Fatal(err)
		}
	}
}

// earnOn runs a full run of approvals on pay, ending at end, so only the
// gate decides whether it is proposed.
func earnOn(t *testing.T, o *Optimizer, end time.Time) {
	t.Helper()
	for i := range 10 {
		observe(t, o, pay(i, end.Add(-time.Duration(9-i)*time.Hour)))
	}
}

// D-309: no proposal for a clerk with no checked record. It opens at the
// first count whose 95% bound is within 1% (268 clean settled effects,
// not 267), and the suggestion carries the measure.
func TestNoProposalUntilSilentRateIsLow(t *testing.T) {
	start := t0.Add(-80 * 24 * time.Hour)
	end := t0.Add(-10 * 24 * time.Hour)
	for _, n := range []int{0, 267, 268} {
		o := newOpt(t, &memStore{}, nil)
		clean(t, o, "pay", start, n)
		earnOn(t, o, end)
		s := suggestions(t, o)
		if want := n >= 268; (len(s) == 1) != want {
			t.Fatalf("%d clean effects: suggested %v, want %v (%+v)", n, len(s) == 1, want, o.Measure("pay"))
		}
		if n == 268 && (s[0].Detection.Effects != 268 || !s[0].Detection.Ready || s[0].Detection.Detection() != 1) {
			t.Fatalf("measure %+v", s[0].Detection)
		}
		if n == 0 {
			if nec, av := o.Split(); av != 0 || nec != 10 {
				t.Fatalf("A10: %d necessary, %d avoidable before the gate opened", nec, av)
			}
		}
	}
}

// D-309: an effect counts only once all of its day is Settle old, since
// the owner may not have corrected it yet.
func TestFreshEffectsDoNotCount(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
	now := t0
	for i := range 300 { // every effect within the last Settle
		at := now.Add(-5*24*time.Hour + time.Duration(i)*20*time.Minute)
		recordAll(t, o, Outcome{Clerk: "pay", Step: strconv.Itoa(i), Ran: at, At: at})
	}
	earnOn(t, o, now)
	if m := o.Measure("pay"); m.Effects != 0 || m.Ready {
		t.Fatalf("unsettled effects counted: %+v", m)
	}
	if len(suggestions(t, o)) != 0 {
		t.Fatal("proposed on unsettled effects")
	}
	// Its day ends after Now-Settle, so it is not settled yet either.
	edge := now.Add(-Settle - time.Hour)
	recordAll(t, o, Outcome{Clerk: "pay", Step: "edge", Ran: edge, At: edge})
	if m := o.Measure("pay"); m.Effects != 0 {
		t.Fatalf("a partly settled day counted: %+v", m)
	}
	day := edge.Truncate(24 * time.Hour).Add(24*time.Hour + Settle)
	recordAll(t, o, Outcome{Clerk: "other", Step: "tick", Ran: day, At: day})
	if m := o.Measure("pay"); m.Effects != 1 {
		t.Fatalf("a settled day did not count: %+v", m)
	}
	observe(t, o, pay(10, now.Add(9*24*time.Hour)))
	if !o.Measure("pay").Ready || len(suggestions(t, o)) != 1 {
		t.Fatalf("settled effects should open the gate: %+v", o.Measure("pay"))
	}
}

// D-309: a correction of an effect the clerk did not flag is silent and
// counts once per step; one the clerk flagged is a caught failure. Silent
// failures shut the gate; caught ones do not.
func TestSilentFailuresShutTheGate(t *testing.T) {
	start := t0.Add(-80 * 24 * time.Hour)
	end := t0.Add(-10 * 24 * time.Hour)

	o := newOpt(t, &memStore{}, nil)
	clean(t, o, "pay", start, 400)
	for i := range 10 { // ten failures, every one flagged by the clerk
		at := start.Add(time.Duration(500+i) * time.Hour)
		recordAll(t, o, Outcome{Clerk: "pay", Step: "f" + strconv.Itoa(i), Ran: at, At: at, Flagged: true},
			Outcome{Clerk: "pay", Step: "f" + strconv.Itoa(i), Ran: at, At: end, Flagged: true, Corrected: true})
	}
	earnOn(t, o, end)
	m := o.Measure("pay")
	if m.Effects != 410 || m.Flagged != 10 || m.Silent != 0 || !m.Ready || len(suggestions(t, o)) != 1 {
		t.Fatalf("caught failures should not shut the gate: %+v", m)
	}

	o = newOpt(t, &memStore{}, nil)
	clean(t, o, "pay", start, 400)
	for i := range 3 { // three silent failures, one corrected twice
		at := start.Add(time.Duration(i) * time.Hour)
		x := Outcome{Clerk: "pay", Step: "pay-" + strconv.Itoa(i), Ran: at, At: end, Corrected: true}
		recordAll(t, o, x)
		if i == 0 {
			recordAll(t, o, x)
		}
	}
	earnOn(t, o, end)
	m = o.Measure("pay")
	if m.Effects != 400 || m.Silent != 3 || m.Ready || len(suggestions(t, o)) != 0 {
		t.Fatalf("silent failures should shut the gate: %+v", m)
	}
	if math.Abs(m.Detection()) > 1e-9 {
		t.Fatalf("detection %v, want 0", m.Detection())
	}
}

// D-309: the gate turns off again when the record ages out of Window, and
// a correction of an effect logged before the record began (more silent
// failures than effects) keeps it shut.
func TestGateClosesAgain(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
	clean(t, o, "pay", t0.Add(-80*24*time.Hour), 300)
	earnOn(t, o, t0.Add(-10*24*time.Hour))
	if len(suggestions(t, o)) != 1 {
		t.Fatalf("gate should be open: %+v", o.Measure("pay"))
	}
	observe(t, o, pay(10, t0.Add(30*24*time.Hour)))
	if m := o.Measure("pay"); m.Effects != 0 || m.Ready || len(suggestions(t, o)) != 0 {
		t.Fatalf("an aged-out record should shut the gate: %+v", m)
	}

	if u := upper(5, 3); u != 1 {
		t.Fatalf("upper(5,3) = %v, want 1", u)
	}
	if u := upper(0, 0); u != 1 {
		t.Fatalf("upper(0,0) = %v, want 1", u)
	}
}

// D-309: the record persists with the rest of the state.
func TestMeasurePersists(t *testing.T) {
	st := &memStore{}
	o := newOpt(t, st, nil)
	clean(t, o, "pay", t0.Add(-80*24*time.Hour), 300)
	earnOn(t, o, t0.Add(-10*24*time.Hour))
	before := o.Measure("pay")
	o2, err := New(Config{Store: st, UserContent: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	if after := o2.Measure("pay"); after != before || !after.Ready {
		t.Fatalf("reloaded %+v, before %+v", after, before)
	}
}
