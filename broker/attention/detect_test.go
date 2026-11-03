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
	if err := o.Record(xs...); err != nil {
		t.Fatal(err)
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

// D-309 (L3 and Security on #4945, 4d8ee5f): each step counts once, by
// the record's own view of it. A repeated effect is ignored; an outcome
// without its clerk or step is refused; a correction is judged by its
// effect's stored flag, never its own; a correction of a step never seen
// counts as silent.
func TestStepIdentity(t *testing.T) {
	at := t0.Add(-30 * 24 * time.Hour)
	tick := Outcome{Clerk: "other", Step: "tick", Ran: t0, At: t0}

	o := newOpt(t, &memStore{}, nil)
	for i := range 134 {
		x := Outcome{Clerk: "pay", Step: strconv.Itoa(i), Ran: at, At: at}
		recordAll(t, o, x, x)
	}
	recordAll(t, o, tick)
	if m := o.Measure("pay"); m.Effects != 134 || m.Ready {
		t.Fatalf("a repeated effect counted twice: %+v", m)
	}

	for _, x := range []Outcome{{Clerk: "pay", Ran: at, At: at, Corrected: true}, {Step: "1", Ran: at, At: at}} {
		if err := o.Record(Outcome{Clerk: "pay", Step: "ok", Ran: at, At: at}, x); err != ErrOutcome {
			t.Fatalf("%+v: err %v, want ErrOutcome", x, err)
		}
	}
	if m := o.Measure("pay"); m.Effects != 134 {
		t.Fatalf("a refused call applied part of itself: %+v", m)
	}

	o = newOpt(t, &memStore{}, nil)
	clean(t, o, "pay", at, 300)
	for i := range 10 { // the clerk never flagged these; the corrections claim it did
		recordAll(t, o, Outcome{Clerk: "pay", Step: "pay-" + strconv.Itoa(i), Ran: at, At: at, Flagged: true, Corrected: true})
	}
	recordAll(t, o, tick)
	if m := o.Measure("pay"); m.Silent != 10 || m.Ready {
		t.Fatalf("a correction's own flag hid a silent failure: %+v", m)
	}

	o = newOpt(t, &memStore{}, nil)
	clean(t, o, "pay", at.Add(-24*time.Hour), 300)
	recordAll(t, o, Outcome{Clerk: "pay", Step: "f", Ran: at, At: at, Flagged: true},
		Outcome{Clerk: "pay", Step: "f", Ran: at, At: at, Corrected: true},
		Outcome{Clerk: "pay", Step: "never-seen", Ran: at, At: at, Corrected: true}, tick)
	if m := o.Measure("pay"); m.Effects != 301 || m.Flagged != 1 || m.Silent != 1 {
		t.Fatalf("flagged effect or unseen step misjudged: %+v", m)
	}
}

// D-309 (Security on #4945): the bound can only be made stricter; a looser
// setting reads as 1%.
func TestBoundOnlyTightens(t *testing.T) {
	at := t0.Add(-30 * 24 * time.Hour)
	for _, cap := range []int{1000, 11, -1} {
		o := newOpt(t, &memStore{}, func(c *Config) { c.MaxSilentPerMille = cap })
		for i := range 10 {
			s := strconv.Itoa(i)
			recordAll(t, o, Outcome{Clerk: "pay", Step: s, Ran: at, At: at}, Outcome{Clerk: "pay", Step: s, Ran: at, At: at, Corrected: true})
		}
		recordAll(t, o, Outcome{Clerk: "other", Step: "tick", Ran: t0, At: t0})
		if m := o.Measure("pay"); m.Ready || o.cfg.MaxSilentPerMille != MaxSilentPerMille {
			t.Fatalf("cap %d: %+v, bound %d", cap, m, o.cfg.MaxSilentPerMille)
		}
	}
	if o := newOpt(t, &memStore{}, func(c *Config) { c.MaxSilentPerMille = 5 }); o.cfg.MaxSilentPerMille != 5 {
		t.Fatal("a stricter bound must hold")
	}
}

// D-309 (L3 R1 on #4945): Due reads the record on its own clock, so a
// record that aged out during a quiet spell no longer counts.
func TestDueAdvancesTheClock(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
	clean(t, o, "pay", t0.Add(-80*24*time.Hour), 300)
	earnOn(t, o, t0.Add(-10*24*time.Hour))
	if len(suggestions(t, o)) != 1 {
		t.Fatalf("gate should be open: %+v", o.Measure("pay"))
	}
	due, err := o.Due(t0.Add(30 * 24 * time.Hour))
	if err != nil || len(due) != 0 {
		t.Fatalf("offered on an aged-out record: %+v %v", due, err)
	}
}

// D-309 (L3 delta on #4945, cc272c34): a correction of a known step is
// placed by the step's own day, so a stale Ran on the correction cannot
// drop it.
func TestCorrectionUsesItsStepsDay(t *testing.T) {
	at := t0.Add(-30 * 24 * time.Hour)
	o := newOpt(t, &memStore{}, nil)
	clean(t, o, "pay", at, 300)
	for i := range 10 {
		recordAll(t, o, Outcome{Clerk: "pay", Step: "pay-" + strconv.Itoa(i), Ran: t0.Add(-200 * 24 * time.Hour), At: t0, Corrected: true})
	}
	if m := o.Measure("pay"); m.Silent != 10 || m.Ready {
		t.Fatalf("corrections dropped: %+v", m)
	}
}

// D-309 invariant 1 (Security on #4945, 6612158899 and 6612913895): an
// outcome with no Ran or no At, effect or correction, refuses the whole
// call before anything applies.
func TestOutcomeNeedsBothTimes(t *testing.T) {
	at := t0.Add(-30 * 24 * time.Hour)
	o := newOpt(t, &memStore{}, nil)
	ok := Outcome{Clerk: "pay", Step: "ok", Ran: at, At: at}
	for _, bad := range []Outcome{
		{Clerk: "pay", Step: "1", At: at}, {Clerk: "pay", Step: "1", Ran: at},
		{Clerk: "pay", Step: "1", At: at, Corrected: true}, {Clerk: "pay", Step: "1", Ran: at, Corrected: true},
	} {
		if err := o.Record(ok, bad); err != ErrOutcome {
			t.Fatalf("%+v: err %v, want ErrOutcome", bad, err)
		}
	}
	if r := o.st.Clerks["pay"]; r != nil && len(r.Steps) != 0 {
		t.Fatalf("a refused call applied part of itself: %+v", r.Steps)
	}
}

// D-309 invariant 3 (Security on #4945): arrival order cannot drop a
// correction. Corrections first, carrying any Ran, then their effects 50
// days old, count the same silent failures as effects first.
func TestCorrectionEitherOrder(t *testing.T) {
	ran := t0.Add(-50 * 24 * time.Hour)
	for _, first := range []string{"correction", "effect"} {
		for _, cran := range []time.Time{ran, t0.Add(-500 * 24 * time.Hour), t0.Add(500 * 24 * time.Hour)} {
			o := newOpt(t, &memStore{}, nil)
			var effects, corrections []Outcome
			for i := range 300 {
				effects = append(effects, Outcome{Clerk: "pay", Step: strconv.Itoa(i), Ran: ran.Add(time.Duration(i) * time.Minute), At: ran})
			}
			for i := range 10 {
				corrections = append(corrections, Outcome{Clerk: "pay", Step: strconv.Itoa(i), Ran: cran, At: ran.Add(24 * time.Hour), Corrected: true})
			}
			if first == "correction" {
				recordAll(t, o, corrections...)
				recordAll(t, o, effects...)
			} else {
				recordAll(t, o, effects...)
				recordAll(t, o, corrections...)
			}
			recordAll(t, o, Outcome{Clerk: "other", Step: "tick", Ran: t0, At: t0})
			if m := o.Measure("pay"); m.Effects != 300 || m.Silent != 10 || m.Ready {
				t.Fatalf("%s first, correction Ran %v: %+v", first, cran, m)
			}
		}
	}
}

// D-309 (Potency on #4945, 602e06ee): KEY-5's literal edges. With the
// clock at t0, an effect 90 days old counts and one 91 days old is gone;
// one 8 days old has settled and one 7 days old has not. A future Ran
// does not move the clock.
func TestLiteralEdges(t *testing.T) {
	if Window != 90*24*time.Hour || Settle != 7*24*time.Hour {
		t.Fatalf("Window %v, Settle %v: KEY-5 names 90 and 7 days", Window, Settle)
	}
	day := 24 * time.Hour
	for _, c := range []struct {
		age  time.Duration
		want int
	}{{90 * day, 1}, {91 * day, 0}, {8 * day, 1}, {7 * day, 0}} {
		o := newOpt(t, &memStore{}, nil)
		recordAll(t, o, Outcome{Clerk: "pay", Step: "e", Ran: t0.Add(-c.age), At: t0})
		if m := o.Measure("pay"); m.Effects != c.want {
			t.Errorf("effect %v old: %d counted, want %d", c.age, m.Effects, c.want)
		}
	}
	o := newOpt(t, &memStore{}, nil)
	recordAll(t, o, Outcome{Clerk: "pay", Step: "f", Ran: t0.Add(400 * day), At: t0})
	if !o.st.Now.Equal(t0) {
		t.Fatalf("a future Ran moved the clock to %v", o.st.Now)
	}
}

// D-309 (Potency release on #4945, 602e06ee): an offer-time tick prunes,
// so Measure right after Due never reads a day outside the window.
func TestDueTickPrunes(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
	recordAll(t, o, Outcome{Clerk: "pay", Step: "e", Ran: t0.Add(-80 * 24 * time.Hour), At: t0})
	if _, err := o.Due(t0.Add(11 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if m := o.Measure("pay"); m.Effects != 0 || len(o.st.Clerks["pay"].Days) != 0 {
		t.Fatalf("a day outside the window survived the offer's tick: %+v", m)
	}
}

// D-309 (Potency on #4945, c26842dd): the record keeps only Window. An
// effect older than Window leaves no entry, and as the clock passes Window
// every day and step of an older record is dropped; an effect on the
// window's first day still counts.
func TestRecordKeepsOnlyTheWindow(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
	clean(t, o, "pay", t0.Add(-80*24*time.Hour), 300)
	old := t0.Add(-200 * 24 * time.Hour)
	recordAll(t, o, Outcome{Clerk: "pay", Step: "old", Ran: old, At: t0.Add(-60 * 24 * time.Hour)})
	r := o.st.Clerks["pay"]
	if _, ok := r.Steps["old"]; ok || r.Days[old.UTC().Format(dayFmt)] != nil {
		t.Fatalf("an effect older than Window left an entry: %+v", r.Steps["old"])
	}
	steps, days := len(r.Steps), len(r.Days)
	if steps != 300 || days == 0 {
		t.Fatalf("steps %d, days %d", steps, days)
	}

	later := t0.Add(80 * 24 * time.Hour) // every clean effect is now older than Window
	edge := later.Add(-Window).UTC().Truncate(24 * time.Hour)
	recordAll(t, o, Outcome{Clerk: "pay", Step: "edge", Ran: edge, At: later})
	if len(r.Steps) != 1 || len(r.Days) != 1 {
		t.Fatalf("after Window: %d steps, %d days, want 1 and 1", len(r.Steps), len(r.Days))
	}
	if m := o.Measure("pay"); m.Effects != 1 {
		t.Fatalf("an effect on the window's first day did not count: %+v", m)
	}
}
