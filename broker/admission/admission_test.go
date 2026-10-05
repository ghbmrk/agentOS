package admission

import (
	"errors"
	"math"
	"reflect"
	"testing"
)

// REQ: RES-1, RES-2

type recPreempter struct {
	frozen []string
	fail   map[string]bool
	during func()
}

func (p *recPreempter) Preempt(id string) error {
	if p.during != nil {
		p.during()
	}
	if p.fail[id] {
		return errors.New("freeze failed")
	}
	p.frozen = append(p.frozen, id)
	return nil
}

func newCtl(p *recPreempter) *Controller {
	// Floor-like numbers in MB: 3900 pool, 600 headroom.
	c, err := New(Config{CapacityMB: 4500, HeadroomMB: 600}, p)
	if err != nil {
		panic(err)
	}
	return c
}

func TestClassesAreOrdered(t *testing.T) {
	if !(Foreground.Outranks(Accepted) && Accepted.Outranks(Experiment)) || Experiment.Outranks(Foreground) {
		t.Fatal("RES-1 order is foreground > accepted work > experiments")
	}
}

func TestAdmitWithinBudgetAndRefuseIntoHeadroom(t *testing.T) {
	c := newCtl(&recPreempter{})
	if _, err := c.Admit(Request{ID: "a", Class: Accepted, MemMB: 2000}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Admit(Request{ID: "b", Class: Accepted, MemMB: 1900}); err != nil {
		t.Fatal(err)
	}
	// 3900 used of 4500; 100 more would leave 500 < 600 headroom.
	if _, err := c.Admit(Request{ID: "c", Class: Accepted, MemMB: 100}); !errors.Is(err, ErrNoRoom) {
		t.Fatalf("admission into headroom: %v", err)
	}
	c.Release("a")
	if _, err := c.Admit(Request{ID: "c", Class: Accepted, MemMB: 100}); err != nil {
		t.Fatal(err)
	}
}

func TestForegroundPreemptsExperimentsOnly(t *testing.T) {
	p := &recPreempter{}
	c := newCtl(p)
	mustAdmit(t, c, Request{ID: "work", Class: Accepted, MemMB: 2000})
	mustAdmit(t, c, Request{ID: "exp1", Class: Experiment, MemMB: 900})
	mustAdmit(t, c, Request{ID: "exp2", Class: Experiment, MemMB: 1000})
	d, err := c.Admit(Request{ID: "call", Class: Foreground, MemMB: 1500})
	if err != nil {
		t.Fatal(err)
	}
	// Newest experiment first, then the next, until the call fits.
	if !reflect.DeepEqual(d.Preempted, []string{"exp2", "exp1"}) || !reflect.DeepEqual(p.frozen, d.Preempted) {
		t.Fatalf("preempted %v, frozen %v", d.Preempted, p.frozen)
	}
	if _, ok := c.Snapshot().Running["work"]; !ok {
		t.Fatal("accepted work must not be preempted")
	}
}

func TestPreemptOnlyWhatIsNeeded(t *testing.T) {
	p := &recPreempter{}
	c := newCtl(p)
	mustAdmit(t, c, Request{ID: "exp1", Class: Experiment, MemMB: 1500})
	mustAdmit(t, c, Request{ID: "exp2", Class: Experiment, MemMB: 1500})
	d := mustAdmit(t, c, Request{ID: "call", Class: Foreground, MemMB: 1000})
	if !reflect.DeepEqual(d.Preempted, []string{"exp2"}) {
		t.Fatalf("preempted %v", d.Preempted)
	}
}

func TestRefuseWithoutPreemptingWhenPreemptionCannotMakeRoom(t *testing.T) {
	p := &recPreempter{}
	c := newCtl(p)
	mustAdmit(t, c, Request{ID: "work", Class: Accepted, MemMB: 3000})
	mustAdmit(t, c, Request{ID: "exp", Class: Experiment, MemMB: 500})
	if _, err := c.Admit(Request{ID: "call", Class: Foreground, MemMB: 1500}); !errors.Is(err, ErrNoRoom) {
		t.Fatalf("got %v", err)
	}
	if len(p.frozen) != 0 {
		t.Fatalf("froze %v for an admission that was refused anyway", p.frozen)
	}
}

func TestExperimentsNeverPreemptAnything(t *testing.T) {
	p := &recPreempter{}
	c := newCtl(p)
	mustAdmit(t, c, Request{ID: "exp1", Class: Experiment, MemMB: 3900})
	if _, err := c.Admit(Request{ID: "exp2", Class: Experiment, MemMB: 100}); !errors.Is(err, ErrNoRoom) {
		t.Fatalf("got %v", err)
	}
	if len(p.frozen) != 0 {
		t.Fatal("an experiment preempted another")
	}
}

func TestFailedPreemptionRefusesAndKeepsAccountingHonest(t *testing.T) {
	p := &recPreempter{fail: map[string]bool{"exp2": true}}
	c := newCtl(p)
	mustAdmit(t, c, Request{ID: "exp1", Class: Experiment, MemMB: 1900})
	mustAdmit(t, c, Request{ID: "exp2", Class: Experiment, MemMB: 2000})
	if _, err := c.Admit(Request{ID: "call", Class: Foreground, MemMB: 1500}); err == nil {
		t.Fatal("admitted although the experiment did not yield")
	}
	if _, ok := c.Snapshot().Running["call"]; ok {
		t.Fatal("refused request still holds its reservation")
	}
	if _, ok := c.Snapshot().Running["exp2"]; !ok {
		t.Fatal("an experiment that failed to freeze still holds its memory")
	}
}

func TestPressureRefusesNonForeground(t *testing.T) {
	c := newCtl(&recPreempter{})
	c.Pressure = func() float64 { return 25 }
	c.MaxPressure = 10
	if _, err := c.Admit(Request{ID: "e", Class: Experiment, MemMB: 10}); !errors.Is(err, ErrPressure) {
		t.Fatalf("got %v", err)
	}
	if _, err := c.Admit(Request{ID: "w", Class: Accepted, MemMB: 10}); !errors.Is(err, ErrPressure) {
		t.Fatalf("got %v", err)
	}
	if _, err := c.Admit(Request{ID: "call", Class: Foreground, MemMB: 10}); err != nil {
		t.Fatalf("foreground under pressure: %v", err)
	}
}

func TestDuplicateAndInvalidRequests(t *testing.T) {
	c := newCtl(&recPreempter{})
	mustAdmit(t, c, Request{ID: "a", Class: Accepted, MemMB: 10})
	if _, err := c.Admit(Request{ID: "a", Class: Accepted, MemMB: 10}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate: %v", err)
	}
	for _, r := range []Request{{ID: "", Class: Accepted, MemMB: 1}, {ID: "x", Class: Class(9), MemMB: 1}, {ID: "y", Class: Accepted, MemMB: 0}} {
		if _, err := c.Admit(r); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v", r, err)
		}
	}
}

func TestSummaryLine(t *testing.T) {
	c := newCtl(&recPreempter{})
	mustAdmit(t, c, Request{ID: "a", Class: Accepted, MemMB: 10})
	mustAdmit(t, c, Request{ID: "b", Class: Experiment, MemMB: 10})
	if got, want := c.Summary(), "Machines: 0 foreground, 1 work, 1 experiments; 3880 MB free."; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func mustAdmit(t *testing.T, c *Controller, r Request) Decision {
	t.Helper()
	d, err := c.Admit(r)
	if err != nil {
		t.Fatalf("admit %s: %v", r.ID, err)
	}
	return d
}

func TestAcceptedWorkAlsoOutranksExperiments(t *testing.T) {
	p := &recPreempter{}
	c := newCtl(p)
	mustAdmit(t, c, Request{ID: "exp", Class: Experiment, MemMB: 3900})
	d := mustAdmit(t, c, Request{ID: "task", Class: Accepted, MemMB: 1000})
	if !reflect.DeepEqual(d.Preempted, []string{"exp"}) {
		t.Fatalf("preempted %v", d.Preempted)
	}
}

func TestConfigMustLeaveRoomAboveHeadroom(t *testing.T) {
	for _, cfg := range []Config{{CapacityMB: 1000, HeadroomMB: -500}, {CapacityMB: 600, HeadroomMB: 600}, {CapacityMB: 0, HeadroomMB: 0}} {
		if _, err := New(cfg, &recPreempter{}); err == nil {
			t.Errorf("accepted %+v", cfg)
		}
	}
}

func TestHugeRequestIsRefusedWithoutOverflow(t *testing.T) {
	c := newCtl(&recPreempter{})
	if _, err := c.Admit(Request{ID: "x", Class: Foreground, MemMB: math.MaxInt64}); !errors.Is(err, ErrNoRoom) {
		t.Fatalf("got %v", err)
	}
	if _, err := c.Admit(Request{ID: "y", Class: Foreground, MemMB: 3901}); !errors.Is(err, ErrNoRoom) {
		t.Fatalf("larger than capacity minus headroom: %v", err)
	}
}

func TestNaNPressureCountsAsOverTheLimit(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(-1), -1, math.Inf(1)} {
		c := newCtl(&recPreempter{})
		c.Pressure = func() float64 { return v }
		c.MaxPressure = 10
		if _, err := c.Admit(Request{ID: "w", Class: Accepted, MemMB: 10}); !errors.Is(err, ErrPressure) {
			t.Fatalf("pressure %v: got %v", v, err)
		}
	}
}

func TestSummaryNeverShowsNegativeFreeMemory(t *testing.T) {
	c := newCtl(&recPreempter{})
	c.running["big"] = Request{ID: "big", Class: Accepted, MemMB: 5000}
	if got, want := c.Summary(), "Machines: 0 foreground, 1 work, 0 experiments; 0 MB free."; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestUnderPressureAcceptedWorkMayReplaceExperiments(t *testing.T) {
	p := &recPreempter{}
	c := newCtl(p)
	mustAdmit(t, c, Request{ID: "exp", Class: Experiment, MemMB: 500})
	c.Pressure = func() float64 { return 25 }
	c.MaxPressure = 10
	d := mustAdmit(t, c, Request{ID: "task", Class: Accepted, MemMB: 400})
	if !reflect.DeepEqual(d.Preempted, []string{"exp"}) {
		t.Fatalf("preempted %v", d.Preempted)
	}
	if _, err := c.Admit(Request{ID: "task2", Class: Accepted, MemMB: 400}); !errors.Is(err, ErrPressure) {
		t.Fatalf("no experiments left to replace: %v", err)
	}
}

func TestPartialPreemptionAdmitsWhenEnoughWasFreed(t *testing.T) {
	p := &recPreempter{fail: map[string]bool{"exp3": true}}
	c := newCtl(p)
	mustAdmit(t, c, Request{ID: "exp1", Class: Experiment, MemMB: 2000})
	mustAdmit(t, c, Request{ID: "exp2", Class: Experiment, MemMB: 1000})
	mustAdmit(t, c, Request{ID: "exp3", Class: Experiment, MemMB: 900})
	// Needs exp3 and exp2 (newest first); exp3 fails, but exp2 alone frees 1000.
	d, err := c.Admit(Request{ID: "call", Class: Foreground, MemMB: 1000})
	if err != nil {
		t.Fatalf("enough room was freed: %v", err)
	}
	if !reflect.DeepEqual(d.Preempted, []string{"exp2"}) {
		t.Fatalf("preempted %v", d.Preempted)
	}
}

func TestPreemptionRunsWithoutTheLock(t *testing.T) {
	p := &recPreempter{}
	c := newCtl(p)
	var summary string
	p.during = func() { summary = c.Summary() } // deadlocks if Preempt runs under the lock
	mustAdmit(t, c, Request{ID: "exp", Class: Experiment, MemMB: 3900})
	mustAdmit(t, c, Request{ID: "call", Class: Foreground, MemMB: 100})
	if summary == "" {
		t.Fatal("preempter not called")
	}
}

// REQ: LOOP-1
// Busy is the loop scheduler's "spare" signal: accepted work running, or
// memory pressure over the limit, needs the box; the owner's always-on
// foreground agent alone does not (admission already preempts experiments
// when foreground needs memory).
func TestBusyIsAcceptedWorkOrPressure(t *testing.T) {
	p := 0.0
	c, err := New(Config{CapacityMB: 4000, HeadroomMB: 500}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Pressure, c.MaxPressure = func() float64 { return p }, 10
	if c.Busy() {
		t.Fatal("idle box is busy")
	}
	if _, err := c.Admit(Request{ID: "agent", Class: Foreground, MemMB: 1000}); err != nil {
		t.Fatal(err)
	}
	if c.Busy() {
		t.Fatal("the foreground agent alone made the box busy")
	}
	if _, err := c.Admit(Request{ID: "job", Class: Accepted, MemMB: 500}); err != nil {
		t.Fatal(err)
	}
	if !c.Busy() {
		t.Fatal("accepted work running, not busy")
	}
	c.Release("job")
	if c.Busy() {
		t.Fatal("still busy after the work ended")
	}
	for _, v := range []float64{11, math.NaN(), -1} {
		p = v
		if !c.Busy() {
			t.Fatalf("pressure %v, not busy", v)
		}
	}
}

// PE5: BusyCause reads Busy and whether pressure is over its limit in one
// call, so the scheduler's cause for a preemption is consistent; an
// unreadable reading is pressure, as for Busy.
func TestBusyCauseSaysWhetherPressureHolds(t *testing.T) {
	p := 0.0
	c, err := New(Config{CapacityMB: 4000, HeadroomMB: 500}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Pressure, c.MaxPressure = func() float64 { return p }, 10
	if b, pr := c.BusyCause(); b || pr {
		t.Fatalf("idle: %v %v", b, pr)
	}
	if _, err := c.Admit(Request{ID: "job", Class: Accepted, MemMB: 500}); err != nil {
		t.Fatal(err)
	}
	if b, pr := c.BusyCause(); !b || pr {
		t.Fatalf("accepted work: %v %v", b, pr)
	}
	for _, v := range []float64{11, math.NaN(), -1} {
		p = v
		if b, pr := c.BusyCause(); !b || !pr {
			t.Fatalf("pressure %v: %v %v", v, b, pr)
		}
	}
}
