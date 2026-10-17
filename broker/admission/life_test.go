package admission

import (
	"errors"
	"reflect"
	"testing"
)

// REQ: RES-2

// lifePreempter records which life of each victim it was asked to preempt,
// and refuses a life that is not the current one, as vm.Manager does.
type lifePreempter struct {
	current map[string]string // ID -> its current life
	byID    []string
	byLife  []string
}

func (p *lifePreempter) Preempt(id string) error {
	p.byID = append(p.byID, id)
	return nil
}

func (p *lifePreempter) PreemptInstance(id, inst string) error {
	if p.current[id] != inst {
		return errors.New("not that life")
	}
	p.byLife = append(p.byLife, id+"@"+inst)
	return nil
}

// A victim admitted with an Instance is preempted by that life, so a
// successor given its ID after the pick cannot be hit (#2144).
func TestRES2VictimIsPreemptedByItsLife(t *testing.T) {
	p := &lifePreempter{current: map[string]string{"e": "life1"}}
	c, err := New(Config{CapacityMB: 1000}, p)
	must(t, err)
	_, err = c.Admit(Request{ID: "e", Class: Experiment, MemMB: 800, Instance: "life1"})
	must(t, err)
	d, err := c.Admit(Request{ID: "f", Class: Foreground, MemMB: 800})
	must(t, err)
	if !reflect.DeepEqual(d.Preempted, []string{"e"}) || !reflect.DeepEqual(p.byLife, []string{"e@life1"}) || p.byID != nil {
		t.Fatalf("preempted %v, by life %v, by ID %v", d.Preempted, p.byLife, p.byID)
	}
}

// When the picked life is gone and a successor holds the ID, the refusal
// leaves the successor counted and r is admitted only if there is room.
func TestRES2StaleLifeRefusalLeavesTheSuccessorCounted(t *testing.T) {
	p := &lifePreempter{current: map[string]string{"e": "life1"}}
	c, err := New(Config{CapacityMB: 1000}, p)
	must(t, err)
	_, err = c.Admit(Request{ID: "e", Class: Experiment, MemMB: 800, Instance: "life1"})
	must(t, err)
	c.pre = &hookLife{lifePreempter: p, during: func() {
		// The picked life is destroyed and a smaller successor admitted.
		c.Release("e")
		p.current["e"] = "life2"
		if _, err := c.Admit(Request{ID: "e", Class: Experiment, MemMB: 200, Instance: "life2"}); err != nil {
			t.Errorf("successor: %v", err)
		}
	}}
	d, err := c.Admit(Request{ID: "f", Class: Foreground, MemMB: 800})
	must(t, err)
	if len(d.Preempted) != 0 || len(p.byLife) != 0 || p.byID != nil {
		t.Fatalf("a successor was preempted: %v, by life %v, by ID %v", d.Preempted, p.byLife, p.byID)
	}
	if got := c.Snapshot().Running["e"]; got.Instance != "life2" {
		t.Fatalf("successor e not counted: %+v", c.Snapshot().Running)
	}
}

type hookLife struct {
	*lifePreempter
	during func()
}

func (h *hookLife) PreemptInstance(id, inst string) error {
	h.during()
	return h.lifePreempter.PreemptInstance(id, inst)
}

// A request without an Instance, or a Preempter that is not a
// LifePreempter, is preempted by ID as before.
func TestRES2PreemptByIDWithoutALife(t *testing.T) {
	p := &lifePreempter{}
	c, err := New(Config{CapacityMB: 1000}, p)
	must(t, err)
	_, err = c.Admit(Request{ID: "e", Class: Experiment, MemMB: 800})
	must(t, err)
	_, err = c.Admit(Request{ID: "f", Class: Foreground, MemMB: 800})
	must(t, err)
	if !reflect.DeepEqual(p.byID, []string{"e"}) || p.byLife != nil {
		t.Fatalf("by ID %v, by life %v", p.byID, p.byLife)
	}

	r := &recPreempter{}
	c2, err := New(Config{CapacityMB: 1000}, r)
	must(t, err)
	_, err = c2.Admit(Request{ID: "e", Class: Experiment, MemMB: 800, Instance: "life1"})
	must(t, err)
	_, err = c2.Admit(Request{ID: "f", Class: Foreground, MemMB: 800})
	must(t, err)
	if !reflect.DeepEqual(r.frozen, []string{"e"}) {
		t.Fatalf("frozen %v", r.frozen)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
