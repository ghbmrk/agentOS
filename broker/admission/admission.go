// Package admission decides which agent machines may run (SPEC RES-1, RES-2).
//
// Classes are ordered foreground > accepted work > experiments. Admission
// refuses anything that would leave less than the declared memory headroom,
// because a cgroup at its hard limit stalls in reclaim instead of failing
// (S3). A higher class may preempt experiments, and only experiments: the
// newest first, and only as many as the request needs. Preemption that cannot
// make room does not happen at all. Memory pressure (PSI) is an input that
// refuses everything but foreground.
//
// The controller is pure bookkeeping plus a Preempter callback; enforcing
// the budgets with cgroups is the VM lifecycle package's job (P1-4).
package admission

import (
	"errors"
	"fmt"
	"sync"
)

// Class is an admission class (RES-1). Lower values outrank higher ones.
type Class int

const (
	Foreground Class = iota // calls, STOP/STATUS, owner chat
	Accepted                // accepted work
	Experiment              // spare-capacity work (LOOP-1)
)

// Outranks reports whether c has priority over o.
func (c Class) Outranks(o Class) bool { return c < o }

func (c Class) valid() bool { return c >= Foreground && c <= Experiment }

// Request asks to run one machine with a declared memory budget.
type Request struct {
	ID    string
	Class Class
	MemMB int64
}

// Decision is a successful admission and what was preempted for it.
type Decision struct {
	Preempted []string
}

// Preempter freezes or kills a running experiment. It returns nil only once
// the machine's memory is released.
type Preempter interface {
	Preempt(id string) error
}

// Config holds the declared budget (RES-2).
type Config struct {
	CapacityMB int64 // memory available to admitted machines
	HeadroomMB int64 // never admitted into
}

var (
	ErrInvalid  = errors.New("admission: invalid request")
	ErrNoRoom   = errors.New("admission: would cut into the declared headroom")
	ErrPressure = errors.New("admission: memory pressure too high")
)

// Controller is safe for concurrent use.
type Controller struct {
	cfg Config
	pre Preempter
	// Pressure, if set, returns current memory pressure (PSI some avg10, %).
	// Above MaxPressure only foreground is admitted.
	Pressure    func() float64
	MaxPressure float64

	mu      sync.Mutex
	running map[string]Request
	order   []string // admission order, for newest-first preemption
}

// New returns a controller for cfg.
func New(cfg Config, pre Preempter) *Controller {
	return &Controller{cfg: cfg, pre: pre, running: map[string]Request{}}
}

// Admit admits r or refuses it, preempting experiments when r outranks them
// and that makes enough room.
func (c *Controller) Admit(r Request) (Decision, error) {
	if r.ID == "" || !r.Class.valid() || r.MemMB <= 0 {
		return Decision{}, fmt.Errorf("%w: %+v", ErrInvalid, r)
	}
	if r.Class != Foreground && c.Pressure != nil && c.Pressure() > c.MaxPressure {
		return Decision{}, ErrPressure
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.running[r.ID]; dup {
		return Decision{}, fmt.Errorf("%w: %s already admitted", ErrInvalid, r.ID)
	}
	need := r.MemMB - c.freeLocked()
	var victims []string
	for i := len(c.order) - 1; i >= 0 && need > 0; i-- {
		v := c.running[c.order[i]]
		if v.Class == Experiment && r.Class.Outranks(Experiment) {
			victims = append(victims, v.ID)
			need -= v.MemMB
		}
	}
	if need > 0 {
		return Decision{}, ErrNoRoom
	}
	for _, id := range victims {
		if err := c.pre.Preempt(id); err != nil {
			return Decision{Preempted: victims}, fmt.Errorf("admission: preempting %s: %w", id, err)
		}
		c.removeLocked(id)
	}
	c.running[r.ID] = r
	c.order = append(c.order, r.ID)
	return Decision{Preempted: victims}, nil
}

// Release returns a machine's memory.
func (c *Controller) Release(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(id)
}

// Snapshot is the current admission state.
type Snapshot struct {
	Running map[string]Request
	FreeMB  int64
}

// Snapshot returns a copy of the current state.
func (c *Controller) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Snapshot{Running: map[string]Request{}, FreeMB: c.freeLocked()}
	for k, v := range c.running {
		s.Running[k] = v
	}
	return s
}

// Summary is STATUS's one line about machines, in fixed wording.
func (c *Controller) Summary() string {
	s := c.Snapshot()
	var n [3]int
	for _, r := range s.Running {
		n[r.Class]++
	}
	return fmt.Sprintf("Machines: %d foreground, %d work, %d experiments; %d MB free.", n[0], n[1], n[2], s.FreeMB)
}

func (c *Controller) freeLocked() int64 {
	used := int64(0)
	for _, r := range c.running {
		used += r.MemMB
	}
	return c.cfg.CapacityMB - c.cfg.HeadroomMB - used
}

func (c *Controller) removeLocked(id string) {
	if _, ok := c.running[id]; !ok {
		return
	}
	delete(c.running, id)
	for i, o := range c.order {
		if o == id {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}
