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
	"math"
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
	// Owner marks the owner's own work: set only by broker code for the
	// owner's machines, never for a loop's, a replay's or the clean
	// room's. Experiments cannot carry it. It makes accepted work count as
	// the owner's for BusyCause and RevokedForOwner (PE5, security P2).
	Owner bool
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
	// Above MaxPressure, or when the reading is NaN, foreground is admitted
	// as usual, accepted work only if preempting experiments covers all of
	// its memory, and experiments not at all.
	Pressure    func() float64
	MaxPressure float64

	mu       sync.Mutex
	running  map[string]Request
	order    []string        // admission order, for newest-first preemption
	yielding map[string]bool // experiments being preempted right now
	// revokes records, per victim, whether it was preempted for the
	// owner's work without pressure (RevokedForOwner).
	revokes map[string]bool
}

// New returns a controller for cfg, which needs capacity > headroom >= 0.
func New(cfg Config, pre Preempter) (*Controller, error) {
	if cfg.HeadroomMB < 0 || cfg.CapacityMB <= cfg.HeadroomMB {
		return nil, fmt.Errorf("admission: need capacity > headroom >= 0, got %+v", cfg)
	}
	return &Controller{cfg: cfg, pre: pre, running: map[string]Request{}, yielding: map[string]bool{}}, nil
}

// Admit admits r or refuses it, preempting experiments when r outranks them
// and that makes enough room. Preemption runs without the controller lock,
// so STATUS and other admissions never wait behind a VM freeze; r's memory
// is reserved meanwhile.
func (c *Controller) Admit(r Request) (Decision, error) {
	if r.ID == "" || !r.Class.valid() || r.MemMB <= 0 || r.Owner && r.Class == Experiment {
		return Decision{}, fmt.Errorf("%w: %+v", ErrInvalid, r)
	}
	if r.MemMB > c.cfg.CapacityMB-c.cfg.HeadroomMB {
		return Decision{}, ErrNoRoom
	}
	pressured := false
	if r.Class != Foreground && c.Pressure != nil {
		p := c.Pressure()
		// NaN or a negative reading (-Inf included) is not a real PSI value,
		// so it counts as over the limit rather than as no pressure.
		pressured = math.IsNaN(p) || p < 0 || p > c.MaxPressure
		if pressured && r.Class == Experiment {
			return Decision{}, ErrPressure
		}
	}

	c.mu.Lock()
	if _, dup := c.running[r.ID]; dup {
		c.mu.Unlock()
		return Decision{}, fmt.Errorf("%w: %s already admitted", ErrInvalid, r.ID)
	}
	need := r.MemMB - c.freeLocked()
	if pressured {
		// Under pressure, accepted work may only replace experiments.
		need = r.MemMB
	}
	var victims []string
	for i := len(c.order) - 1; i >= 0 && need > 0; i-- {
		v := c.running[c.order[i]]
		if v.Class == Experiment && r.Class.Outranks(Experiment) && !c.yielding[v.ID] {
			victims = append(victims, v.ID)
			need -= v.MemMB
		}
	}
	if need > 0 {
		c.mu.Unlock()
		if pressured {
			return Decision{}, ErrPressure
		}
		return Decision{}, ErrNoRoom
	}
	c.running[r.ID] = r
	c.order = append(c.order, r.ID)
	forOwner := !pressured && (r.Class == Foreground || r.Class == Accepted && r.Owner)
	if len(c.revokes)+len(victims) > maxRevokes {
		c.revokes = nil // unread records go; a missing one is not the owner's
	}
	if c.revokes == nil {
		c.revokes = map[string]bool{}
	}
	for _, id := range victims {
		c.yielding[id] = true
		c.revokes[id] = forOwner
	}
	c.mu.Unlock()

	var done []string
	var firstErr error
	for _, id := range victims {
		if err := c.pre.Preempt(id); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("admission: preempting %s: %w", id, err)
			}
			continue
		}
		done = append(done, id)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range victims {
		delete(c.yielding, id)
	}
	for _, id := range done {
		c.removeLocked(id)
	}
	// Admit if what did yield made enough room; otherwise give the
	// reservation back. A preempted experiment stays preempted either way.
	if c.freeLocked() < 0 {
		c.removeLocked(r.ID)
		if firstErr == nil {
			firstErr = ErrNoRoom
		}
		return Decision{Preempted: done}, firstErr
	}
	return Decision{Preempted: done}, nil
}

// maxRevokes bounds the revoke records kept unread.
const maxRevokes = 256

// RevokedForOwner reports, once, whether admission preempted machine id
// for the owner's work without memory pressure: foreground, or accepted
// work marked Owner. It is recorded when the victim is picked, under the
// same lock, so it is the reason for that preemption and no later one.
// False when there is no record (PE5, security P3).
func (c *Controller) RevokedForOwner(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.revokes[id]
	delete(c.revokes, id)
	return v
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

// Busy reports that the box has no spare compute for loop work (LOOP-1):
// accepted work is running, or memory pressure is over MaxPressure (or not
// a real reading). Foreground machines alone do not count: the owner's
// agent machine runs all the time, and when foreground needs memory,
// Admit preempts experiments for it.
func (c *Controller) Busy() bool {
	busy, _, _ := c.BusyCause()
	return busy
}

// BusyCause is Busy, whether the busy work is the owner's (accepted work
// marked Owner), and whether memory pressure is over its limit (an
// unreadable reading counts as over), read together so the loop
// scheduler's cause for a preemption is consistent (PE5).
func (c *Controller) BusyCause() (busy, owner, pressure bool) {
	if c.Pressure != nil {
		if p := c.Pressure(); math.IsNaN(p) || p < 0 || p > c.MaxPressure {
			pressure = true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.running {
		if r.Class == Accepted {
			busy = true
			owner = owner || r.Owner
		}
	}
	return busy || pressure, owner, pressure
}

// Summary is STATUS's one line about machines, in fixed wording.
func (c *Controller) Summary() string {
	s := c.Snapshot()
	var n [3]int
	for _, r := range s.Running {
		n[r.Class]++
	}
	free := s.FreeMB
	if free < 0 {
		free = 0 // never text a negative figure (or a minus sign) to the owner
	}
	return fmt.Sprintf("Machines: %d foreground, %d work, %d experiments; %d MB free.", n[0], n[1], n[2], free)
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
