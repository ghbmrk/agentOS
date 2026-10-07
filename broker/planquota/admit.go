// Package planquota admits provider-agent runs against usage pools (RES-5).
//
// A plan has one or more pools the provider meters. Admission refuses a
// run that would take any pool it draws on past the owner's reserve.
// Concurrent workers per pool are capped (default 2). Spare work also
// respects a foreground forecast until reset.
package planquota

import (
	"fmt"
	"sync"
	"time"
)

// DefaultConcurrency is the per-pool concurrent provider-agent worker cap.
const DefaultConcurrency = 2

// Pool is one usage pool on a plan (RES-5).
type Pool struct {
	ID       string  // provider's name, e.g. "five_hour"
	Used     float64 // 0..1 utilization
	Reserve  float64 // 0..1 owner share; default 0
	Reset    time.Time
	Running  int // concurrent workers currently on this pool
	MaxConc  int // 0 means DefaultConcurrency
	Forecast float64 // spare floor: expected foreground use until Reset (0..1)
}

// Headroom is how much of the pool sits above the effective floor
// (reserve for foreground; max(reserve, forecast) for spare).
func (p Pool) Headroom(spare bool) float64 {
	floor := p.Reserve
	if spare && p.Forecast > floor {
		floor = p.Forecast
	}
	h := 1 - p.Used - floor
	if h < 0 {
		return 0
	}
	return h
}

// Cap is the concurrency limit.
func (p Pool) Cap() int {
	if p.MaxConc <= 0 {
		return DefaultConcurrency
	}
	return p.MaxConc
}

// Refusal is why a run was not admitted.
type Refusal struct {
	Pool   string
	Reason string // closed set: "at_reserve", "concurrency_full", "unknown_pool"
}

func (r Refusal) Error() string {
	return fmt.Sprintf("planquota: pool %s: %s", r.Pool, r.Reason)
}

// Gate tracks pools and admits runs.
type Gate struct {
	mu    sync.Mutex
	pools map[string]Pool
	now   func() time.Time
}

// New returns an empty gate.
func New() *Gate {
	return &Gate{pools: map[string]Pool{}, now: time.Now}
}

// Set replaces a pool's state (from provider headers or CLI events).
func (g *Gate) Set(p Pool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pools == nil {
		g.pools = map[string]Pool{}
	}
	g.pools[p.ID] = p
}

// Get returns a pool's current state.
func (g *Gate) Get(id string) (Pool, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.pools[id]
	return p, ok
}

// Admit starts a run that draws on pools. spare is LOOP-1 spare-class work.
// On success the concurrency counters are raised; Release must be called.
func (g *Gate) Admit(pools []string, spare bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, id := range pools {
		p, ok := g.pools[id]
		if !ok {
			return Refusal{Pool: id, Reason: "unknown_pool"}
		}
		if p.Headroom(spare) <= 0 {
			return Refusal{Pool: id, Reason: "at_reserve"}
		}
		if p.Running >= p.Cap() {
			return Refusal{Pool: id, Reason: "concurrency_full"}
		}
	}
	for _, id := range pools {
		p := g.pools[id]
		p.Running++
		g.pools[id] = p
	}
	return nil
}

// Release drops concurrency after a run ends (success, refuse mid-run, or cut-off).
func (g *Gate) Release(pools []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, id := range pools {
		p, ok := g.pools[id]
		if !ok || p.Running == 0 {
			continue
		}
		p.Running--
		g.pools[id] = p
	}
}

// Cooldown is the soonest reset among pools that refused, for CAP-9 failover.
func (g *Gate) Cooldown(pools []string) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	var soon time.Time
	for _, id := range pools {
		p, ok := g.pools[id]
		if !ok || p.Reset.IsZero() {
			continue
		}
		if soon.IsZero() || p.Reset.Before(soon) {
			soon = p.Reset
		}
	}
	return soon
}
