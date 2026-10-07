// Package planquota admits provider-agent runs against usage pools (RES-5).
package planquota

import (
	"fmt"
	"sync"
	"time"
)

const DefaultConcurrency = 2

type Pool struct {
	ID       string
	Used     float64
	Reserve  float64
	Reset    time.Time
	Running  int
	MaxConc  int
	Forecast float64
}

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

func (p Pool) Cap() int {
	if p.MaxConc <= 0 {
		return DefaultConcurrency
	}
	return p.MaxConc
}

type Refusal struct {
	Pool   string
	Reason string
}

func (r Refusal) Error() string {
	return fmt.Sprintf("planquota: pool %s: %s", r.Pool, r.Reason)
}

type Gate struct {
	mu    sync.Mutex
	pools map[string]Pool
	now   func() time.Time
}

func New() *Gate { return &Gate{pools: map[string]Pool{}, now: time.Now} }

func (g *Gate) Set(p Pool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pools == nil {
		g.pools = map[string]Pool{}
	}
	g.pools[p.ID] = p
}

func (g *Gate) Get(id string) (Pool, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.pools[id]
	return p, ok
}

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
