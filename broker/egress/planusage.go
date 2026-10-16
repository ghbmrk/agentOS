package egress

import (
	"sort"
	"sync"
	"time"
)

// SignalKind names a plan signal read on the broker's own connection.
type SignalKind string

// SignalLoginRefused is a refresh the provider refused with one of the
// route's RefusedLogin codes: the stored login no longer works (CRED-5).
const SignalLoginRefused SignalKind = "login-refused"

// PlanSignal is one signal read from the provider's response on the
// broker's own connection, never from anything the worker wrote.
type PlanSignal struct {
	At       time.Time
	Provider string
	Worker   string
	Kind     SignalKind
}

// UsageSnapshot is one provider's plan usage as the broker last read it:
// the newest reading of each pool, whichever worker's call carried it, and
// the last refused login (zero when none).
type UsageSnapshot struct {
	Pools        []QuotaReading
	LoginRefused time.Time
}

// PlanUsage aggregates every worker route's readings and signals per
// provider (RES-5): a pool is the plan's, not a worker's. Its Quota and
// Signal are a WorkerRouteConfig's; the zero value is ready.
type PlanUsage struct {
	mu      sync.Mutex
	pools   map[string]map[string]QuotaReading // provider, pool
	refused map[string]time.Time
}

// planPool is readQuota's pool for a used-up signal that came with no pool
// headers.
const planPool = "plan"

// Quota keeps q if it is the pool's newest reading. A pool reading
// supersedes an older "plan" signal: the provider has since said how much
// is left.
func (u *PlanUsage) Quota(q QuotaReading) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.pools == nil {
		u.pools = map[string]map[string]QuotaReading{}
	}
	p := u.pools[q.Provider]
	if p == nil {
		p = map[string]QuotaReading{}
		u.pools[q.Provider] = p
	}
	if old, ok := p[q.Pool]; ok && old.At.After(q.At) {
		return
	}
	p[q.Pool] = q
	if plan, ok := p[planPool]; ok && q.Pool != planPool && plan.At.Before(q.At) {
		delete(p, planPool)
	}
}

// Signal records s.
func (u *PlanUsage) Signal(s PlanSignal) {
	if s.Kind != SignalLoginRefused {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.refused == nil {
		u.refused = map[string]time.Time{}
	}
	if s.At.After(u.refused[s.Provider]) {
		u.refused[s.Provider] = s.At
	}
}

// Snapshot returns provider's usage, pools sorted by name.
func (u *PlanUsage) Snapshot(provider string) UsageSnapshot {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := UsageSnapshot{LoginRefused: u.refused[provider]}
	for _, q := range u.pools[provider] {
		s.Pools = append(s.Pools, q)
	}
	sort.Slice(s.Pools, func(i, j int) bool { return s.Pools[i].Pool < s.Pools[j].Pool })
	return s
}
