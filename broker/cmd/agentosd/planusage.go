package main

import (
	"errors"
	"math"
	"time"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/provagent"
)

// wirePlanUsage gives the provider runner RES-5's inputs (#1856): the
// vault process's readings of each provider's plan, aggregated across its
// worker routes, and the owner's reserve.
func wirePlanUsage(r *provagent.Runner, rc *modelroute.RouteControl) {
	r.Usage = planUsage{rc}.Usage
	r.Reserve = ownerReserve
}

// ownerReserve is the share of each pool kept for the owner's own use. RES-5
// and ONB-9 default it to 0% ("Kept for your own use: 0%"); the owner's
// per-pool setting (an OP-5 budget) is not built, and the row that builds it
// wires it here (provagent P15).
func ownerReserve(provider, pool string) float64 { return 0 }

// planUsage adapts the route control's usage verb to provagent's Usage, so
// provagent links no network client (ARC-2).
type planUsage struct{ rc *modelroute.RouteControl }

func (p planUsage) Usage(provider string) (provagent.Usage, error) {
	if p.rc == nil {
		return provagent.Usage{}, errors.New("no plan route control")
	}
	u, err := p.rc.Usage(provider)
	if err != nil {
		return provagent.Usage{}, err
	}
	out := provagent.Usage{LoginRefused: u.LoginRefused}
	for _, q := range u.Pools {
		left := math.Min(1, math.Max(0, 1-q.UsedPercent/100))
		if q.Exhausted {
			left = 0
		}
		var reset time.Time
		if q.ResetAt > 0 {
			reset = time.Unix(q.ResetAt, 0)
		}
		out.Readings = append(out.Readings, provagent.Reading{Pool: q.Pool, Left: left, At: q.At, ResetAt: reset, Exhausted: q.Exhausted})
	}
	return out, nil
}
