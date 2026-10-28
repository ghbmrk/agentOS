package vision

import (
	"sync"
	"time"
)

// Pacing (part b, VIS-track; brief question 3, RES-2, VIS-A26). Each
// camera has a declared frame rate and a floor rate. While admission has
// headroom, a camera's frames go to the service at its rate; once
// admission refuses headroom, at its floor rate, so detection goes on at
// the floor rather than stopping, and identification is not what the
// floor guarantees.

// Pace defaults.
const (
	// DefaultEvery is a camera's declared frame interval: 5 frames a
	// second.
	DefaultEvery = 200 * time.Millisecond
	// DefaultFloorEvery is a camera's floor interval: 1 frame a second.
	DefaultFloorEvery = time.Second
	// maxFloorEvery is the slowest floor a camera may declare, so
	// detection never stops in all but name.
	maxFloorEvery = 5 * time.Second
)

// Rate is one camera's declared frame interval and its floor interval.
type Rate struct {
	Every, Floor time.Duration
}

func (r Rate) valid() bool {
	return r.Every > 0 && r.Floor >= r.Every && r.Floor <= maxFloorEvery
}

// Pace decides which frames go to the service. The zero value sends every
// camera's frames at the default rate while Headroom is nil.
type Pace struct {
	// Rates are the cameras' declared rates; a camera without one, or
	// with one out of bounds, has the default.
	Rates map[string]Rate
	// Headroom reports whether admission has headroom now (RES-2:
	// agentosd's admission controller not busy). Nil always has.
	Headroom func() bool

	mu   sync.Mutex
	last map[string]time.Time
}

// Take reports whether camera's frame taken at at goes to the service.
func (p *Pace) Take(camera string, at time.Time) bool {
	if !ValidEnrolledID(camera) {
		return false
	}
	r, ok := p.Rates[camera]
	if !ok || !r.valid() {
		r = Rate{Every: DefaultEvery, Floor: DefaultFloorEvery}
	}
	every := r.Every
	if p.Headroom != nil && !p.Headroom() {
		every = r.Floor
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last == nil {
		p.last = map[string]time.Time{}
	}
	if last, ok := p.last[camera]; ok && at.Sub(last) < every && !at.Before(last) {
		return false
	}
	p.last[camera] = at
	return true
}
