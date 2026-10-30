package main

import (
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/clerk/homekit"
)

// limiter is DEV-8's limit on the thermostats' values (design point 8): per
// device and characteristic, Burst values per Window go out and the rest
// are counted into one coalesced event when the window ends. It restates
// devhost's rule, which is unexported inside devhost.Host, as the camera
// clerk does (CAM-clerk-5); its config is a devhost.Limit.
//
// Until the kernel's device-report entry exists (DEVSLOT b3, #3474; b2c
// wires it), every value that passes is counted and dropped, never logged
// with its value (HK-host-5).
type limiter struct {
	lim devhost.Limit
	now func() time.Time

	mu     sync.Mutex
	win    map[wkey]*window
	order  []wkey
	counts map[string]*counts
}

type wkey struct{ device, char string }

type window struct {
	open    bool
	start   time.Time
	n       int
	dropped int
}

// counts is one device's tally: values that passed the limit, values the
// limit held back, and the coalesced events that stood for them.
type counts struct{ sent, limited, coalesced int }

func newLimiter(lim devhost.Limit, now func() time.Time) *limiter {
	return &limiter{lim: lim, now: now, win: map[wkey]*window{}, counts: map[string]*counts{}}
}

func (l *limiter) tally(device string) *counts {
	c := l.counts[device]
	if c == nil {
		c = &counts{}
		l.counts[device] = c
	}
	return c
}

// emit is the clerk's Emit hook.
func (l *limiter) emit(e homekit.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.flush(now)
	k := wkey{e.Device, e.Characteristic}
	w := l.win[k]
	if w == nil {
		w = &window{}
		l.win[k] = w
		l.order = append(l.order, k)
	}
	if !w.open {
		w.open, w.start, w.n = true, now, 0
	}
	if w.n < l.lim.Burst {
		w.n++
		l.tally(e.Device).sent++
		return nil
	}
	w.dropped++
	l.tally(e.Device).limited++
	return nil
}

// Flush ends the windows past their Window, each with its coalesced event.
// The host calls it on a timer, so a flood's count goes out even if the
// thermostat then falls quiet.
func (l *limiter) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flush(l.now())
}

func (l *limiter) flush(now time.Time) {
	for _, k := range l.order {
		w := l.win[k]
		if !w.open || now.Sub(w.start) < l.lim.Window {
			continue
		}
		if w.dropped > 0 {
			l.tally(k.device).coalesced++
		}
		w.open, w.dropped = false, 0
	}
}

// forget drops a removed device's windows and tally.
func (l *limiter) forget(device string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.counts, device)
	out := l.order[:0]
	for _, k := range l.order {
		if k.device == device {
			delete(l.win, k)
			continue
		}
		out = append(out, k)
	}
	l.order = out
}

func (l *limiter) stats(device string) counts {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c := l.counts[device]; c != nil {
		return *c
	}
	return counts{}
}
