package camera

import (
	"slices"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/clerk/devslot"
)

// limiter is each camera's DEV-8 limit, per event kind, with devhost's
// rule: the first Burst events of a window go to the sink, the rest are
// counted, and the count goes out as one coalesced event once the window
// has ended. Events are private and verified: a camera proved its pinned
// key (DEV-3).
type limiter struct {
	mu    sync.Mutex
	limit devhost.Limit
	now   func() time.Time
	sink  devhost.Sink
	win   map[string]*window // by camera and kind
}

type window struct {
	start   time.Time
	n       int
	dropped int
	last    devslot.Event
}

func (l *limiter) emit(id, kind string, v int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if err := l.flushLocked(now); err != nil {
		return err
	}
	e := devslot.Event{Device: id, Op: Op, Label: devslot.Label, Reading: devslot.Reading{Kind: kind, Value: v, Time: now.UTC()}}
	k := id + "\x00" + kind
	w := l.win[k]
	if w == nil {
		w = &window{start: now}
		l.win[k] = w
	}
	if w.n < l.limit.Burst {
		w.n++
		return l.sink.Emit(devhost.Event{Event: e})
	}
	w.dropped++
	w.last = e
	return nil
}

func (l *limiter) flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flushLocked(l.now())
}

// flushLocked ends each window that has run its length, in key order, and
// forgets it, so the map holds only open windows.
func (l *limiter) flushLocked(now time.Time) error {
	keys := make([]string, 0, len(l.win))
	for k, w := range l.win {
		if now.Sub(w.start) >= l.limit.Window {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		w := l.win[k]
		delete(l.win, k)
		if w.dropped == 0 {
			continue
		}
		if err := l.sink.Emit(devhost.Event{Event: w.last, Coalesced: w.dropped}); err != nil {
			return err
		}
	}
	return nil
}
