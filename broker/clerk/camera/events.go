package camera

import "time"

// Label is every event's data-flow label (PLN-3).
const Label = "private"

// Kind is a camera event's kind, from a closed list.
type Kind string

const (
	// Silent: nothing arrived for the node's interval, or it cannot be
	// reached.
	Silent Kind = "silent"
	// KeyRefused: the node presented a key other than its pin and is off.
	KeyRefused Kind = "key-refused"
	// StreamFault: a frame broke the camera wire and the connection ended.
	StreamFault Kind = "stream-fault"
	// Recovered: frames arrive again after Silent.
	Recovered Kind = "recovered"
)

// Event is one camera event as it goes onto the bus (DEV-8): private,
// untrusted, and verified, since the node is pinned by a key (DEV-3), so an
// owner rule may make "camera silent" urgent. It carries the camera's ID,
// the kind and the time, never a byte the node sent. A Coalesced event
// stands for that many events of one kind past the window's limit.
type Event struct {
	Camera    string
	Kind      Kind
	Label     string
	Verified  bool
	Time      time.Time
	Coalesced int
}

// EventSink takes the clerk's events: the kernel's device-report entry
// (DEVSLOT b3, #3321).
type EventSink interface {
	Emit(Event) error
}

// Limit is each camera's DEV-8 rate limit for each kind: Burst events per
// Window, and one coalesced, counted event for the rest. Each kind has its
// own window, so a flapping node's faults never hide its key change.
type Limit struct {
	Burst  int
	Window time.Duration
}

type wkey struct {
	camera string
	kind   Kind
}

type window struct {
	open    bool
	start   time.Time
	n       int
	dropped int
	last    Event
}

// emit passes e under its camera and kind's limit, as devhost's host does
// for drivers' readings.
func (c *Clerk) emit(e Event) error {
	c.lmu.Lock()
	defer c.lmu.Unlock()
	now := c.cfg.Now()
	if err := c.flush(now); err != nil {
		return err
	}
	k := wkey{e.Camera, e.Kind}
	w := c.win[k]
	if w == nil {
		w = &window{}
		c.win[k] = w
		c.order = append(c.order, k)
	}
	if !w.open {
		w.open, w.start, w.n = true, now, 0
	}
	if w.n < c.cfg.Limit.Burst {
		w.n++
		return c.cfg.Events.Emit(e)
	}
	w.dropped++
	w.last = e
	return nil
}

// Flush emits the coalesced events of windows that have ended. The host
// process calls it on a timer, so a flood's count goes out even if the
// node then falls quiet.
func (c *Clerk) Flush() error {
	c.lmu.Lock()
	defer c.lmu.Unlock()
	return c.flush(c.cfg.Now())
}

func (c *Clerk) flush(now time.Time) error {
	for _, k := range c.order {
		w := c.win[k]
		if !w.open || now.Sub(w.start) < c.cfg.Limit.Window {
			continue
		}
		w.open = false
		if w.dropped == 0 {
			continue
		}
		ev := w.last
		ev.Coalesced = w.dropped
		w.dropped, w.last = 0, Event{}
		if err := c.cfg.Events.Emit(ev); err != nil {
			return err
		}
	}
	return nil
}
