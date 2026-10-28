package vision

import (
	"strconv"
	"sync"
	"time"
)

// Plate events (part d, VIS-plates-sound; DEV-8, VIS-A9, VIS-A19). A read
// of plate text is a channel the untrusted service fills, about 52 bits a
// read, so the client reports a vehicle track's plate once, only after the
// same read has held over several frames and outweighs every other read,
// and each camera's plate events are rate-limited, the excess coalesced
// and counted. A service that cycles reads to push bits out gets nothing
// for that track, and a flood of tracks gets a count, not plates.

// Plate rule defaults.
const (
	// DefaultPlateHold is the frames a read must hold before it is
	// reported.
	DefaultPlateHold = 3
	// DefaultPlatesPerMinute bounds one camera's plate events a minute.
	DefaultPlatesPerMinute = 6
	// MaxPlateReads bounds the distinct reads one track may give; past
	// it the track's reads are noise, and it never reports.
	MaxPlateReads = 8
	// MaxPlateTracks bounds the tracks held at once; a new track past it
	// evicts the one read least recently.
	MaxPlateTracks = 256
)

// TrackKey names one vehicle track: the camera's id and the track number
// the client's tracker gave it (part b), never the service's.
type TrackKey struct {
	Camera string
	Track  uint64
}

// PlateEvent is a track's plate as the bus carries it: Plate is quoted, as
// device-supplied text (DEV-8). Frames is how many frames gave that read.
// Coalesced counts this camera's plate events dropped by its rate limit
// since its last event.
type PlateEvent struct {
	Camera    string
	Track     uint64
	Plate     string
	Frames    int
	Coalesced int
}

// Plates holds the per-track plate reads. The zero value is not ready;
// use NewPlates.
type Plates struct {
	// Hold is the frames a read must hold before it is reported, and it
	// must also be held twice as often as every other read together.
	Hold int
	// PerMinute bounds each camera's plate events in any minute.
	PerMinute int
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu      sync.Mutex
	tracks  map[TrackKey]*plateTrack
	tick    uint64                  // orders reads, for eviction
	cameras map[string]*plateCamera // rate limit per camera
}

type plateTrack struct {
	reads    map[string]int
	done     bool
	lastRead uint64
}

type plateCamera struct {
	sent      []time.Time // events in the last minute
	coalesced int
	lastSeen  time.Time
}

// NewPlates returns Plates with the default rule.
func NewPlates() *Plates {
	return &Plates{Hold: DefaultPlateHold, PerMinute: DefaultPlatesPerMinute}
}

func (p *Plates) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Read takes one frame's detection on track k and returns the track's
// plate event when this read settles it. A detection without plate text,
// or not a vehicle, settles nothing. A track reports at most once, until
// End forgets it.
func (p *Plates) Read(k TrackKey, d Detection) (PlateEvent, bool) {
	if d.Class != Vehicle || d.Plate == "" || !ValidPlate(d.Plate) || !ValidEnrolledID(k.Camera) {
		return PlateEvent{}, false
	}
	hold := max(p.Hold, 1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tracks == nil {
		p.tracks = map[TrackKey]*plateTrack{}
		p.cameras = map[string]*plateCamera{}
	}
	p.tick++
	t := p.tracks[k]
	if t == nil {
		if len(p.tracks) >= MaxPlateTracks {
			p.evict()
		}
		t = &plateTrack{reads: map[string]int{}}
		p.tracks[k] = t
	}
	t.lastRead = p.tick
	if t.done {
		return PlateEvent{}, false
	}
	if _, ok := t.reads[d.Plate]; !ok && len(t.reads) == MaxPlateReads {
		// Too many distinct reads: noise or a service cycling text.
		// The track never reports, and its reads are dropped.
		t.done = true
		clear(t.reads)
		return PlateEvent{}, false
	}
	t.reads[d.Plate]++
	best, n, total := "", 0, 0
	for r, c := range t.reads {
		total += c
		if c > n || c == n && r < best {
			best, n = r, c
		}
	}
	if n < hold || n < 2*(total-n) {
		return PlateEvent{}, false
	}
	t.done = true
	clear(t.reads)
	c := p.camera(k.Camera)
	if len(c.sent) >= max(p.PerMinute, 1) {
		c.coalesced++
		return PlateEvent{}, false
	}
	c.sent = append(c.sent, p.now())
	e := PlateEvent{Camera: k.Camera, Track: k.Track, Plate: strconv.Quote(best), Frames: n, Coalesced: c.coalesced}
	c.coalesced = 0
	return e, true
}

// camera returns id's rate-limit state with events older than a minute
// gone. The caller holds mu.
func (p *Plates) camera(id string) *plateCamera {
	now := p.now()
	c := p.cameras[id]
	if c == nil {
		// Cameras are the owner's few; a stale one is dropped when a
		// new one comes, so the map stays small.
		for old, oc := range p.cameras {
			if now.Sub(oc.lastSeen) > time.Hour && oc.coalesced == 0 {
				delete(p.cameras, old)
			}
		}
		c = &plateCamera{}
		p.cameras[id] = c
	}
	c.lastSeen = now
	keep := c.sent[:0]
	for _, at := range c.sent {
		if now.Sub(at) < time.Minute {
			keep = append(keep, at)
		}
	}
	c.sent = keep
	return c
}

// evict forgets the track read least recently. The caller holds mu.
func (p *Plates) evict() {
	var oldest TrackKey
	var at uint64
	first := true
	for k, t := range p.tracks {
		if first || t.lastRead < at {
			oldest, at, first = k, t.lastRead, false
		}
	}
	p.forget(oldest)
}

func (p *Plates) forget(k TrackKey) {
	if t := p.tracks[k]; t != nil {
		clear(t.reads)
		delete(p.tracks, k)
	}
}

// End forgets track k, when the tracker ends it.
func (p *Plates) End(k TrackKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.forget(k)
}

// Coalesced is camera's plate events dropped by its rate limit and not
// yet carried by an event.
func (p *Plates) Coalesced(camera string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.cameras[camera]; c != nil {
		return c.coalesced
	}
	return 0
}
