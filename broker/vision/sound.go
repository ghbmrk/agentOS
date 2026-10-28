package vision

import (
	"context"
	"sync"
	"time"
)

// Sound events (part d, VIS-plates-sound; brief point 7, DEV-7, DEV-8,
// VIS-A20). Audio goes to the service's classifier and only labels from
// the fixed list come back. Hear zeroes the clip once the call is done, on
// every path, so no caller of it keeps audio by accident, and nothing here
// logs, stores or forwards a byte of it. A label repeats onto the bus at
// most once per Quiet for each source, and each source's repeats are
// rate-limited, the excess coalesced and counted per label; a label with no
// event in the last minute always passes, so a rare one is never starved.

// Sound rule defaults.
const (
	// DefaultSoundQuiet is the least time between two events of one
	// label from one source.
	DefaultSoundQuiet = 30 * time.Second
	// DefaultSoundsPerMinute bounds one source's repeat events a minute.
	DefaultSoundsPerMinute = 6
)

// SoundEvent is one sound label heard at one source, as the bus carries
// it. Coalesced counts that label's events from the source dropped since
// its last event, by Quiet or the rate limit.
type SoundEvent struct {
	Source    string
	Label     string
	Conf      int
	Coalesced int
}

// Sounds turns clips from capture sources into sound events. The zero
// value is not ready; use NewSounds.
type Sounds struct {
	// Client is the service's feed client.
	Client Client
	// Quiet is the least time between two events of one label from one
	// source.
	Quiet time.Duration
	// PerMinute bounds each source's events in any minute once they
	// include a repeat: an event whose label already had one in that
	// minute. A label's first event in a minute always passes, so a
	// source gives at most PerMinute+MaxSounds events a minute.
	PerMinute int
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu      sync.Mutex
	sources map[string]*soundSource
}

type soundSource struct {
	last      map[string]time.Time // each label's last event
	sent      []time.Time          // events in the last minute
	coalesced map[string]int       // each label's drops since its last event
	lastSeen  time.Time
}

// NewSounds returns Sounds on c with the default rule.
func NewSounds(c Client) *Sounds {
	return &Sounds{Client: c, Quiet: DefaultSoundQuiet, PerMinute: DefaultSoundsPerMinute}
}

func (s *Sounds) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Hear classifies pcm (AudioPCM16k) from source, a capture source's id
// from [a-z0-9-], and returns the events it gives. pcm is zeroed before
// Hear returns, whatever happens. On an error there are no events, and
// the error's cause (CauseOf) is one of the service's.
func (s *Sounds) Hear(ctx context.Context, source string, pcm []byte) ([]SoundEvent, error) {
	defer clear(pcm)
	if !ValidEnrolledID(source) {
		return nil, badRequest("source id outside its alphabet")
	}
	ss, err := s.Client.Sound(ctx, pcm)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.source(source)
	now := s.now()
	quiet := s.Quiet
	if quiet <= 0 {
		quiet = DefaultSoundQuiet
	}
	var out []SoundEvent
	for _, h := range ss {
		at, sent := src.last[h.Label]
		if sent && now.Sub(at) < quiet {
			src.coalesced[h.Label]++
			continue
		}
		// A label with no event in the last minute passes the limit, so
		// routine labels cannot starve a rare one (an alarm after a
		// run of dog barks); the limit holds the repeats.
		if sent && now.Sub(at) < time.Minute && len(src.sent) >= max(s.PerMinute, 1) {
			src.coalesced[h.Label]++
			continue
		}
		src.last[h.Label] = now
		src.sent = append(src.sent, now)
		out = append(out, SoundEvent{Source: source, Label: h.Label, Conf: h.Conf, Coalesced: src.coalesced[h.Label]})
		delete(src.coalesced, h.Label)
	}
	return out, nil
}

// source returns id's state with events older than a minute gone. The
// caller holds mu.
func (s *Sounds) source(id string) *soundSource {
	now := s.now()
	if s.sources == nil {
		s.sources = map[string]*soundSource{}
	}
	src := s.sources[id]
	if src == nil {
		// Sources are the owner's few; a stale one is dropped when a
		// new one comes, so the map stays small.
		for old, o := range s.sources {
			if now.Sub(o.lastSeen) > time.Hour && len(o.coalesced) == 0 {
				delete(s.sources, old)
			}
		}
		src = &soundSource{last: map[string]time.Time{}, coalesced: map[string]int{}}
		s.sources[id] = src
	}
	src.lastSeen = now
	keep := src.sent[:0]
	for _, at := range src.sent {
		if now.Sub(at) < time.Minute {
			keep = append(keep, at)
		}
	}
	src.sent = keep
	return src
}

// Coalesced is source's events of label dropped and not yet carried by an
// event.
func (s *Sounds) Coalesced(source, label string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if src := s.sources[source]; src != nil {
		return src.coalesced[label]
	}
	return 0
}
