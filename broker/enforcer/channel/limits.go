package channel

import "time"

// Kind is what a log line or a rate limit is about.
type Kind string

const (
	KindHello    Kind = "hello"    // a connection the core authenticated
	KindPreAuth  Kind = "preauth"  // a connection dropped before it authenticated
	KindCommand  Kind = "command"  // a device command
	KindTighten  Kind = "tighten"  // a closed-list tightening
	KindRead     Kind = "read"     // a read
	KindAnnounce Kind = "announce" // a proposal link the core texted
	KindHead     Kind = "head"     // a log head or key-change entry
	KindAnswer   Kind = "answer"   // a device challenge's answer
	KindRefused  Kind = "refused"  // any request or frame refused
	KindFrame    Kind = "frame"    // a frame that ended the connection
	KindPause    Kind = "pause"    // the channel paused or resumed
	KindTrip     Kind = "trip"     // a core trip at the enforcer (KRN-12)
)

// Limit is a token bucket: Burst at once, then one more every Every. A
// request that finds its kind's bucket empty is a burst past the rate, a
// core trip (NET-2 The channel, D-255). KindRefused's bucket pauses instead,
// since the kernel cannot know a request will be refused. KindPreAuth is
// the one bucket that neither trips nor pauses: past it, failed hellos are
// still dropped but no longer logged one by one.
type Limit struct {
	Burst int
	Every time.Duration
}

// DefaultLimits are the rates the channel takes before it trips. They are
// set well above an honest core's use and are a checkpoint, not a
// measurement (ASSUMPTIONS ENF-d-3). The engine's own per-device
// tightening limit (policy.TightenLimit) applies inside them.
var DefaultLimits = map[Kind]Limit{
	KindHello:    {Burst: 10, Every: time.Minute},
	KindCommand:  {Burst: 30, Every: 2 * time.Second},
	KindTighten:  {Burst: 20, Every: time.Minute},
	KindRead:     {Burst: 120, Every: 250 * time.Millisecond},
	KindAnnounce: {Burst: 5, Every: 10 * time.Minute},
	KindHead:     {Burst: 600, Every: 100 * time.Millisecond},
	KindAnswer:   {Burst: 30, Every: 2 * time.Second},
	KindRefused:  {Burst: 10, Every: time.Minute},
	KindPreAuth:  {Burst: 10, Every: time.Minute},
}

type bucket struct {
	l      Limit
	tokens int
	last   time.Time
}

func newBucket(l Limit, now time.Time) *bucket {
	return &bucket{l: l, tokens: l.Burst, last: now}
}

// take refills by whole intervals since last and takes one token.
func (b *bucket) take(now time.Time) bool {
	if b.l.Every > 0 && now.After(b.last) {
		n := int(now.Sub(b.last) / b.l.Every)
		if n > 0 {
			b.tokens = min(b.l.Burst, b.tokens+n)
			b.last = b.last.Add(time.Duration(n) * b.l.Every)
		}
	}
	if b.tokens == 0 {
		return false
	}
	if b.tokens == b.l.Burst {
		b.last = now // a full bucket does not bank time
	}
	b.tokens--
	return true
}

func (b *bucket) fill(now time.Time) { b.tokens, b.last = b.l.Burst, now }
