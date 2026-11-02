package wire

import "time"

// RateKind is what one of the core's rates counts: each message the core
// sends on the channel takes one token of its kind (NET-2 The channel,
// D-255). The enforcer trips the core on a message past its kind's rate,
// and the kernel checks the same rate before it sends (broker/kernel/
// chancheck), so both read the kinds, the rates and the bucket here,
// never a copy (ASSUMPTIONS ENF-d-w7).
type RateKind uint8

const (
	RateHello    RateKind = 1 // a connection's hello
	RateCommand  RateKind = 2 // a device command
	RateTighten  RateKind = 3 // a closed-list tightening
	RateRead     RateKind = 4 // a read
	RateAnnounce RateKind = 5 // a proposal link the core texted
	RateHead     RateKind = 6 // a log head or key-change entry
	RateAnswer   RateKind = 7 // a device challenge's answer
)

// RateKindOf is the kind a frame of type t from the core counts as, and
// zero for a type the core does not send. A head and an entry share one
// rate.
func RateKindOf(t Type) RateKind {
	switch t {
	case THello:
		return RateHello
	case TCommand:
		return RateCommand
	case TTighten:
		return RateTighten
	case TRead:
		return RateRead
	case TAnnounce:
		return RateAnnounce
	case THead, TEntry:
		return RateHead
	case TAnswer:
		return RateAnswer
	}
	return 0
}

// RateKinds are every kind, in order.
var RateKinds = [...]RateKind{RateHello, RateCommand, RateTighten, RateRead, RateAnnounce, RateHead, RateAnswer}

// Limit is a token bucket: Burst at once, then one more every Every.
// Every is positive.
type Limit struct {
	Burst int
	Every time.Duration
}

// Rate is kind k's rate, and the zero Limit, which admits nothing, for a
// kind not listed. The numbers are set well above an honest core's use and
// are a checkpoint, not a measurement (ASSUMPTIONS ENF-d-w7). A function,
// not a map, so no importer can change the table the other end reads.
func Rate(k RateKind) Limit {
	switch k {
	case RateHello:
		return Limit{Burst: 10, Every: time.Minute}
	case RateCommand:
		return Limit{Burst: 30, Every: 2 * time.Second}
	case RateTighten:
		return Limit{Burst: 20, Every: time.Minute}
	case RateRead:
		return Limit{Burst: 120, Every: 250 * time.Millisecond}
	case RateAnnounce:
		return Limit{Burst: 5, Every: 10 * time.Minute}
	case RateHead:
		return Limit{Burst: 600, Every: 100 * time.Millisecond}
	case RateAnswer:
		return Limit{Burst: 30, Every: 2 * time.Second}
	}
	return Limit{}
}

// Bucket is a Limit's state, kept as the time the bucket is full again
// (the generic cell rate algorithm's theoretical arrival time). A token is
// left at now while full is at most Burst-1 intervals after now; taking
// one moves full one interval past the later of full and now. So a
// message counted later leaves the bucket emptier, and a message checked
// later finds it fuller: the two facts the kernel's check rests on
// (ASSUMPTIONS ENF-d-w7). A reading earlier than one already seen counts
// as that one, so a clock stepped back refills nothing and takes nothing.
// A Bucket is not safe for concurrent use.
type Bucket struct {
	l    Limit
	full time.Time
	seen time.Time
}

// NewBucket is a full bucket for l at now.
func NewBucket(l Limit, now time.Time) *Bucket {
	return &Bucket{l: l, full: now, seen: now}
}

// Has reports whether a token is left at now, taking none.
func (b *Bucket) Has(now time.Time) bool {
	now = b.see(now)
	return b.l.Burst > 0 && b.full.Sub(now) <= time.Duration(b.l.Burst-1)*b.l.Every
}

// Take takes one token at now and reports whether one was left. A bucket
// with none left is unchanged.
func (b *Bucket) Take(now time.Time) bool {
	if !b.Has(now) {
		return false
	}
	b.Spend(b.seen)
	return true
}

// Spend counts one message at at whether or not a token is left: the
// kernel's record of a message the enforcer may have counted as late as
// at. It does not move the bucket's clock.
func (b *Bucket) Spend(at time.Time) {
	if b.full.Before(at) {
		b.full = at
	}
	b.full = b.full.Add(b.l.Every)
}

func (b *Bucket) see(now time.Time) time.Time {
	if now.Before(b.seen) {
		return b.seen
	}
	b.seen = now
	return now
}
