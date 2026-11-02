package channel

import (
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

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
	KindTrip     Kind = "trip"     // a core trip at the enforcer (KRN-12)
)

// Limit is a token bucket: Burst at once, then one more every Every.
type Limit = wire.Limit

// rated are the kinds whose rates the kernel checks before it sends, each
// read from the shared format definition (wire.Rate, D-255). A message of
// one of them past its rate trips the core (NET-2 The channel).
var rated = map[wire.RateKind]Kind{
	wire.RateHello:    KindHello,
	wire.RateCommand:  KindCommand,
	wire.RateTighten:  KindTighten,
	wire.RateRead:     KindRead,
	wire.RateAnnounce: KindAnnounce,
	wire.RateHead:     KindHead,
	wire.RateAnswer:   KindAnswer,
}

// The two rates that are the enforcer's own, which the kernel cannot
// check and which never trip. Past refusedLimit requests only wait,
// refused, until it refills, since the kernel cannot know a request will
// be refused. Past preAuthLimit failed hellos are still dropped but no
// longer logged one by one. Both are a checkpoint, not a measurement
// (ASSUMPTIONS ENF-d-3).
var (
	refusedLimit = Limit{Burst: 10, Every: time.Minute}
	preAuthLimit = Limit{Burst: 10, Every: time.Minute}
)

// DefaultLimit is kind k's rate: a rated kind's from the shared format
// definition, refusals' and failed hellos' the enforcer's own. The
// engine's own per-device tightening limit (policy.TightenLimit) applies
// inside them.
func DefaultLimit(k Kind) Limit {
	switch k {
	case KindRefused:
		return refusedLimit
	case KindPreAuth:
		return preAuthLimit
	}
	for rk, rk2 := range rated {
		if rk2 == k {
			return wire.Rate(rk)
		}
	}
	return Limit{}
}
