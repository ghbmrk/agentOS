package hint

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Mode is the owner's policy for one category (OSS-7).
type Mode int

const (
	Automatic Mode = iota // the default: content crossing is clean-room
	Ask                   // ask the owner each time
	Never                 // keep on the box; still logged
)

const (
	// DefaultDailyLimit is the most hints one daily batch may carry when
	// Config.DailyLimit is zero (arbitrator's ruling on #40).
	DefaultDailyLimit = 5
	// DefaultEmbargoReserve is the batch slots kept for embargo kinds when
	// Config.EmbargoReserve is zero, capped to leave one routine slot.
	DefaultEmbargoReserve = 2
	// DefaultDedupeDays is how many days a hint counts as a duplicate of
	// an identical one queued or asked, when Config.DedupeDays is zero.
	DefaultDedupeDays = 7
	// DefaultReleaseAt is the UTC time of day a batch is released when
	// Config.ReleaseAt is zero.
	DefaultReleaseAt = 4 * time.Hour
)

// ErrNoPending is returned when an ID names no hint waiting for the owner.
var ErrNoPending = errors.New("hint: no such pending hint")

// Outbox receives each day's batch of canonical hints for the clean-room
// builder, sorted, with the day the batch belongs to. Each day labels at
// most one batch, so Send must be idempotent by day: after a crash, or an
// error that came after delivery, the emitter sends the same batch (the
// bytes recorded when it was formed) for the same day again, and the
// outbox delivers a day at most once.
type Outbox interface {
	Send(day string, batch [][]byte) error
}

// Config sets up an Emitter.
type Config struct {
	Schema *Schema         // nil means Default()
	Policy map[string]Mode // by category; absent means Automatic

	// DailyLimit caps one batch (0 means DefaultDailyLimit). EmbargoReserve
	// of its slots are kept for embargo kinds such as vuln (0 means
	// DefaultEmbargoReserve, at most DailyLimit-1); slots one class leaves
	// unused go to the other. Hints over the cap wait for the next batch.
	DailyLimit     int
	EmbargoReserve int
	// DedupeDays: a hint identical to one queued or asked within this many
	// days (today included) is a Duplicate (0 means DefaultDedupeDays).
	DedupeDays int
	// MaxBacklog bounds the hints of each class waiting to cross (0 means
	// 7 × DailyLimit). Over it, a hint is logged OverLimit and dropped.
	// MaxPending bounds the asks waiting for the owner the same way.
	// Asks unanswered for DedupeDays expire as Expired (declined).
	MaxBacklog int
	MaxPending int
	// ReleaseAt is the UTC time of day after which the previous days'
	// hints are released (0 means DefaultReleaseAt).
	ReleaseAt time.Duration

	Log    Log    // required
	Outbox Outbox // required
	Now    func() time.Time
}

// Result says what Emit did. ID is set for an Asked hint and is what the
// owner's Approve or Decline names; it never crosses the bridge.
type Result struct {
	Outcome Outcome
	ID      int
}

// Pending is a hint waiting for the owner.
type Pending struct {
	ID     int
	Day    string
	Kind   string
	Fields map[string]string
}

type queued struct {
	seq     int
	day     string
	embargo bool
	canon   string
}

// batch is a Forwarded record whose send has not been committed by a Sent
// record.
type batch struct {
	seq    int // the Forwarded record
	day    string
	items  []queued
	failed bool // a SendFailed record is already logged for it
}

// Emitter is the private side's single exit to the bridge.
//
// Emit never sends. It queues a hint (or asks the owner about it), and
// Release, called on any schedule, sends every hint queued on an earlier
// day as one batch once the day's release time has passed, in sorted
// canonical order. Only the set of hints crosses: not their order, not
// when they were emitted. The day only moves forward: a clock stepped
// back keeps the latest day seen, so it cannot shorten the dedupe window
// or reopen an earlier day's release. The host clock is trusted: each step
// forward to a new day allows one more batch.
//
// A batch is one Forwarded record, written before the send, and a Sent
// record after the outbox accepts it. A batch without Sent (a failed send,
// or a crash in between) is resent, exactly the same set for the same
// day, before any new batch.
type Emitter struct {
	cfg Config

	mu          sync.Mutex
	seq         int
	day         string            // latest UTC day seen; never moves back
	seen        map[string]string // canonical form -> latest day queued or asked
	backlog     []queued          // waiting to cross, oldest first
	pending     map[int]Pending   // asks waiting for the owner
	inflight    *batch            // forwarded, not yet committed Sent
	lastRelease string            // day of the latest batch formed
}

// PLACEHOLDER_TOO_LARGE — will use push_files from JSON instead
