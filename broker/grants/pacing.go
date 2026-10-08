package grants

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// PacingStore is a broker-private, exclusive single-writer store. Save must
// durably and atomically replace the state; any error has an uncertain outcome.
// change.FileStore satisfies this interface. Use a separate file from other
// components. Missing state is accepted only for trusted first provisioning;
// PacingRequireExisting must be true for a provisioned installation.
type PacingStore interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// PacingStoreHealth is an optional trusted backend lifecycle signal. The
// callback must be bounded, nonblocking, I/O-free and safe for concurrent reads.
// It must not call back into Gate or acquire its admission mutex. It reports
// observed retirement/failure, not permission revocation or store freshness.
type PacingStoreHealth interface{ PacingHealth() error }

// ErrPacingRecovery deliberately discloses no storage path or underlying error.
var ErrPacingRecovery = errors.New("grants: pacing recovery required")

const (
	maxPacingLimit = 4096
	// MaxPacingStateBytes bounds serialized accounting state and bounded readers.
	MaxPacingStateBytes = 512 * 1024
	maxPacingBytes      = MaxPacingStateBytes
)

type pacingState struct {
	Version int         `json:"version"`
	Limit   int         `json:"limit"`
	Last    time.Time   `json:"last"`
	Aged    time.Time   `json:"aged"`
	Texts   []time.Time `json:"texts"`
}

// PacingHealth reports a latched accounting failure without admission locking
// or store I/O, including a still-running store call beyond its configured threshold.
// A failed object cannot be repaired in place: quiesce it and construct a new
// gate against the same durable store after trusted recovery.
func (g *Gate) PacingHealth() error {
	if g.pacingFault.Load() {
		return ErrPacingRecovery
	}
	if s, ok := g.cfg.PacingStore.(PacingStoreHealth); ok && s.PacingHealth() != nil {
		g.pacingFault.Store(true)
	}
	deadline := g.pacingDeadline.Load()
	if deadline != nil && !time.Now().Before(*deadline) && g.pacingDeadline.CompareAndSwap(deadline, nil) {
		g.pacingFault.Store(true)
	}
	if g.pacingFault.Load() {
		return ErrPacingRecovery
	}
	return nil
}

func pacingTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 }

// Called under mu for reservations. Read the clock inside the lock so concurrent
// callers cannot compare an older sampled time with a later committed one.
func (g *Gate) pacingClockLocked(now time.Time) bool {
	if g.PacingHealth() != nil {
		return false
	}
	if g.cfg.PacingStore == nil {
		return true
	}
	if g.pacingFault.Load() || !pacingTime(now) || now.Before(g.pacingLast) {
		g.pacingFault.Store(true)
		return false
	}
	g.pacingLast = now.Round(0).UTC()
	return true
}

func (g *Gate) openPacing() {
	if g.PacingHealth() != nil {
		return
	}
	if g.cfg.PacingMaxStoreLatency < 0 || g.cfg.PacingMaxStoreLatency > 5*time.Minute || g.cfg.PacingMaxStoreLatency > 0 && g.cfg.PacingStore == nil {
		g.pacingFault.Store(true)
		return
	}
	if g.cfg.PacingStore == nil {
		g.pacingFault.Store(g.cfg.PacingRequireExisting)
		return
	}
	now := g.cfg.Now().Round(0).UTC()
	if g.cfg.RequestsPerHour > maxPacingLimit || !pacingTime(now) {
		g.pacingFault.Store(true)
		return
	}
	var b []byte
	err := g.pacingStoreCall(func() (err error) {
		b, err = g.cfg.PacingStore.Load()
		return err
	})
	if err != nil || len(b) > maxPacingBytes || g.cfg.PacingRequireExisting && b == nil {
		g.pacingFault.Store(true)
		return
	}
	if b != nil {
		var st pacingState
		// Require the canonical form we write. This also refuses duplicate keys,
		// unknown fields, trailing values, null and noncanonical timestamp encodings.
		err = json.Unmarshal(b, &st)
		canonical, e := json.Marshal(st)
		if err != nil || e != nil || !bytes.Equal(b, canonical) || st.Version != 1 || st.Limit != g.cfg.RequestsPerHour || !pacingTime(st.Last) || now.Before(st.Last) || len(st.Texts) > st.Limit || (!st.Aged.IsZero() && (!pacingTime(st.Aged) || st.Aged.After(st.Last))) {
			g.pacingFault.Store(true)
			return
		}
		for i, t := range st.Texts {
			if !pacingTime(t) || t.After(st.Last) || i > 0 && t.Before(st.Texts[i-1]) {
				g.pacingFault.Store(true)
				return
			}
		}
		g.sent = append([]time.Time(nil), st.Texts...)
		g.agedAt = st.Aged
	}
	g.pacingLast = now
	g.textsLocked(now)
	// Confirm the recovered image's durability before allowing a new send, also
	// covering a previous save that replaced the file but reported sync failure.
	g.commitPacingLocked(now, 0, g.agedAt)
}

// Persist the newest limit timestamps. Older discarded reservations expire no
// later than retained ones: while they could matter, at least limit newer texts
// remain, so paced traffic is still refused. This preserves exact available
// allowance without unbounded urgent-traffic history. No caller refunds sends.
func (g *Gate) commitPacingLocked(now time.Time, n int, aged time.Time) bool {
	if g.cfg.PacingStore == nil {
		return true
	}
	if g.PacingHealth() != nil {
		return false
	}
	texts := append([]time.Time(nil), g.sent...)
	texts = append(texts, g.asked...)
	slices.SortFunc(texts, func(a, b time.Time) int { return a.Compare(b) })
	nKeep := min(n, g.cfg.RequestsPerHour)
	for range nKeep {
		texts = append(texts, now.Round(0).UTC())
	}
	if len(texts) > g.cfg.RequestsPerHour {
		texts = texts[len(texts)-g.cfg.RequestsPerHour:]
	}
	st := pacingState{Version: 1, Limit: g.cfg.RequestsPerHour, Last: g.pacingLast, Aged: aged.Round(0).UTC(), Texts: texts}
	b, err := json.Marshal(st)
	if err != nil || len(b) > maxPacingBytes {
		g.pacingFault.Store(true)
		return false
	}
	if err = g.pacingStoreCall(func() error { return g.cfg.PacingStore.Save(b) }); err != nil {
		g.pacingFault.Store(true)
		return false
	}
	g.sent = texts
	g.asked = nil
	g.agedAt = aged
	return true
}

// The admission mutex serializes store calls. Publish only their monotonic
// deadline for health observers; no worker, timer, retry or alternate writer is
// created. A late callback may already have committed: never grant permission
// or refund that uncertain/spent debt. Returning from this function is the
// observed completion boundary, not a guarantee about kernel I/O timing.
func (g *Gate) pacingStoreCall(call func() error) error {
	var deadline *time.Time
	if g.cfg.PacingMaxStoreLatency > 0 {
		end := time.Now().Add(g.cfg.PacingMaxStoreLatency)
		deadline = &end
		g.pacingDeadline.Store(deadline)
	}
	err := call()
	g.pacingDeadline.Store(nil)
	if err != nil || deadline != nil && !time.Now().Before(*deadline) {
		g.pacingFault.Store(true)
	}
	if g.PacingHealth() != nil {
		return ErrPacingRecovery
	}
	return nil
}

// ProvisionedPacingConfigured inspects only immutable constructor options. It
// does not read/write storage, reserve, repair, or assert store health/custody.
// Assembly still binds PacingHealth, including held missing/faulted-state startup.
func (g *Gate) ProvisionedPacingConfigured() bool {
	return g != nil && g.cfg.PacingStore != nil && g.cfg.PacingRequireExisting &&
		g.cfg.PacingMaxStoreLatency > 0 && g.cfg.PacingMaxStoreLatency <= 5*time.Minute
}
