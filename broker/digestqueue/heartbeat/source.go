// Package heartbeat supplies an explicitly scheduled, durable daily alive line.
// It does not start a timer, grant dispatch authority or prove owner visibility.
package heartbeat

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"io"
	"math"
	"slices"
	"sync"
	"time"
)

const ID = "daily-heartbeat"
const Line = "Box is running."
const maxStateBytes = 16 << 10

var ErrInvalid = errors.New("heartbeat: invalid configuration, state or receipt")
var ErrRecovery = errors.New("heartbeat: storage needs recovery")
var ErrClock = errors.New("heartbeat: clock restricted or moved backwards")
var ErrStale = errors.New("heartbeat: previous day's pending line needs recovery")
var ErrFull = errors.New("heartbeat: generation bound exhausted")

type Config struct {
	Store digestqueue.Store
	// Clock is a trusted atomic time/restriction observation. Any error holds
	// new time-sensitive work. Do not supply a guest clock or an unchecked RTC.
	Clock func() (time.Time, error)
	// Zone is an explicit IANA zone or UTC; Local is refused. Minute is the
	// first eligible local wall minute, from 0 through 1439.
	Zone   string
	Minute int
	Rand   io.Reader
}
type state struct {
	Schema  int                   `json:"schema"`
	Zone    string                `json:"zone"`
	Minute  int                   `json:"minute"`
	Key     []byte                `json:"key"`
	Seq     uint64                `json:"seq"`
	Acked   uint64                `json:"acked"`
	LastDay string                `json:"last_day"`
	Pending *digestqueue.Snapshot `json:"pending,omitempty"`
}
type receipt struct {
	Generation uint64 `json:"generation"`
	Day        string `json:"day"`
	MAC        string `json:"mac"`
}
type Source struct {
	mu     sync.Mutex
	cfg    Config
	zone   *time.Location
	st     state
	broken bool
}

var _ digestqueue.Source = (*Source)(nil)

func cloneSnapshot(s digestqueue.Snapshot) digestqueue.Snapshot {
	s.Lines = slices.Clone(s.Lines)
	s.References = slices.Clone(s.References)
	return s
}
func cloneState(st state) state {
	st.Key = slices.Clone(st.Key)
	if st.Pending != nil {
		p := cloneSnapshot(*st.Pending)
		st.Pending = &p
	}
	return st
}
func decode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return ErrInvalid
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
func validDay(day string) bool {
	t, err := time.Parse("2006-01-02", day)
	return err == nil && t.Year() >= 1 && t.Year() <= 9999 && t.Format("2006-01-02") == day
}
func (s *Source) mac(gen uint64, day string) string {
	h := hmac.New(sha256.New, s.st.Key)
	fmt.Fprintf(h, "agentos/digest/heartbeat/v1\x00%s\x00%d\x00%d\x00%s", s.cfg.Zone, s.cfg.Minute, gen, day)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Source) decodeSnapshot(snap digestqueue.Snapshot) (receipt, error) {
	var r receipt
	if snap.Source != ID || snap.Generation == 0 || len(snap.Lines) != 1 || snap.Lines[0] != Line || len(snap.References) != 0 || len(snap.Receipt) > 256 {
		return r, ErrInvalid
	}
	if err := decode([]byte(snap.Receipt), &r); err != nil {
		return r, err
	}
	canonical, _ := json.Marshal(r)
	if string(canonical) != snap.Receipt {
		return r, ErrInvalid
	}
	reconstructed, err := digestqueue.NewSnapshotWithReceipt(ID, snap.Generation, []string{Line}, nil, snap.Receipt)
	if err != nil || reconstructed.Hash != snap.Hash || r.Generation != snap.Generation || !validDay(r.Day) || len(r.MAC) != 64 || !hmac.Equal([]byte(r.MAC), []byte(s.mac(r.Generation, r.Day))) {
		return r, ErrInvalid
	}
	return r, nil
}
func New(cfg Config) (*Source, error) {
	if cfg.Store == nil || cfg.Clock == nil || cfg.Zone == "" || cfg.Zone == "Local" || cfg.Minute < 0 || cfg.Minute >= 24*60 {
		return nil, ErrInvalid
	}
	zone, err := time.LoadLocation(cfg.Zone)
	if err != nil {
		return nil, ErrInvalid
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	raw, err := cfg.Store.Load()
	if err != nil {
		return nil, errors.Join(ErrRecovery, err)
	}
	if len(raw) > maxStateBytes {
		return nil, ErrInvalid
	}
	s := &Source{cfg: cfg, zone: zone, st: state{Schema: 1, Zone: cfg.Zone, Minute: cfg.Minute}}
	if len(raw) == 0 {
		s.st.Key = make([]byte, 32)
		if _, err := io.ReadFull(cfg.Rand, s.st.Key); err != nil {
			return nil, ErrInvalid
		}
	} else {
		if err := decode(raw, &s.st); err != nil {
			return nil, err
		}
	}
	st := s.st
	if st.Schema != 1 || st.Zone != cfg.Zone || st.Minute != cfg.Minute || len(st.Key) != 32 || st.Acked > st.Seq {
		return nil, ErrInvalid
	}
	if st.Seq == 0 {
		if st.Acked != 0 || st.LastDay != "" || st.Pending != nil {
			return nil, ErrInvalid
		}
	} else {
		if !validDay(st.LastDay) {
			return nil, ErrInvalid
		}
		if st.Pending == nil {
			if st.Seq != st.Acked {
				return nil, ErrInvalid
			}
		} else {
			r, err := s.decodeSnapshot(*st.Pending)
			if err != nil || st.Pending.Generation != st.Seq || st.Seq-st.Acked != 1 || r.Day != st.LastDay {
				return nil, ErrInvalid
			}
		}
	}
	// Confirm observed state before accepting a possibly uncertain prior rename.
	if err := s.save(st); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Source) save(st state) error {
	raw, err := json.Marshal(st)
	if err != nil || len(raw) > maxStateBytes {
		return ErrInvalid
	}
	if err := s.cfg.Store.Save(raw); err != nil {
		s.broken = true
		return errors.Join(ErrRecovery, err)
	}
	s.st = cloneState(st)
	return nil
}
func (s *Source) ready(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.broken {
		return ErrRecovery
	}
	return nil
}
func (s *Source) clock(ctx context.Context) (time.Time, string, error) {
	t, err := s.cfg.Clock()
	if err := ctx.Err(); err != nil {
		return time.Time{}, "", err
	}
	if err != nil || t.IsZero() || t.Year() < 1 || t.Year() > 9999 || t.UTC().Year() < 1 || t.UTC().Year() > 9999 {
		return time.Time{}, "", ErrClock
	}
	local := t.In(s.zone)
	if local.Year() < 1 || local.Year() > 9999 {
		return time.Time{}, "", ErrClock
	}
	day := local.Format("2006-01-02")
	if s.st.LastDay != "" && day < s.st.LastDay {
		return time.Time{}, "", ErrClock
	}
	return local, day, nil
}

// Plan stages at most one heartbeat per trusted local day. It never replaces a
// stale unacknowledged day. Wall-minute comparison handles spring gaps; the
// durable day ledger prevents duplicate issuance during the repeated fall hour.
func (s *Source) Plan(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	local, day, err := s.clock(ctx)
	if err != nil {
		return err
	}
	if s.st.Pending != nil {
		if day != s.st.LastDay {
			return ErrStale
		}
		return nil
	}
	if day == s.st.LastDay || local.Hour()*60+local.Minute() < s.cfg.Minute {
		return nil
	}
	if s.st.Seq == math.MaxUint64 {
		return ErrFull
	}
	next := cloneState(s.st)
	next.Seq++
	next.LastDay = day
	r := receipt{Generation: next.Seq, Day: day, MAC: s.mac(next.Seq, day)}
	raw, _ := json.Marshal(r)
	snap, err := digestqueue.NewSnapshotWithReceipt(ID, next.Seq, []string{Line}, nil, string(raw))
	if err != nil {
		return err
	}
	next.Pending = &snap
	return s.save(next)
}
func (s *Source) Peek(ctx context.Context) (*digestqueue.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	_, day, err := s.clock(ctx)
	if err != nil {
		return nil, err
	}
	if s.st.Pending == nil {
		return nil, nil
	}
	if day != s.st.LastDay {
		return nil, ErrStale
	}
	snap := cloneSnapshot(*s.st.Pending)
	return &snap, nil
}

// Ack validates private issuance, not clock/transport/owner authority. Replaying
// an already admitted exact receipt remains possible during clock restrictions.
func (s *Source) Ack(ctx context.Context, snap digestqueue.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	r, err := s.decodeSnapshot(snap)
	if err != nil {
		return err
	}
	if r.Generation > s.st.Seq {
		return ErrInvalid
	}
	if r.Generation <= s.st.Acked {
		return nil
	}
	if s.st.Pending == nil || snap.Hash != s.st.Pending.Hash || r.Day != s.st.LastDay {
		return ErrInvalid
	}
	next := cloneState(s.st)
	next.Acked = r.Generation
	next.Pending = nil
	return s.save(next)
}

// Validate refuses old-day alive lines even if their issuance was authentic.
func (s *Source) Validate(ctx context.Context, snap digestqueue.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	r, err := s.decodeSnapshot(snap)
	if err != nil || r.Generation > s.st.Seq {
		return ErrInvalid
	}
	_, day, err := s.clock(ctx)
	if err != nil {
		return err
	}
	if r.Day != day {
		return ErrStale
	}
	return nil
}
func (s *Source) Health() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken {
		return ErrRecovery
	}
	return nil
}
