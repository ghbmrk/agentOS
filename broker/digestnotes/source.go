// Package digestnotes persists fixed owner-channel guard notices. It holds no
// codes, message bodies, owner authority or transport. Integration is opt-in.
package digestnotes

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
	"io"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
)

var ErrInvalid = errors.New("digestnotes: invalid event, receipt or state")
var ErrRecovery = errors.New("digestnotes: source quarantined; reopen durable state")
var ErrFull = errors.New("digestnotes: representable bound exhausted")

const MaxWrong = 200
const maxStateBytes = 64 << 10

type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}
type Config struct {
	Store    Store
	Location *time.Location
	Rand     io.Reader
}

// Event is broker-owned and count-only. Zero is invalid. WrongAt is a wrong
// local-code timestamp, not the code itself or a message body.
type Event struct {
	Dropped, Silent, Counted, Challenge bool
	WrongAt                             time.Time
}
type Counts struct {
	Dropped   uint64 `json:"dropped"`
	Silent    uint64 `json:"silent"`
	Counted   uint64 `json:"counted"`
	Challenge uint64 `json:"challenge"`
}
type Snapshot struct {
	Schema     int         `json:"schema"`
	Generation uint64      `json:"generation"`
	Hash       string      `json:"hash"`
	Lines      []string    `json:"lines"`
	Counts     Counts      `json:"counts"`
	Wrong      []time.Time `json:"wrong,omitempty"`
	Overflow   uint64      `json:"overflow"`
}
type state struct {
	Schema     int         `json:"schema"`
	Zone       string      `json:"zone"`
	Key        []byte      `json:"key"`
	Seq        uint64      `json:"seq"`
	Acked      uint64      `json:"acked"`
	Counts     Counts      `json:"counts"`
	Wrong      []time.Time `json:"wrong,omitempty"`
	Overflow   uint64      `json:"overflow"`
	Pending    *Snapshot   `json:"pending,omitempty"`
	RecordSeq  uint64      `json:"record_seq,omitempty"`
	RecordHash string      `json:"record_hash,omitempty"`
}
type Source struct {
	mu       sync.Mutex
	store    Store
	location *time.Location
	st       state
	broken   error
}

func cloneSnapshot(s Snapshot) Snapshot {
	s.Lines = slices.Clone(s.Lines)
	s.Wrong = slices.Clone(s.Wrong)
	return s
}
func cloneState(s state) state {
	s.Key = slices.Clone(s.Key)
	s.Wrong = slices.Clone(s.Wrong)
	if s.Pending != nil {
		p := cloneSnapshot(*s.Pending)
		s.Pending = &p
	}
	return s
}
func mac(key []byte, s Snapshot) string {
	s.Hash = ""
	raw, _ := json.Marshal(s)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("agentos/owner/digest/v1\x00"))
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil))
}
func authentic(key []byte, s Snapshot) bool {
	if s.Schema != 1 || s.Generation == 0 || len(s.Hash) != 64 || len(s.Lines) == 0 || len(s.Lines) > 3 || len(s.Wrong) > MaxWrong {
		return false
	}
	for _, line := range s.Lines {
		if line == "" || len(line) > 4096 {
			return false
		}
	}
	for _, at := range s.Wrong {
		if at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
			return false
		}
	}
	a, err := hex.DecodeString(s.Hash)
	if err != nil {
		return false
	}
	b, _ := hex.DecodeString(mac(key, s))
	return hmac.Equal(a, b)
}
func covers(a, b Counts) bool {
	return a.Dropped >= b.Dropped && a.Silent >= b.Silent && a.Counted >= b.Counted && a.Challenge >= b.Challenge
}
func prefix(full, part []time.Time) bool {
	if len(full) < len(part) {
		return false
	}
	for i, at := range part {
		if !full[i].Equal(at) {
			return false
		}
	}
	return true
}
func valid(st state) bool {
	if st.Schema != 1 || st.Zone == "" || len(st.Key) != 32 || st.Acked > st.Seq || len(st.Wrong) > MaxWrong {
		return false
	}
	if st.RecordSeq == 0 {
		if st.RecordHash != "" {
			return false
		}
	} else {
		raw, err := hex.DecodeString(st.RecordHash)
		if err != nil || len(raw) != sha256.Size || len(st.RecordHash) != 64 {
			return false
		}
	}
	for _, at := range st.Wrong {
		if at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
			return false
		}
	}
	if st.Pending == nil {
		return st.Seq == st.Acked
	}
	p := st.Pending
	return st.Acked < st.Seq && p.Generation == st.Seq && authentic(st.Key, *p) && covers(st.Counts, p.Counts) && st.Overflow >= p.Overflow && prefix(st.Wrong, p.Wrong)
}
func New(cfg Config) (*Source, error) {
	if cfg.Store == nil {
		return nil, ErrInvalid
	}
	if cfg.Location == nil {
		cfg.Location = time.UTC
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	raw, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	st := state{Schema: 1, Zone: cfg.Location.String()}
	if len(raw) > 0 {
		if len(raw) > maxStateBytes {
			return nil, ErrInvalid
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err = d.Decode(&st); err != nil {
			return nil, errors.Join(ErrInvalid, err)
		}
		if err = d.Decode(new(any)); err != io.EOF {
			return nil, ErrInvalid
		}
	} else {
		st.Key = make([]byte, 32)
		if _, err = io.ReadFull(cfg.Rand, st.Key); err != nil {
			return nil, err
		}
	}
	if st.Zone != cfg.Location.String() || !valid(st) {
		return nil, ErrInvalid
	}
	s := &Source{store: cfg.Store, location: cfg.Location, st: st}
	// Observing a replacement after a prior error is not durable confirmation.
	// Re-save before this instance may return or acknowledge source content.
	if err = s.commit(st); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Source) commit(next state) error {
	raw, err := json.Marshal(next)
	if err == nil && len(raw) > maxStateBytes {
		err = ErrFull
	}
	if err == nil {
		err = s.store.Save(raw)
	}
	if err != nil {
		s.broken = errors.Join(ErrRecovery, err)
		return s.broken
	}
	s.st = next
	return nil
}
func (s *Source) Health() error { s.mu.Lock(); defer s.mu.Unlock(); return s.broken }
func (s *Source) Record(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	if s.st.RecordSeq != 0 || !validEvent(e) {
		return ErrInvalid
	}
	return s.recordLocked(e, 0, "")
}

func validEvent(e Event) bool {
	if e == (Event{}) {
		return false
	}
	if e.WrongAt.IsZero() {
		return true
	}
	// Local year bounds alone are insufficient: an offset can move the UTC
	// instant across the persisted representation boundary.
	return e.WrongAt.Year() >= 1 && e.WrongAt.Year() <= 9999 && e.WrongAt.UTC().Year() >= 1 && e.WrongAt.UTC().Year() <= 9999
}

// RecordOnce admits one ordered, single-producer event. Only the latest ID
// can be replayed, with identical normalized content; older IDs and gaps are
// rejected. The producer must durably retire each outbox entry before issuing
// the next. IDs are ingestion receipts, never owner or transport authority.
func (s *Source) RecordOnce(id uint64, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	if id == 0 || !validEvent(e) {
		return ErrInvalid
	}
	if !e.WrongAt.IsZero() {
		e.WrongAt = e.WrongAt.Round(0).UTC()
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return ErrInvalid
	}
	sum := sha256.Sum256(append([]byte("agentos/owner/record/v1\x00"), raw...))
	hash := hex.EncodeToString(sum[:])
	if id == s.st.RecordSeq {
		if hash != s.st.RecordHash {
			return ErrInvalid
		}
		return s.commit(cloneState(s.st))
	}
	if s.st.RecordSeq == math.MaxUint64 || id != s.st.RecordSeq+1 {
		return ErrInvalid
	}
	if s.st.RecordSeq == 0 && (s.st.Seq != 0 || s.st.Acked != 0 || s.st.Pending != nil || s.st.Counts != (Counts{}) || len(s.st.Wrong) != 0 || s.st.Overflow != 0) {
		return ErrInvalid
	}
	return s.recordLocked(e, id, hash)
}

func (s *Source) recordLocked(e Event, id uint64, hash string) error {
	next := cloneState(s.st)
	if id != 0 {
		next.RecordSeq, next.RecordHash = id, hash
	}
	for _, entry := range []struct {
		enabled bool
		count   *uint64
	}{{e.Dropped, &next.Counts.Dropped}, {e.Silent, &next.Counts.Silent}, {e.Counted, &next.Counts.Counted}, {e.Challenge, &next.Counts.Challenge}} {
		if entry.enabled {
			if *entry.count == math.MaxUint64 {
				s.broken = errors.Join(ErrRecovery, ErrFull)
				return s.broken
			}
			*entry.count++
		}
	}
	if !e.WrongAt.IsZero() {
		if len(next.Wrong) < MaxWrong {
			next.Wrong = append(next.Wrong, e.WrongAt.Round(0).UTC())
		} else {
			if next.Overflow == math.MaxUint64 {
				s.broken = errors.Join(ErrRecovery, ErrFull)
				return s.broken
			}
			next.Overflow++
		}
	}
	return s.commit(next)
}
func (s *Source) lines(st state) []string {
	var out []string
	if st.Counts.Dropped > 0 {
		out = append(out, fmt.Sprintf("%d code messages without the current challenge were ignored.", st.Counts.Dropped))
	}
	var parts []string
	if st.Counts.Silent > 0 {
		parts = append(parts, fmt.Sprintf("%d texts with a code passed on unchecked", st.Counts.Silent))
	}
	if st.Counts.Counted > 0 {
		parts = append(parts, fmt.Sprintf("%d codes refused at the vault's limit", st.Counts.Counted))
	}
	if st.Counts.Challenge > 0 {
		parts = append(parts, fmt.Sprintf("challenge mode switched on %d times", st.Counts.Challenge))
	}
	if len(parts) > 0 {
		out = append(out, "Possible code flood: "+strings.Join(parts, ", ")+".")
	}
	if len(st.Wrong) > 0 || st.Overflow > 0 {
		var times []string
		for i, at := range st.Wrong {
			if i == 20 {
				times = append(times, fmt.Sprintf("and %d more", len(st.Wrong)-20))
				break
			}
			times = append(times, at.In(s.location).Format("15:04"))
		}
		line := fmt.Sprintf("%d wrong codes entered on the box's Wi-Fi", len(st.Wrong))
		if len(times) > 0 {
			line += ": " + strings.Join(times, ", ")
		}
		if st.Overflow > 0 {
			line += fmt.Sprintf("; %d additional wrong tries not individually listed", st.Overflow)
		}
		out = append(out, line+".")
	}
	return out
}
func (s *Source) Peek(ctx context.Context) (*Snapshot, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.broken != nil {
		return nil, s.broken
	}
	next := cloneState(s.st)
	if next.Pending == nil {
		lines := s.lines(next)
		if len(lines) == 0 {
			return nil, nil
		}
		if next.Seq == math.MaxUint64 {
			s.broken = errors.Join(ErrRecovery, ErrFull)
			return nil, s.broken
		}
		next.Seq++
		p := Snapshot{Schema: 1, Generation: next.Seq, Lines: lines, Counts: next.Counts, Wrong: slices.Clone(next.Wrong), Overflow: next.Overflow}
		p.Hash = mac(next.Key, p)
		next.Pending = &p
	}
	if err := s.commit(next); err != nil {
		return nil, err
	}
	p := cloneSnapshot(*s.st.Pending)
	return &p, nil
}
func (s *Source) check(p Snapshot) error {
	if s.broken != nil {
		return s.broken
	}
	if !authentic(s.st.Key, p) || p.Generation > s.st.Seq {
		return ErrInvalid
	}
	if p.Generation <= s.st.Acked {
		return nil
	}
	if s.st.Pending == nil || s.st.Pending.Hash != p.Hash {
		return ErrInvalid
	}
	return nil
}

// Validate proves local issuance and receipt eligibility. It is not send
// authority, delivery evidence, producer isolation or a complete forget check.
func (s *Source) Validate(p Snapshot) error { s.mu.Lock(); defer s.mu.Unlock(); return s.check(p) }
func (s *Source) Ack(ctx context.Context, p Snapshot) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.check(p); err != nil {
		return err
	}
	next := cloneState(s.st)
	if p.Generation > next.Acked {
		if !covers(next.Counts, p.Counts) || next.Overflow < p.Overflow || !prefix(next.Wrong, p.Wrong) {
			return ErrInvalid
		}
		next.Counts.Dropped -= p.Counts.Dropped
		next.Counts.Silent -= p.Counts.Silent
		next.Counts.Counted -= p.Counts.Counted
		next.Counts.Challenge -= p.Counts.Challenge
		next.Wrong = slices.Clone(next.Wrong[len(p.Wrong):])
		next.Overflow -= p.Overflow
		next.Acked = p.Generation
		next.Pending = nil
	}
	// Repeated old acknowledgments also require successful durable persistence.
	return s.commit(next)
}
