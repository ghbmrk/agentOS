// Package digestqueue persists broker-rendered digest notifications separately
// from the modem bridge's deliberately lossy queue. It is not an executor or a
// generic outbox: no approvals, codes, agent text or third-party actions belong
// here. Caller integration must enforce that boundary.
package digestqueue

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalid        = errors.New("digestqueue: invalid record or policy")
	ErrConflict       = errors.New("digestqueue: association or content conflicts")
	ErrFull           = errors.New("digestqueue: capacity exhausted")
	ErrRecovery       = errors.New("digestqueue: storage outcome uncertain; reopen before use")
	ErrUnacknowledged = errors.New("digestqueue: source acknowledgments incomplete")
	ErrState          = errors.New("digestqueue: transition refused")
	ErrExpired        = errors.New("digestqueue: notification expired")
	ErrRetired        = errors.New("digestqueue: source generation retired")
	ErrInFlight       = errors.New("digestqueue: reference has an unresolved send")
	ErrMissing        = errors.New("digestqueue: no such batch")
)

// Store must atomically replace its state. Successful Save means the replacement
// and its directory entry are durable. Any Save error, including one after rename,
// quarantines this Queue. change.FileStore and change.MemStore satisfy this API.
// A production caller must protect/encrypt private state and provide one writer.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// Limits are explicit deployment policy, persisted and immutable on reopen.
// The test fixture values are not product qualification targets.
type Limits struct {
	MaxBatches  int `json:"max_batches"`
	MaxSources  int `json:"max_sources"`
	MaxAttempts int `json:"max_attempts"`
	MaxBytes    int `json:"max_bytes"`
}

func (l Limits) valid() bool {
	return l.MaxBatches > 0 && l.MaxBatches <= 1024 && l.MaxSources > 0 && l.MaxSources <= 1024 && l.MaxAttempts > 0 && l.MaxAttempts <= 1024 && l.MaxBytes >= 256 && l.MaxBytes <= 32<<20
}

// Snapshot is immutable broker source output. Hash binds the source, generation,
// lines and references. It detects inconsistency; it is not producer authority.
type Snapshot struct {
	Source     string   `json:"source"`
	Generation uint64   `json:"generation"`
	Hash       string   `json:"hash"`
	Lines      []string `json:"lines"`
	References []string `json:"references,omitempty"`
}

var name = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func NewSnapshot(source string, generation uint64, lines, refs []string) (Snapshot, error) {
	s := Snapshot{Source: source, Generation: generation, Lines: slices.Clone(lines), References: slices.Clone(refs)}
	if !s.validContent() {
		return Snapshot{}, ErrInvalid
	}
	s.Hash = s.hash()
	return s, nil
}
func (s Snapshot) validContent() bool {
	if !name.MatchString(s.Source) || s.Generation == 0 || len(s.Lines) == 0 || len(s.Lines) > 64 || len(s.References) > 64 {
		return false
	}
	total := 0
	for _, line := range s.Lines {
		if line == "" || len(line) > 4096 || !utf8.ValidString(line) {
			return false
		}
		total += len(line)
	}
	if total > 64<<10 {
		return false
	}
	seen := map[string]bool{}
	for _, r := range s.References {
		if !name.MatchString(r) || seen[r] {
			return false
		}
		seen[r] = true
	}
	return true
}
func (s Snapshot) hash() string {
	s.Hash = ""
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s Snapshot) valid() bool { return s.validContent() && s.Hash == s.hash() }

type State string

const (
	Ready     State = "ready"
	Sending   State = "sending"
	Accepted  State = "transport-accepted"
	Unknown   State = "delivery-unknown"
	Expired   State = "expired"
	Cancelled State = "cancelled"
	Failed    State = "not-sent-exhausted"
)

type Outcome string

const (
	TransportAccepted Outcome = "transport-accepted"
	OutcomeUnknown    Outcome = "delivery-unknown"
	NotSent           Outcome = "proven-not-sent"
)

// Batch never asserts carrier delivery or owner visibility. Evidence is an opaque
// broker evidence reference, not a receipt parser or authenticated proof.
type Batch struct {
	ID           uint64     `json:"id"`
	Snapshots    []Snapshot `json:"snapshots,omitempty"`
	Acknowledged []bool     `json:"acknowledged,omitempty"`
	Created      time.Time  `json:"created"`
	Expires      time.Time  `json:"expires"`
	State        State      `json:"state"`
	Attempts     int        `json:"attempts"`
	Evidence     string     `json:"evidence,omitempty"`
	Redacted     bool       `json:"redacted,omitempty"`
	// Late marks a held batch the caller re-armed once with Late; the render
	// func sees it and must say the digest is late.
	Late bool `json:"late,omitempty"`
}
type latest struct {
	Generation uint64 `json:"generation"`
	Hash       string `json:"hash"`
	ID         uint64 `json:"id"`
}
type state struct {
	Schema  int               `json:"schema"`
	Policy  Limits            `json:"policy"`
	Seq     uint64            `json:"seq"`
	Batches []Batch           `json:"batches"`
	Latest  map[string]latest `json:"latest"`
}

// Queue serializes collection and transitions within one broker process. The
// Store must not be shared with another Queue/process concurrently.
type Queue struct {
	mu     sync.Mutex
	store  Store
	st     state
	broken bool
}

func New(store Store, limits Limits) (*Queue, error) {
	if store == nil || !limits.valid() {
		return nil, ErrInvalid
	}
	raw, err := store.Load()
	if err != nil {
		return nil, err
	}
	st := state{Schema: 1, Policy: limits, Latest: map[string]latest{}}
	if len(raw) > 0 {
		if len(raw) > limits.MaxBytes {
			return nil, ErrInvalid
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err = d.Decode(&st); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if err = d.Decode(new(any)); err != io.EOF {
			return nil, ErrInvalid
		}
	}
	if err = validate(st, limits); err != nil {
		return nil, err
	}
	q := &Queue{store: store, st: st}
	for i := range q.st.Batches {
		if q.st.Batches[i].State == Sending {
			q.st.Batches[i].State = Unknown
		}
	}
	// Re-save even a ready state: after a prior post-rename error Load may see
	// bytes whose directory entry was not synced. Acknowledgments require a
	// successful durable Save, not merely a successful read.
	if err = q.save(q.st); err != nil {
		return nil, err
	}
	return q, nil
}
func validate(st state, limits Limits) error {
	if st.Schema != 1 || st.Policy != limits || st.Latest == nil || len(st.Batches) > limits.MaxBatches || len(st.Latest) > limits.MaxSources {
		return ErrInvalid
	}
	seen := map[uint64]bool{}
	associations := map[string]bool{}
	for source, l := range st.Latest {
		if !name.MatchString(source) || l.Generation == 0 || l.ID == 0 || l.ID > st.Seq || len(l.Hash) != 64 {
			return ErrInvalid
		}
		if _, err := hex.DecodeString(l.Hash); err != nil {
			return ErrInvalid
		}
	}
	for _, b := range st.Batches {
		if b.ID == 0 || b.ID > st.Seq || seen[b.ID] || b.Created.IsZero() || !b.Expires.After(b.Created) || b.Attempts < 0 || b.Attempts > limits.MaxAttempts || (b.Evidence != "" && !name.MatchString(b.Evidence)) {
			return ErrInvalid
		}
		seen[b.ID] = true
		terminal := b.State == Accepted || b.State == Expired || b.State == Cancelled || b.State == Failed
		if !terminal && b.State != Ready && b.State != Sending && b.State != Unknown {
			return ErrInvalid
		}
		if (b.State == Sending || b.State == Unknown || b.State == Accepted || b.State == Failed) && b.Attempts == 0 {
			return ErrInvalid
		}
		if (b.State == Accepted || b.State == Failed) && b.Evidence == "" {
			return ErrInvalid
		}
		if b.State == Ready && b.Attempts >= limits.MaxAttempts {
			return ErrInvalid
		}
		// Forget redacts an unknown batch whole and keeps its state (W5-Dc-r7).
		if b.Redacted {
			if (!terminal && b.State != Unknown) || len(b.Snapshots) != 0 || len(b.Acknowledged) != 0 {
				return ErrInvalid
			}
			continue
		}
		if len(b.Snapshots) == 0 || len(b.Snapshots) > 16 || len(b.Acknowledged) != len(b.Snapshots) {
			return ErrInvalid
		}
		prior := ""
		for i, s := range b.Snapshots {
			if !s.valid() || s.Source <= prior {
				return ErrInvalid
			}
			prior = s.Source
			l, ok := st.Latest[s.Source]
			if !ok || s.Generation > l.Generation || (s.Generation == l.Generation && s.Hash != l.Hash) {
				return ErrInvalid
			}
			// An expired batch's association may be re-offered in a later batch
			// (DB-6), so only live batches must own their association uniquely.
			if b.State == Expired {
				continue
			}
			if s.Generation == l.Generation && b.ID != l.ID {
				return ErrInvalid
			}
			key := fmt.Sprintf("%s/%d", s.Source, s.Generation)
			if associations[key] {
				return ErrInvalid
			}
			associations[key] = true
			if (b.State == Sending || b.State == Unknown || b.State == Accepted || b.State == Failed) && !b.Acknowledged[i] {
				return ErrInvalid
			}
		}
	}
	return nil
}
func clone[T any](v T) T { b, _ := json.Marshal(v); var out T; _ = json.Unmarshal(b, &out); return out }
func (q *Queue) save(st state) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if len(b) > st.Policy.MaxBytes {
		return ErrFull
	}
	if err = q.store.Save(b); err != nil {
		q.broken = true
		return fmt.Errorf("%w: %v", ErrRecovery, err)
	}
	return nil
}
func (q *Queue) commit(next state) error {
	if err := validate(next, next.Policy); err != nil {
		return err
	}
	if err := q.save(next); err != nil {
		return err
	}
	q.st = next
	return nil
}
func find(st *state, id uint64) (*Batch, error) {
	for i := range st.Batches {
		if st.Batches[i].ID == id {
			return &st.Batches[i], nil
		}
	}
	return nil, ErrMissing
}
func (q *Queue) Get(id uint64) (Batch, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return Batch{}, ErrRecovery
	}
	b, err := find(&q.st, id)
	if err != nil {
		return Batch{}, err
	}
	return clone(*b), nil
}

// List returns owned copies for recovery/source acknowledgment work, never an
// owner-visible delivery claim. The caller must not send these except through (*Sender).Send.
func (q *Queue) List() ([]Batch, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return nil, ErrRecovery
	}
	return clone(q.st.Batches), nil
}

// Enqueue durably admits complete snapshots before callers may acknowledge their
// sources. A repeated exact batch returns its original ID; mixed old/new source
// associations cannot produce another batch. Canonical ordering is broker-owned.
func (q *Queue) Enqueue(snapshots []Snapshot, created, expires time.Time) (Batch, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return Batch{}, ErrRecovery
	}
	if len(snapshots) == 0 || len(snapshots) > 16 || created.IsZero() || !expires.After(created) {
		return Batch{}, ErrInvalid
	}
	ss := clone(snapshots)
	slices.SortFunc(ss, func(a, b Snapshot) int {
		if a.Source < b.Source {
			return -1
		}
		if a.Source > b.Source {
			return 1
		}
		return 0
	})
	for i, s := range ss {
		if !s.valid() || (i > 0 && ss[i-1].Source == s.Source) {
			return Batch{}, ErrInvalid
		}
	}
	body, _ := json.Marshal(ss)
	for _, b := range q.st.Batches {
		if b.Redacted || b.State == Expired {
			continue
		}
		old, _ := json.Marshal(b.Snapshots)
		if bytes.Equal(body, old) {
			if !created.Equal(b.Created) || !expires.Equal(b.Expires) {
				return Batch{}, ErrConflict
			}
			return clone(b), nil
		}
	}
	for _, s := range ss {
		if l, ok := q.st.Latest[s.Source]; ok && s.Generation <= l.Generation {
			if s.Generation == l.Generation && s.Hash == l.Hash {
				b, err := find(&q.st, l.ID)
				if err != nil {
					return Batch{}, ErrRetired
				}
				// An expired batch never reached the owner and its source was
				// never acknowledged: the source re-offers it as a new intent.
				// A forgotten snapshot is gone from that batch and stays refused.
				if b.State == Expired && slices.ContainsFunc(b.Snapshots, func(v Snapshot) bool { return v.Hash == s.Hash }) {
					continue
				}
			}
			return Batch{}, ErrConflict
		}
	}
	next := clone(q.st)
	if len(next.Batches) >= next.Policy.MaxBatches || next.Seq == math.MaxUint64 {
		return Batch{}, ErrFull
	}
	next.Seq++
	b := Batch{ID: next.Seq, Snapshots: ss, Acknowledged: make([]bool, len(ss)), Created: created.UTC(), Expires: expires.UTC(), State: Ready}
	for _, s := range ss {
		next.Latest[s.Source] = latest{Generation: s.Generation, Hash: s.Hash, ID: b.ID}
	}
	if len(next.Latest) > next.Policy.MaxSources {
		return Batch{}, ErrFull
	}
	next.Batches = append(next.Batches, b)
	if err := q.commit(next); err != nil {
		return Batch{}, err
	}
	return clone(b), nil
}

// Acknowledge is called only after a trusted source durably acknowledges this
// exact source/generation/hash. This queue does not itself mutate source state.
func (q *Queue) Acknowledge(id uint64, source string, generation uint64, hash string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return ErrRecovery
	}
	next := clone(q.st)
	b, err := find(&next, id)
	if err != nil {
		return err
	}
	if b.Redacted {
		return ErrState
	}
	for i, s := range b.Snapshots {
		if s.Source == source && s.Generation == generation && s.Hash == hash {
			if b.Acknowledged[i] {
				return nil
			}
			if b.State != Ready {
				return ErrState
			}
			b.Acknowledged[i] = true
			return q.commit(next)
		}
	}
	return ErrConflict
}

// begin persists sending before a transport may be invoked. A crash from here
// cannot prove no text was sent, so reopening quarantines this attempt as unknown.
// Only (*Sender).Send calls it (DB-2); a test pins that.
func (q *Queue) begin(id uint64, now time.Time) (Batch, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return Batch{}, ErrRecovery
	}
	next := clone(q.st)
	b, err := find(&next, id)
	if err != nil {
		return Batch{}, err
	}
	if b.State != Ready || b.Redacted {
		return Batch{}, ErrState
	}
	if now.IsZero() || now.Before(b.Created) {
		return Batch{}, ErrInvalid
	}
	if !now.Before(b.Expires) {
		return Batch{}, ErrExpired
	}
	for _, acked := range b.Acknowledged {
		if !acked {
			return Batch{}, ErrUnacknowledged
		}
	}
	if b.Attempts >= next.Policy.MaxAttempts {
		return Batch{}, ErrState
	}
	b.Attempts++
	b.State = Sending
	b.Evidence = ""
	if err = q.commit(next); err != nil {
		return Batch{}, err
	}
	return clone(*b), nil
}

// finish records a trusted adapter's observation for the current attempt. A
// NotSent result permits bounded retry only with affirmative not-sent evidence;
// timeouts, lost receipts and absence of evidence must be OutcomeUnknown.
// These references do not authenticate evidence; no guest may call this API.
func (q *Queue) finish(id uint64, attempt int, outcome Outcome, evidence string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return ErrRecovery
	}
	next := clone(q.st)
	b, err := find(&next, id)
	if err != nil {
		return err
	}
	// A redacted batch has no text to resend or account for: it stays as it is.
	if (b.State != Sending && b.State != Unknown) || b.Redacted || attempt != b.Attempts {
		return ErrState
	}
	if evidence != "" && !name.MatchString(evidence) {
		return ErrInvalid
	}
	switch outcome {
	case TransportAccepted:
		if evidence == "" {
			return ErrInvalid
		}
		b.State = Accepted
	case OutcomeUnknown:
		b.State = Unknown
	case NotSent:
		if evidence == "" {
			return ErrInvalid
		}
		b.State = Ready
		if b.Attempts >= next.Policy.MaxAttempts {
			b.State = Failed
		}
	default:
		return ErrInvalid
	}
	b.Evidence = evidence
	return q.commit(next)
}

// Expire affects only unsent ready batches whose sources are all unacknowledged.
// A batch with any consumed source stays Ready and is reported by Held, so a
// digest whose lines the sources already gave up is never dropped silently.
// Unknown/in-flight deliveries remain unresolved regardless of expiry and never
// become eligible for automatic retry.
func (q *Queue) Expire(now time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return ErrRecovery
	}
	if now.IsZero() {
		return ErrInvalid
	}
	next := clone(q.st)
	changed := false
	for i := range next.Batches {
		b := &next.Batches[i]
		if b.State == Ready && !now.Before(b.Expires) && !slices.Contains(b.Acknowledged, true) {
			b.State = Expired
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return q.commit(next)
}

// Held lists unsent batches that are past expiry but whose sources were already
// acknowledged. begin refuses them, so they need an owner-visible resolution
// from the caller (Late or Forget); the queue never discards or resends them on
// its own.
func (q *Queue) Held(now time.Time) ([]Batch, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return nil, ErrRecovery
	}
	var out []Batch
	for _, b := range q.st.Batches {
		if b.State == Ready && !b.Redacted && !now.Before(b.Expires) && slices.Contains(b.Acknowledged, true) {
			out = append(out, clone(b))
		}
	}
	return out, nil
}

// Late re-arms a held batch once (DB-4): only a ready batch that Held reports
// at now, with every source acknowledged and not already late. It sets Late and
// the new expiry and persists; begin's expiry check is unchanged, so a late batch
// not sent by its new expiry is held again and cannot be re-armed. The caller
// then resolves it with Forget or an owner-visible notice.
func (q *Queue) Late(id uint64, now, expires time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return ErrRecovery
	}
	if now.IsZero() || !expires.After(now) {
		return ErrInvalid
	}
	next := clone(q.st)
	b, err := find(&next, id)
	if err != nil {
		return err
	}
	if b.State != Ready || b.Redacted || b.Late || now.Before(b.Expires) || slices.Contains(b.Acknowledged, false) {
		return ErrState
	}
	b.Late = true
	b.Expires = expires.UTC()
	return q.commit(next)
}

// Forget purges one reference (DB-5). In a ready (held included) or expired
// batch it removes only the snapshots that carry the reference, with their
// acknowledgment bits; if none remain, a ready batch is cancelled and an expired
// one stays expired, both redacted. Accepted, failed and cancelled batches are
// redacted whole, and so is an unknown batch, which keeps its state, attempts
// and evidence: it is never resent, and the owner may have its text already
// (W5-Dc-r7). Any matching sending batch refuses the whole call before any
// mutation: Send finishes it or a reopen makes it unknown, then ask again.
// The source keeps a duty too: drop the reference and never re-offer it; a
// forgotten generation re-offered is refused with ErrConflict.
// Association hashes remain in bounded private dedupe state until an explicitly
// reviewed reset/migration; they must be covered by private-storage protection.
func (q *Queue) Forget(reference string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return ErrRecovery
	}
	if !name.MatchString(reference) {
		return ErrInvalid
	}
	next := clone(q.st)
	matches := func(s Snapshot) bool { return slices.Contains(s.References, reference) }
	changed := false
	for _, b := range next.Batches {
		if slices.ContainsFunc(b.Snapshots, matches) {
			if b.State == Sending {
				return ErrInFlight
			}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	for i := range next.Batches {
		b := &next.Batches[i]
		if !slices.ContainsFunc(b.Snapshots, matches) {
			continue
		}
		if b.State == Ready || b.State == Expired {
			var ss []Snapshot
			var acked []bool
			for k, s := range b.Snapshots {
				if !matches(s) {
					ss, acked = append(ss, s), append(acked, b.Acknowledged[k])
				}
			}
			b.Snapshots, b.Acknowledged = ss, acked
			if len(ss) > 0 {
				continue
			}
			if b.State == Ready {
				b.State = Cancelled
			}
		}
		b.Snapshots = nil
		b.Acknowledged = nil
		b.Redacted = true
	}
	return q.commit(next)
}

// Compact removes terminal payloads but retains per-source high-water identity
// and the monotonically increasing batch sequence. No unresolved send is removed,
// nor any batch holding a snapshot its source has not acknowledged while the
// ledger still points at it: that association is how a re-offer is admitted or
// refused. An expired batch no ledger entry points at was superseded (DB-6).
func (q *Queue) Compact() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return ErrRecovery
	}
	next := clone(q.st)
	pointed := map[uint64]bool{}
	for _, l := range next.Latest {
		pointed[l.ID] = true
	}
	next.Batches = slices.DeleteFunc(next.Batches, func(b Batch) bool {
		terminal := b.State == Accepted || b.State == Expired || b.State == Cancelled || b.State == Failed
		return terminal && (!slices.Contains(b.Acknowledged, false) || (b.State == Expired && !pointed[b.ID]))
	})
	if len(next.Batches) == len(q.st.Batches) {
		return nil
	}
	return q.commit(next)
}
