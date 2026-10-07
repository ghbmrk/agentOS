package owner

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/digestnotes"
)

const MaxDigestOutbox = 128

var ErrDigestInvalid = errors.New("owner: invalid digest outbox transaction or state")
var ErrDigestMismatch = errors.New("owner: digest source checkpoint does not match retained outbox")
var ErrDigestRecovery = errors.New("owner: digest authority state needs recovery")
var ErrDigestFull = errors.New("owner: digest outbox capacity exhausted")

// DigestOutboxState is private owner-state metadata, never a guest/owner message.
// Its entries commit in the same State replacement as the authority mutation.
type DigestOutboxState struct {
	Schema   int                 `json:"schema"`
	Binding  string              `json:"binding"`
	Produced uint64              `json:"produced"`
	Acked    uint64              `json:"acked"`
	LastHash string              `json:"last_hash,omitempty"`
	Pending  []DigestOutboxEntry `json:"pending,omitempty"`
}
type DigestOutboxEntry struct {
	ID    uint64            `json:"id"`
	Event digestnotes.Event `json:"event"`
}

func copyDigestOutbox(o *DigestOutboxState) *DigestOutboxState {
	if o == nil {
		return nil
	}
	next := *o
	next.Pending = slices.Clone(o.Pending)
	return &next
}
func digestHex(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(s) == 64 && len(b) == 32
}
func validDigestOutbox(o *DigestOutboxState) bool {
	if o == nil || o.Schema != 1 || !digestHex(o.Binding) || o.Acked > o.Produced || len(o.Pending) > MaxDigestOutbox || o.Produced-o.Acked != uint64(len(o.Pending)) {
		return false
	}
	if o.Acked == 0 {
		if o.LastHash != "" {
			return false
		}
	} else if !digestHex(o.LastHash) {
		return false
	}
	for i, p := range o.Pending {
		if p.ID != o.Acked+uint64(i)+1 {
			return false
		}
		if _, err := digestnotes.EventHash(p.Event); err != nil {
			return false
		}
	}
	return true
}
func equalDigestOutbox(a, b *DigestOutboxState) bool {
	return a != nil && b != nil && a.Schema == b.Schema && a.Binding == b.Binding && a.Produced == b.Produced && a.Acked == b.Acked && a.LastHash == b.LastHash && slices.Equal(a.Pending, b.Pending)
}
func matchDigestCheckpoint(o *DigestOutboxState, p digestnotes.ProducerCheckpoint) bool {
	if !validDigestOutbox(o) || p.Binding != o.Binding {
		return false
	}
	if p.Sequence == o.Acked {
		return p.Hash == o.LastHash
	}
	if len(o.Pending) == 0 || p.Sequence != o.Pending[0].ID {
		return false
	}
	hash, err := digestnotes.EventHash(o.Pending[0].Event)
	return err == nil && p.Hash == hash
}

type DigestOutboxConfig struct {
	Store  Store
	Source *digestnotes.Source
}

// DigestOutbox is an opt-in, single-writer transaction coordinator. Do not use
// it concurrently with Channel or another writer sharing this owner Store.
// Handler integration must delegate ALL state mutations to one coordinator.
// No existing Channel, daemon, code verifier or transport enables it here.
type DigestOutbox struct {
	mu     sync.Mutex
	store  Store
	source *digestnotes.Source
	st     State
	broken error
}

func NewDigestOutbox(cfg DigestOutboxConfig) (*DigestOutbox, error) {
	if cfg.Store == nil || cfg.Source == nil {
		return nil, ErrDigestInvalid
	}
	st, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if st.DigestOutbox != nil && !validDigestOutbox(st.DigestOutbox) {
		return nil, ErrDigestInvalid
	}
	checkpoint, err := cfg.Source.ClaimProducer()
	if err != nil {
		return nil, err
	}
	if st.DigestOutbox == nil {
		// Historical source events cannot be paired with an empty authority outbox.
		if checkpoint.Sequence != 0 || checkpoint.Hash != "" {
			return nil, ErrDigestMismatch
		}
		st.DigestOutbox = &DigestOutboxState{Schema: 1, Binding: checkpoint.Binding}
	}
	if !matchDigestCheckpoint(st.DigestOutbox, checkpoint) {
		return nil, ErrDigestMismatch
	}
	o := &DigestOutbox{store: cfg.Store, source: cfg.Source, st: copyState(st)}
	// Re-save observed state before accepting an uncertain prior replacement.
	if err = o.save(st); err != nil {
		return nil, err
	}
	return o, nil
}
func (o *DigestOutbox) save(next State) error {
	if err := o.store.Save(copyState(next)); err != nil {
		o.broken = errors.Join(ErrDigestRecovery, err)
		return o.broken
	}
	o.st = copyState(next)
	return nil
}
func (o *DigestOutbox) State() (State, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.broken != nil {
		return State{}, o.broken
	}
	return copyState(o.st), nil
}
func (o *DigestOutbox) Health() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.broken != nil {
		return o.broken
	}
	return o.source.Health()
}

// Update commits an authority-only mutation while preserving producer metadata.
// Callbacks may mutate only the supplied State; they must have no external effects.
func (o *DigestOutbox) Update(mutate func(*State)) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.broken != nil {
		return o.broken
	}
	if mutate == nil {
		return ErrDigestInvalid
	}
	return o.commit(nil, mutate)
}

// Commit atomically saves a typed guard note and its authority-state mutation.
// A full outbox refuses before invoking the callback, never dropping old entries.
func (o *DigestOutbox) Commit(event digestnotes.Event, mutate func(*State)) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.broken != nil {
		return o.broken
	}
	if _, err := digestnotes.EventHash(event); err != nil {
		return ErrDigestInvalid
	}
	if len(o.st.DigestOutbox.Pending) >= MaxDigestOutbox || o.st.DigestOutbox.Produced == math.MaxUint64 {
		return ErrDigestFull
	}
	if event.WrongAt.IsZero() {
		event.WrongAt = time.Time{}
	} else {
		event.WrongAt = event.WrongAt.Round(0).UTC()
	}
	return o.commit(&event, mutate)
}
func (o *DigestOutbox) commit(event *digestnotes.Event, mutate func(*State)) error {
	next := copyState(o.st)
	if mutate != nil {
		mutate(&next)
	}
	if !equalDigestOutbox(next.DigestOutbox, o.st.DigestOutbox) {
		return ErrDigestInvalid
	}
	if event != nil {
		next.DigestOutbox.Produced++
		next.DigestOutbox.Pending = append(next.DigestOutbox.Pending, DigestOutboxEntry{ID: next.DigestOutbox.Produced, Event: *event})
	}
	return o.save(next)
}
func (o *DigestOutbox) mismatch() error {
	o.broken = errors.Join(ErrDigestRecovery, ErrDigestMismatch)
	return o.broken
}

// Flush replays only retained entries in order, retiring each after the source's
// exact RecordOnce success and a confirmed owner-state save. It does not deliver
// a digest, consume a source snapshot, invoke inference or grant authority.
// Cancellation is checked between synchronous store calls, not during them.
func (o *DigestOutbox) Flush(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.broken != nil {
		return o.broken
	}
	if ctx == nil {
		return ErrDigestInvalid
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		checkpoint, err := o.source.ProducerCheckpoint()
		if err != nil {
			return err
		}
		if !matchDigestCheckpoint(o.st.DigestOutbox, checkpoint) {
			return o.mismatch()
		}
		if len(o.st.DigestOutbox.Pending) == 0 {
			return nil
		}
		event := o.st.DigestOutbox.Pending[0]
		if err = o.source.RecordOnce(event.ID, event.Event); err != nil {
			return err
		}
		confirmed, err := o.source.ProducerCheckpoint()
		if err != nil {
			return err
		}
		hash, _ := digestnotes.EventHash(event.Event)
		if confirmed.Binding != o.st.DigestOutbox.Binding || confirmed.Sequence != event.ID || confirmed.Hash != hash {
			return o.mismatch()
		}
		next := copyState(o.st)
		next.DigestOutbox.Acked = event.ID
		next.DigestOutbox.LastHash = hash
		next.DigestOutbox.Pending = slices.Clone(next.DigestOutbox.Pending[1:])
		if err = o.save(next); err != nil {
			return err
		}
	}
}
