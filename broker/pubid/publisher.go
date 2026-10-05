package pubid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	// DefaultReleaseAt is the UTC time of day after which the day's batch
	// is published (Config.ReleaseAt zero). It is an hour after the hint
	// emitter's, so a day's hints and a day's publications never leave
	// together.
	DefaultReleaseAt = 5 * time.Hour
	// DefaultMaxDelayDays is how many whole days an item may wait beyond
	// the day it was queued (Config.MaxDelayDays zero): each waits 1 to
	// this many days, drawn when it is queued.
	DefaultMaxDelayDays = 3
	// MaxQueue bounds the items waiting.
	MaxQueue = 256
	// MaxPayload bounds one item's bytes before signing.
	MaxPayload = 1 << 20
	// maxSkewDays: a published day more than this far ahead of the clock
	// came from a clock that was wrong, not one stepped back a little, so
	// it no longer holds publication back (L3 on #163).
	maxSkewDays = 28
)

// ErrFull means MaxQueue items are already waiting.
var ErrFull = errors.New("pubid: publication queue full")

// Signer signs one payload of its kind with the epoch's key, returning
// the bytes to publish.
type Signer func(priv ed25519.PrivateKey, payload []byte) ([]byte, error)

// Sender publishes one day's batch. It must be idempotent by day: after a
// crash or an error that came after delivery, the same batch for the same
// day is sent again.
type Sender interface {
	Publish(day string, batch [][]byte) error
}

// Config sets up a Publisher.
type Config struct {
	Path     string            // the outbox state file
	Identity *Identity         // signs every item
	Signers  map[string]Signer // by kind; a kind with no signer is refused
	Sender   Sender
	Now      func() time.Time // nil means time.Now
	// ReleaseAt is the UTC time of day after which due items leave (0
	// means DefaultReleaseAt).
	ReleaseAt time.Duration
	// MaxDelayDays (0 means DefaultMaxDelayDays).
	MaxDelayDays int
	Rand         io.Reader // delay draws; nil means crypto/rand
}

type item struct {
	Kind    string `json:"kind"`
	Payload []byte `json:"payload"`
	Due     string `json:"due"` // UTC day it may leave
}

type formed struct {
	Day   string   `json:"day"`
	Batch [][]byte `json:"batch"`
}

type outbox struct {
	Items   []item  `json:"items"`
	Last    string  `json:"last"`              // newest day a batch was published for
	Pending *formed `json:"pending,omitempty"` // formed, not confirmed sent
}

// Publisher holds public output until its day and publishes each day's
// due items as one sorted batch at the release time (OSS-6).
type Publisher struct {
	cfg Config
	mu  sync.Mutex
	st  outbox
}

// NewPublisher opens the outbox at cfg.Path.
func NewPublisher(cfg Config) (*Publisher, error) {
	if cfg.Path == "" || cfg.Identity == nil || cfg.Sender == nil || len(cfg.Signers) == 0 {
		return nil, errors.New("pubid: path, identity, sender and signers are required")
	}
	signers := make(map[string]Signer, len(cfg.Signers))
	for k, s := range cfg.Signers {
		if s == nil || k == "" {
			return nil, fmt.Errorf("pubid: kind %q has no signer", k)
		}
		signers[k] = s
	}
	cfg.Signers = signers
	if cfg.ReleaseAt == 0 {
		cfg.ReleaseAt = DefaultReleaseAt
	}
	if cfg.ReleaseAt < 0 || cfg.ReleaseAt >= 24*time.Hour {
		return nil, fmt.Errorf("pubid: release time %v is not a time of day", cfg.ReleaseAt)
	}
	if cfg.MaxDelayDays == 0 {
		cfg.MaxDelayDays = DefaultMaxDelayDays
	}
	if cfg.MaxDelayDays < 1 || cfg.MaxDelayDays > 255 {
		return nil, fmt.Errorf("pubid: delay of %d days", cfg.MaxDelayDays)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	p := &Publisher{cfg: cfg}
	b, err := os.ReadFile(cfg.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err := d.Decode(&p.st); err != nil {
			return nil, fmt.Errorf("pubid: outbox %s: %w", cfg.Path, err)
		}
		dropped, err := p.validate()
		if err != nil {
			return nil, fmt.Errorf("pubid: outbox %s: %w", cfg.Path, err)
		}
		if dropped {
			if err := p.save(); err != nil {
				return nil, err
			}
		}
	}
	return p, nil
}

// validate checks a loaded outbox and drops items of a kind with no signer
// (a kind no longer published), reporting whether it dropped any. Anything
// else malformed refuses the outbox rather than crash at release.
func (p *Publisher) validate() (bool, error) {
	if len(p.st.Items) > MaxQueue {
		return false, fmt.Errorf("%d items", len(p.st.Items))
	}
	if p.st.Last != "" && !isDay(p.st.Last) {
		return false, errors.New("bad last day")
	}
	if f := p.st.Pending; f != nil && (!isDay(f.Day) || len(f.Batch) == 0) {
		return false, errors.New("bad pending batch")
	}
	var keep []item
	for _, it := range p.st.Items {
		if !isDay(it.Due) || len(it.Payload) == 0 || len(it.Payload) > MaxPayload {
			return false, errors.New("bad item")
		}
		if p.cfg.Signers[it.Kind] != nil {
			keep = append(keep, it)
		}
	}
	dropped := len(keep) != len(p.st.Items)
	p.st.Items = keep
	return dropped, nil
}

func isDay(s string) bool {
	t, err := time.Parse("2006-01-02", s)
	return err == nil && day(t) == s
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// Queue holds payload for publication as kind. It leaves in the batch of
// a day 1 to MaxDelayDays after today, drawn now. A refusal never echoes
// the payload.
func (p *Publisher) Queue(kind string, payload []byte) error {
	if p.cfg.Signers[kind] == nil {
		return errors.New("pubid: unknown kind")
	}
	if len(payload) == 0 || len(payload) > MaxPayload {
		return fmt.Errorf("pubid: payload of %d bytes", len(payload))
	}
	var r [1]byte
	if _, err := io.ReadFull(p.cfg.Rand, r[:]); err != nil {
		return err
	}
	delay := 1 + int(r[0])%p.cfg.MaxDelayDays
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.st.Items) >= MaxQueue {
		return ErrFull
	}
	due := day(p.cfg.Now().UTC().AddDate(0, 0, delay))
	p.st.Items = append(p.st.Items, item{Kind: kind, Payload: append([]byte(nil), payload...), Due: due})
	if err := p.save(); err != nil {
		p.st.Items = p.st.Items[:len(p.st.Items)-1]
		return err
	}
	return nil
}

// Clear discards every item not yet published, and a formed batch whose
// delivery was not confirmed, so turning sharing off stops what is already
// queued (UX on #163). It returns how many items were discarded. A batch
// the sender accepted before an error may already be out; nothing can
// recall that.
func (p *Publisher) Clear() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	old := p.st
	n := len(p.st.Items)
	if p.st.Pending != nil {
		n += len(p.st.Pending.Batch)
	}
	p.st.Items, p.st.Pending = nil, nil
	if err := p.save(); err != nil {
		p.st = old
		return 0, err
	}
	return n, nil
}

// Len is how many items wait.
func (p *Publisher) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.st.Items)
}

// Release publishes today's batch once the release time has passed: every
// due item, signed now with the epoch's key, sorted by its signed bytes.
// At most one batch a day, and none while the clock is behind the last
// published day, unless that day is over maxSkewDays ahead (a clock that
// was wrong). An item that fails to sign is dropped, so it cannot hold the
// others back; the error says how many. A batch formed earlier and not
// confirmed is resent unchanged, for its own day, and no new batch is
// formed in that call. Only a fixed broker timer may call it: when it runs
// is when the batch leaves.
func (p *Publisher) Release() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Now().UTC()
	today := day(now)
	if now.Sub(now.Truncate(24*time.Hour)) < p.cfg.ReleaseAt ||
		(today <= p.st.Last && p.st.Last <= day(now.AddDate(0, 0, maxSkewDays))) {
		return nil
	}
	if p.st.Pending != nil {
		return p.send()
	}
	var due, rest []item
	for _, it := range p.st.Items {
		if it.Due <= today {
			due = append(due, it)
		} else {
			rest = append(rest, it)
		}
	}
	if len(due) == 0 {
		return nil
	}
	priv, _, err := p.cfg.Identity.Key()
	if err != nil {
		return err
	}
	batch := make([][]byte, 0, len(due))
	failed := 0
	for _, it := range due {
		b, err := p.cfg.Signers[it.Kind](priv, it.Payload)
		if err != nil {
			failed++
			continue
		}
		batch = append(batch, b)
	}
	clear(priv)
	var ferr error
	if failed > 0 {
		// The signer's error may quote the payload, so it is not passed on.
		ferr = fmt.Errorf("pubid: %d items could not be signed and were dropped", failed)
	}
	sort.Slice(batch, func(i, j int) bool { return bytes.Compare(batch[i], batch[j]) < 0 })
	old := p.st
	p.st.Items = rest
	if len(batch) > 0 {
		p.st.Pending = &formed{Day: today, Batch: batch}
	}
	if err := p.save(); err != nil {
		p.st = old
		return err
	}
	if len(batch) == 0 {
		return ferr
	}
	return errors.Join(p.send(), ferr)
}

// send publishes the pending batch and, once the sender accepts it,
// records its day as published.
func (p *Publisher) send() error {
	f := p.st.Pending
	if err := p.cfg.Sender.Publish(f.Day, f.Batch); err != nil {
		return fmt.Errorf("pubid: publishing %s: %w", f.Day, err)
	}
	// A pending batch was formed on or after the last published day.
	p.st.Pending, p.st.Last = nil, f.Day
	return p.save()
}

func (p *Publisher) save() error {
	b, err := json.Marshal(p.st)
	if err != nil {
		return err
	}
	return writeAtomic(p.cfg.Path, b)
}
