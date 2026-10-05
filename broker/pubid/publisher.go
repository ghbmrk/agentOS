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
	"path/filepath"
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
	// maxDays is how many published days the outbox remembers, so no day
	// is published twice even after a wrong clock is corrected.
	maxDays = 64
	// maxEnds bounds the days trim keeps from before clock jumps.
	maxEnds = 8
	// redrawAfterDays: an item due more than this many days after today
	// was queued under a clock that was wrong, far beyond any plausible
	// clock error (a clock kept in local time, a step back of days), so it
	// gets a new draw. Smaller would let a clock behind pull a correct due
	// day in and lose the delay (L3 round 3 on #163).
	redrawAfterDays = 28
)

// ErrFull means MaxQueue items are already waiting.
var ErrFull = errors.New("pubid: publication queue full")

// ErrClock means the clock is before the public reference or too far
// ahead to trust, so nothing is queued (plausible).
var ErrClock = errors.New("pubid: the clock is not plausible")

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
	Items []item `json:"items"`
	// Days are the days batches were published for, newest maxDays.
	Days    []string `json:"days"`
	Pending *formed  `json:"pending,omitempty"` // formed, not confirmed sent
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
	// Others who can write the directory could swap in items for the box
	// to sign (L3 round 3 on #163).
	if err := checkDir(filepath.Dir(cfg.Path)); err != nil {
		return nil, err
	}
	if err := sweepTemp(filepath.Dir(cfg.Path)); err != nil {
		return nil, err
	}
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
		// No redraw here: a load runs just after boot, maybe before the
		// clock is right (L3 round 3 on #163).
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
	if len(p.st.Days) > maxDays {
		return false, fmt.Errorf("%d days", len(p.st.Days))
	}
	for _, d := range p.st.Days {
		if !isDay(d) {
			return false, errors.New("bad published day")
		}
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

// plausible: the clock is on or after the public reference, and a full
// delay from now still has a four-digit year. A clock outside that (unset
// before NTP, or set absurdly far ahead) neither queues nor publishes
// (L3 round 2 on #163).
func (p *Publisher) plausible(now time.Time) bool {
	return !now.Before(Reference) && now.AddDate(0, 0, p.cfg.MaxDelayDays+1).Year() <= 9999
}

// last is the newest published day no further ahead of today than an item
// can wait: a later one came from a clock that was wrong, and holding
// publication back for it would freeze the outbox (L3 MUST 1 on #163).
func (p *Publisher) last(today time.Time) string {
	limit := day(today.AddDate(0, 0, p.cfg.MaxDelayDays+1))
	l := ""
	for _, d := range p.st.Days {
		if d > l && d <= limit {
			l = d
		}
	}
	return l
}

// draw picks an item's leaving day: 1 to MaxDelayDays days after the
// later of today and the last published day, so a clock behind the last
// batch cannot shorten the delay.
func (p *Publisher) draw(now time.Time) (string, error) {
	var r [1]byte
	if _, err := io.ReadFull(p.cfg.Rand, r[:]); err != nil {
		return "", err
	}
	base := now.UTC()
	if l := p.last(base); l > day(base) {
		base, _ = time.Parse("2006-01-02", l)
	}
	return day(base.AddDate(0, 0, 1+int(r[0])%p.cfg.MaxDelayDays)), nil
}

// redraw gives a new leaving day to every item due more than
// redrawAfterDays after today, as one queued under a clock far ahead
// would be; otherwise it would never leave, or fill the queue for good
// (L3 round 2 on #163). Only Release calls it, with a plausible clock past
// the last published day.
func (p *Publisher) redraw(now time.Time) error {
	limit := day(now.AddDate(0, 0, redrawAfterDays))
	for i := range p.st.Items {
		if p.st.Items[i].Due <= limit {
			continue
		}
		d, err := p.draw(now)
		if err != nil {
			return err
		}
		p.st.Items[i].Due = d
	}
	return nil
}

// checkDir refuses a directory others can write.
func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("pubid: %s is writable by others", dir)
	}
	return nil
}

// sweepTemp removes temporary files a crash left in dir. The identity and
// the outbox belong to one broker process, which opens each once at start,
// so no other writer's temporary file is in flight then.
func sweepTemp(dir string) error {
	names, err := filepath.Glob(filepath.Join(dir, ".pubid-*"))
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := os.Remove(n); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
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
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Now().UTC()
	if !p.plausible(now) {
		return ErrClock
	}
	if len(p.st.Items) >= MaxQueue {
		return ErrFull
	}
	due, err := p.draw(now)
	if err != nil {
		return err
	}
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
// At most one batch a day: none on or behind the last plausible published
// day, so no day is published twice. Items due
// further ahead than an item can wait are redrawn first. A clock that is
// not plausible publishes nothing. An item that fails to sign is dropped, so it cannot hold the
// others back; the error says how many. A batch formed earlier and not
// confirmed is resent unchanged, for its own day, and no new batch is
// formed in that call. Only a fixed broker timer may call it: when it runs
// is when the batch leaves.
func (p *Publisher) Release() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Now().UTC()
	today := day(now)
	if now.Sub(now.Truncate(24*time.Hour)) < p.cfg.ReleaseAt || !p.plausible(now) {
		return nil
	}
	if p.st.Pending != nil {
		return p.send()
	}
	if today <= p.last(now) {
		return nil
	}
	// Saved with the batch below; if none forms, the next release redraws again.
	if err := p.redraw(now); err != nil {
		return err
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
	p.st.Pending, p.st.Days = nil, p.trim(append(p.st.Days, f.Day))
	return p.save()
}

// trim keeps at most maxDays published days: the newest day before each
// jump of more than redrawAfterDays (the true newest day when a clock was
// far ahead, so it is never pushed out and never published again; the
// newest maxEnds such days), then the newest of the rest (L3 round 3 on
// #163).
func (p *Publisher) trim(days []string) []string {
	sort.Strings(days)
	var ends []string
	for i, d := range days {
		if i == len(days)-1 || gap(d, days[i+1]) > redrawAfterDays {
			ends = append(ends, d)
		}
	}
	if len(ends) > maxEnds {
		ends = ends[len(ends)-maxEnds:]
	}
	keep := map[string]bool{}
	for _, d := range ends {
		keep[d] = true
	}
	for i := len(days) - 1; i >= 0 && len(keep) < maxDays; i-- {
		keep[days[i]] = true
	}
	out := days[:0]
	for _, d := range days {
		if keep[d] {
			out = append(out, d)
		}
	}
	return out
}

// gap is how many days b is after a (both valid days).
func gap(a, b string) int {
	ta, _ := time.Parse("2006-01-02", a)
	tb, _ := time.Parse("2006-01-02", b)
	return int(tb.Sub(ta) / (24 * time.Hour))
}

func (p *Publisher) save() error {
	b, err := json.Marshal(p.st)
	if err != nil {
		return err
	}
	return writeAtomic(p.cfg.Path, b)
}
