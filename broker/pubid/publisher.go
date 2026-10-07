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
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
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
	// maxDays is how many counted days the outbox remembers, newest by
	// date, so no day counts twice (or gets two batches) unless the clock
	// falls behind further than that.
	maxDays = 400
	// minCountGap is the least monotonic time between two counted days in
	// one process, so a clock moved on cannot count days faster than they
	// pass while the broker runs.
	minCountGap = 20 * time.Hour
	// maxStep is the most days a step may move on, so a box off for up to
	// maxStep-1 days in a row keeps counting. A larger move is a jump.
	maxStep = 3
)

// ErrFull means MaxQueue items are already waiting.
var ErrFull = errors.New("pubid: publication queue full")

// ErrClock means the clock is before the public reference or too far
// ahead to trust, so nothing is queued (plausible).
var ErrClock = errors.New("pubid: the clock is not plausible")

// Signer signs one payload of its kind with the epoch's key, returning
// the bytes to publish.
type Signer func(priv ed25519.PrivateKey, payload []byte) ([]byte, error)

// Sender publishes one day's batch. It must be idempotent by day and
// batch: after a crash or an error that came after delivery, the same
// batch for the same day is sent again. A different batch for a day
// already published (a clock behind by more than maxDays) is new, never a
// duplicate (security N1 on #163).
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
	// Mono is monotonic time since some fixed point; nil means
	// CLOCK_BOOTTIME, which counts suspend (Go's monotonic clock off Linux).
	Mono func() time.Duration
	// BootID names the boot. Nil reads /proc/sys/kernel/random/boot_id.
	// Empty means unknown: a stored floor is ignored, because a reading
	// from another boot is not comparable.
	BootID func() string
}

type item struct {
	Kind    string `json:"kind"`
	Payload []byte `json:"payload"`
	// Wait is how many more counted days the item waits; it leaves on the
	// day that brings it to zero.
	Wait int `json:"wait"`
}

type formed struct {
	Day   string   `json:"day"`
	Batch [][]byte `json:"batch"`
}

// The clock model (DECISIONS.md, OSS-6 clock; L3 rounds 4 and 5 on #163).
// The wall clock is the only time the box keeps across restarts, and it
// can be wrong by any amount either way and change at any moment (a
// reboot, NTP), so no item carries a date; each stores how many counted
// days it still waits. A release with a plausible clock, after the release
// time, counts its day once it steps: it moves on from the day the last
// release saw by one to maxStep days. It counts only if that last release
// had itself stepped, the day was never counted, and at least minCountGap
// of monotonic time has passed since the last count on this boot. The
// outbox stores that reading and the boot id, so a broker restart on the
// same boot keeps the floor (OSS-6e). A stored reading ahead of the clock
// is corrupt and counts no day. Another boot id is ignored. A step back or
// a larger move is a jump, and the release after a jump never counts. A
// batch forms only on a counted day. Hence:
//
//   - G1: within one boot an item with delay k leaves no sooner than
//     (k-1)*20h after it was queued, whatever the clock does; with a right
//     clock, no sooner than k-1 days and the release time.
//   - G2: a new boot ignores the stored reading, so each boot can let one
//     day count without real time passing, if someone controls the clock:
//     (k-1-r)*20h for r boots. A broker restart on the same boot cannot.
//   - G3: off days only lengthen waits. A box off for up to maxStep-1 days
//     in a row keeps counting; after longer, the first two days it sees
//     do not count.
//   - G4: no remembered day gets two batches, and no date can freeze the
//     outbox.
//
// TestOSS6ClockModel checks G1, G2 and G4 over random clocks.
type outbox struct {
	Items []item `json:"items"`
	// Days are the counted days, newest maxDays by date.
	Days []string `json:"days"`
	Seen string   `json:"seen,omitempty"` // the day the last release saw
	// Stepped: the release that saw Seen saw it follow the day before it
	// saw, by one to maxStep days.
	Stepped bool    `json:"stepped,omitempty"`
	Pending *formed `json:"pending,omitempty"` // formed, not confirmed sent
	// Counted is set once a day has been counted on Boot. CountAt is that
	// reading of Mono (CLOCK_BOOTTIME in production), in nanoseconds.
	Counted bool   `json:"counted,omitempty"`
	CountAt int64  `json:"count_at,omitempty"`
	Boot    string `json:"boot,omitempty"`
}

// Publisher holds public output until its day and publishes each day's
// due items as one sorted batch at the release time (OSS-6).
type Publisher struct {
	cfg Config
	mu  sync.Mutex
	st  outbox
	// counted is the monotonic time of the last day counted on this boot.
	counted    time.Duration
	hasCounted bool
	// floorCorrupt: the stored reading is ahead of the clock. No day counts
	// until the clock passes it.
	floorCorrupt bool
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
	if cfg.Mono == nil {
		cfg.Mono = monoClock()
	}
	if cfg.BootID == nil {
		cfg.BootID = readBootID
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
		if dropped {
			if err := p.save(); err != nil {
				return nil, err
			}
		}
	}
	p.restoreFloor()
	return p, nil
}

// restoreFloor keeps the 20h floor across a broker restart on the same
// boot. A different boot id is not comparable and is ignored. A stored
// reading ahead of the clock counts no day until the clock passes it.
func (p *Publisher) restoreFloor() {
	if !p.st.Counted {
		return
	}
	boot := p.cfg.BootID()
	if boot == "" || boot != p.st.Boot {
		return
	}
	stored := time.Duration(p.st.CountAt)
	if stored > p.cfg.Mono() {
		p.floorCorrupt = true
		return
	}
	p.counted, p.hasCounted = stored, true
}

// floorShut reports that this release must not count a day.
func (p *Publisher) floorShut() bool {
	now := p.cfg.Mono()
	if p.floorCorrupt {
		if now < time.Duration(p.st.CountAt) {
			return true
		}
		p.floorCorrupt = false
		p.counted, p.hasCounted = time.Duration(p.st.CountAt), true
	}
	return p.hasCounted && now-p.counted < minCountGap
}

func readBootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if s == "" || len(s) > 64 || strings.ContainsAny(s, "\n\r") {
		return ""
	}
	return s
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
			return false, errors.New("bad counted day")
		}
	}
	if p.st.Seen != "" && !isDay(p.st.Seen) {
		return false, errors.New("bad seen day")
	}
	if f := p.st.Pending; f != nil && (!isDay(f.Day) || len(f.Batch) == 0) {
		return false, errors.New("bad pending batch")
	}
	var keep []item
	for _, it := range p.st.Items {
		if it.Wait < 1 || it.Wait > maxWait || len(it.Payload) == 0 || len(it.Payload) > MaxPayload {
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

// plausible: the clock is on or after the public reference and its date
// has a four-digit year. A clock outside that (unset before NTP, or set
// absurdly far ahead) neither queues nor counts (L3 round 2 on #163).
func plausible(now time.Time) bool {
	return !now.Before(Reference) && now.Year() <= 9999
}

// maxWait bounds an item's wait: the largest delay, plus the day it came.
const maxWait = 256

// draw picks an item's delay, 1 to MaxDelayDays counted days.
func (p *Publisher) draw() (int, error) {
	var r [1]byte
	if _, err := io.ReadFull(p.cfg.Rand, r[:]); err != nil {
		return 0, err
	}
	return 1 + int(r[0])%p.cfg.MaxDelayDays, nil
}

// step reports whether today follows the day the last release saw by one
// to maxStep days.
func (p *Publisher) step(today string) bool {
	t, _ := time.Parse("2006-01-02", p.st.Seen)
	for n := 1; n <= maxStep; n++ {
		if day(t.AddDate(0, 0, n)) == today {
			return true
		}
	}
	return false
}

// checkDir refuses a directory that is a symlink, belongs to another
// user, or others can write: any of these lets someone else swap the
// files in it (L3 round 4 on #163).
func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok || int(st.Uid) != os.Geteuid():
		return fmt.Errorf("pubid: %s belongs to another user", dir)
	case fi.Mode().Perm()&0o022 != 0:
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
// the 1st to MaxDelayDays'th counted day after today, drawn now. A refusal never echoes
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
	if !plausible(now) {
		return ErrClock
	}
	if len(p.st.Items) >= MaxQueue {
		return ErrFull
	}
	wait, err := p.draw()
	if err != nil {
		return err
	}
	// Unless a release already counted today, the next counted day may be
	// today itself, which must not count for the item.
	if t := day(now); t != p.st.Seen || !slices.Contains(p.st.Days, t) {
		wait++
	}
	p.st.Items = append(p.st.Items, item{Kind: kind, Payload: append([]byte(nil), payload...), Wait: wait})
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

// Release publishes today's batch once the release time has passed, if
// today counts (the clock model above): every item whose wait it ends,
// signed now with the epoch's key, sorted by its signed bytes. A clock
// that is not plausible publishes nothing. An item that fails to sign is
// dropped, so it cannot hold the others back; the error says how many. A
// batch formed earlier and not confirmed is resent unchanged, for its own
// day, and no new batch is formed in that call. Only a fixed broker timer
// may call it, hourly or so, so no day is missed (G3): when it runs is
// when the batch leaves.
func (p *Publisher) Release() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Now().UTC()
	today := day(now)
	if now.Sub(now.Truncate(24*time.Hour)) < p.cfg.ReleaseAt || !plausible(now) {
		return nil
	}
	if p.st.Pending != nil {
		return p.send()
	}
	if today == p.st.Seen {
		return nil // nothing new, and no write on every tick of the timer
	}
	old := p.st
	step := p.step(today)
	if step && p.st.Stepped && !slices.Contains(p.st.Days, today) {
		// Today counts, once enough monotonic time has passed on this boot;
		// until then it is not seen, so a later tick can count it.
		if p.floorShut() {
			return nil
		}
	} else {
		p.st.Seen, p.st.Stepped = today, step
		if err := p.save(); err != nil {
			p.st = old
			return err
		}
		return nil
	}
	var due, rest []item
	for _, it := range p.st.Items {
		if it.Wait--; it.Wait == 0 {
			due = append(due, it)
		} else {
			rest = append(rest, it)
		}
	}
	var batch [][]byte
	failed := 0
	if len(due) > 0 {
		priv, _, err := p.cfg.Identity.Key()
		if err != nil {
			return err
		}
		for _, it := range due {
			b, err := p.cfg.Signers[it.Kind](priv, it.Payload)
			if err != nil {
				failed++
				continue
			}
			batch = append(batch, b)
		}
		clear(priv)
	}
	var ferr error
	if failed > 0 {
		// The signer's error may quote the payload, so it is not passed on.
		ferr = fmt.Errorf("pubid: %d items could not be signed and were dropped", failed)
	}
	sort.Slice(batch, func(i, j int) bool { return bytes.Compare(batch[i], batch[j]) < 0 })
	p.st.Items, p.st.Seen, p.st.Stepped = rest, today, true
	p.st.Days = trim(append(slices.Clone(p.st.Days), today))
	if len(batch) > 0 {
		p.st.Pending = &formed{Day: today, Batch: batch}
	}
	mono := p.cfg.Mono()
	p.st.Counted, p.st.CountAt, p.st.Boot = true, int64(mono), p.cfg.BootID()
	if err := p.save(); err != nil {
		p.st = old
		return err
	}
	p.counted, p.hasCounted = mono, true
	p.floorCorrupt = false
	if len(batch) == 0 {
		return ferr
	}
	return errors.Join(p.send(), ferr)
}

// send publishes the pending batch; once the sender accepts it, the batch
// is done.
func (p *Publisher) send() error {
	f := p.st.Pending
	if err := p.cfg.Sender.Publish(f.Day, f.Batch); err != nil {
		return fmt.Errorf("pubid: publishing %s: %w", f.Day, err)
	}
	p.st.Pending = nil
	return p.save()
}

// trim keeps the newest maxDays days by date. A clock that ran ahead
// leaves the days it counted at the top, which the true clock reaches
// later; what drops out is the oldest, which only a clock behind by more
// than the remembered span reaches again.
func trim(days []string) []string {
	sort.Strings(days)
	return days[max(0, len(days)-maxDays):]
}

func (p *Publisher) save() error {
	b, err := json.Marshal(p.st)
	if err != nil {
		return err
	}
	return writeAtomic(p.cfg.Path, b)
}
