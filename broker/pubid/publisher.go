package pubid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
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
	// Slots and SlotSize shape the daily batch (Q2, Mark 2026-10-08 on
	// #325): every counted day sends one frame of Slots × SlotSize bytes
	// (1 MiB), whatever it carries. They are image constants, so an update
	// can change them (OSS-6m).
	Slots    = 16
	SlotSize = 64 << 10
	// SignerOverhead bounds what a Signer may add to a payload. A signed
	// item longer than its payload plus this is refused at release, like
	// one that fails to sign.
	SignerOverhead = 1024
	// itemHeader is the item's length in the batch.
	itemHeader = 4
	// ItemOverhead bounds the bytes an item takes in a batch beyond its
	// payload: its signer's additions and its length header.
	ItemOverhead = SignerOverhead + itemHeader
	// batchHeader: magic, version, day, key and item count.
	batchHeader = len(batchMagic) + 1 + 10 + ed25519.PublicKeySize + 2
	// BatchOverhead is the batch envelope and its signature: a zero-item
	// cover batch is exactly this long.
	BatchOverhead = batchHeader + ed25519.SignatureSize
	// UsableSlots (C) is the slots items can use: Slots less those the
	// batch overhead takes.
	UsableSlots = Slots - (BatchOverhead+SlotSize-1)/SlotSize
	// MaxItemSlots (m) is the slots a MaxPayload item takes. The smaller
	// it is, the shorter the worst wait under overload, ceil(B/(C−m+1))
	// counted days (OSS-6s-a3); 4 keeps a 256 KiB item.
	MaxItemSlots = 4
	// MaxPayload bounds one item's bytes before signing, so that one
	// MaxPayload item fits an empty batch in MaxItemSlots slots.
	MaxPayload = MaxItemSlots*SlotSize - ItemOverhead
	// maxCarryAge bounds a carried item's age in counted days: the longest
	// wait the queue bound allows, MaxQueue items of m slots each.
	maxCarryAge = MaxQueue * MaxItemSlots
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

// Sender publishes one day's sealed batch (SealBatch). It must be
// idempotent by day and batch: after a crash or an error that came after
// delivery, the same batch for the same day is sent again. A different
// batch for a day already published (a clock behind by more than maxDays)
// is new, never a duplicate (security N1 on #163). It is called on every
// counted day, with a zero-item cover batch when nothing leaves.
type Sender interface {
	Publish(day string, batch []byte) error
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
	// BootID names the boot whose start is Mono's zero, so the last count
	// is kept across a broker restart on that boot; "" names none. nil
	// means the kernel's boot_id when Mono is nil and CLOCK_BOOTTIME works,
	// else none. Set only with Mono (OSS-6e).
	BootID func() string
}

type item struct {
	Kind    string `json:"kind"`
	Payload []byte `json:"payload"`
	// Wait is how many more counted days the item waits; it is due on the
	// day that brings it to zero.
	Wait int `json:"wait"`
	// Due is the counted day (Count) it came due, set once Wait is zero:
	// an item due but not yet sent, because its day's batch was full, is
	// carried with Wait 0 and leaves in cohort order (OSS-6s-a3).
	Due int64 `json:"due,omitempty"`
}

type formed struct {
	Day   string `json:"day"`
	Batch []byte `json:"batch"` // sealed
}

// The clock model (DECISIONS.md, OSS-6 clock; L3 rounds 4 and 5 on #163).
// The wall clock is the only time the box keeps across restarts, and it
// can be wrong by any amount either way and change at any moment (a
// reboot, NTP), so no item carries a date; each stores how many counted
// days it still waits. A release with a plausible clock, after the release
// time, counts its day once it steps: it moves on from the day the last
// release saw by one to maxStep days. It counts only if that last release
// had itself stepped, the day was never counted, and, within this process,
// at least minCountGap of monotonic time has passed since the last count.
// A step back or a larger move is a jump, and the release after a jump
// never counts. A batch forms only on a counted day. Hence:
//
//   - G1: within one process an item with delay k leaves no sooner than
//     (k-1)*20h after it was queued, whatever the clock does; with a right
//     clock, no sooner than k-1 days and the release time.
//   - G2: the last count's monotonic time and boot are kept, so G1 holds
//     across broker restarts on one boot (OSS-6e). Each reboot can let
//     one day count without real time passing, if someone controls the
//     clock, so (k-1-r)*20h for r reboots (r restarts where the floor
//     clock is not CLOCK_BOOTTIME or the boot has no boot_id).
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
	// Counted is the monotonic time of the last count on Boot, so the
	// floor holds across a restart on that boot (OSS-6e).
	Counted time.Duration `json:"counted,omitempty"`
	Boot    string        `json:"boot,omitempty"`
	// Count numbers the counted days, one up on each; a carried item's Due
	// is one of them, so cohort order holds whatever the wall clock does.
	Count int64 `json:"count,omitempty"`
}

// Publisher holds public output until its day and publishes each day's
// due items as one sorted batch at the release time (OSS-6).
type Publisher struct {
	cfg Config
	mu  sync.Mutex
	st  outbox
	// counted is the monotonic time of the last day counted in this
	// process or, on the same boot, by an earlier one, if any.
	counted    time.Duration
	hasCounted bool
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
		if cfg.BootID != nil {
			return nil, errors.New("pubid: a boot id needs its monotonic clock")
		}
		var boot string
		cfg.Mono, boot = systemClock()
		cfg.BootID = func() string { return boot }
	}
	if cfg.BootID == nil {
		cfg.BootID = func() string { return "" }
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
	p.restoreCount()
	return p, nil
}

// restoreCount carries the last count over from an earlier process on this
// boot, so a restart does not reopen the floor (Security on #180). A count
// from another boot, or with no boot named, is ignored: CLOCK_BOOTTIME
// starts again at each boot. One ahead of the clock now is corrupt and
// counts no day: the floor runs from now, so a bad file can neither open
// it nor freeze the outbox.
func (p *Publisher) restoreCount() {
	boot := p.cfg.BootID()
	if boot == "" || p.st.Boot != boot {
		return
	}
	now := p.cfg.Mono()
	p.counted, p.hasCounted = min(p.st.Counted, now), true
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
	if f := p.st.Pending; f != nil {
		if b, err := OpenBatch(f.Batch); err != nil || b.Day != f.Day || b.Len != len(f.Batch) {
			return false, errors.New("bad pending batch")
		}
	}
	if p.st.Count < 0 {
		return false, errors.New("bad count")
	}
	if p.st.Counted < 0 || len(p.st.Boot) > maxBootID || (p.st.Boot == "" && p.st.Counted != 0) {
		return false, errors.New("bad last count")
	}
	var keep []item
	for _, it := range p.st.Items {
		waiting := it.Wait >= 1 && it.Wait <= maxWait && it.Due == 0
		// A carried item is due no later than now, and no earlier than
		// the longest wait the queue bound allows (OSS-6s-a3).
		carried := it.Wait == 0 && it.Due >= 1 && it.Due <= p.st.Count && p.st.Count-it.Due <= maxCarryAge
		if !waiting && !carried || len(it.Payload) == 0 || len(it.Payload) > MaxPayload {
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

// maxBootID bounds a stored boot id (the kernel's is a 36-byte UUID).
const maxBootID = 64

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
		b, _ := OpenBatch(p.st.Pending.Batch) // checked when formed or loaded
		n += len(b.Items)
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
// today counts (the clock model above). Every counted day sends exactly
// one batch, sealed with the epoch's key: a zero-item cover batch when
// nothing leaves (OSS-6s-a2). The items due, carried ones included, are
// signed now and taken in cohort order (select) while they fit UsableSlots;
// the rest carry to the next counted day. The batch's items are sorted by
// their signed bytes. A clock that is not plausible publishes nothing. An
// item that fails to sign, or whose signer adds more than SignerOverhead,
// is dropped, so it cannot hold the others back; the error says how many.
// A batch formed earlier and not confirmed is resent unchanged, for its
// own day, and no new batch is formed in that call. Only a fixed broker
// timer may call it, hourly or so, so no day is missed (G3): when it runs
// is when the batch leaves.
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
		// Today counts, once enough monotonic time has passed in this
		// process; until then it is not seen, so a later tick can count it.
		if p.hasCounted && p.cfg.Mono()-p.counted < minCountGap {
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
	count := p.st.Count + 1
	var due, rest []item
	for _, it := range p.st.Items {
		// A carried item (Wait 0) is never decremented, so it stays due.
		if it.Wait > 0 {
			if it.Wait--; it.Wait == 0 {
				it.Due = count
			}
		}
		if it.Wait == 0 {
			due = append(due, it)
		} else {
			rest = append(rest, it)
		}
	}
	priv, _, err := p.cfg.Identity.Key()
	if err != nil {
		return err
	}
	defer clear(priv)
	batch, carried, failed := p.selectItems(priv, today, due)
	rest = append(rest, carried...)
	var ferr error
	if failed > 0 {
		// The signer's error may quote the payload, so it is not passed on.
		ferr = fmt.Errorf("pubid: %d items could not be signed and were dropped", failed)
	}
	sort.Slice(batch, func(i, j int) bool { return bytes.Compare(batch[i], batch[j]) < 0 })
	sealed, err := SealBatch(priv, today, batch)
	if err != nil {
		return err
	}
	m, boot := p.cfg.Mono(), p.cfg.BootID()
	p.st.Items, p.st.Seen, p.st.Stepped, p.st.Count = rest, today, true, count
	p.st.Counted, p.st.Boot = 0, ""
	if boot != "" && len(boot) <= maxBootID && m >= 0 {
		p.st.Counted, p.st.Boot = m, boot
	}
	p.st.Days = trim(append(slices.Clone(p.st.Days), today))
	p.st.Pending = &formed{Day: today, Batch: sealed}
	if err := p.save(); err != nil {
		p.st = old
		return err
	}
	p.counted, p.hasCounted = m, true
	return errors.Join(p.send(), ferr)
}

// selectItems signs the due items and takes them in cohort order while
// they fit (OSS-6s-a3): carried cohorts first, oldest first, then the
// newly due as the youngest; within a cohort, by cohortRank, so the queue
// order does not show. It stops at the first item that does not fit and
// carries the rest. Every item fits an empty batch, so each counted day
// publishes at least the head of the oldest cohort, and nothing that came
// due later overtakes an item. It returns the signed items taken, the
// items carried, and how many failed to sign.
func (p *Publisher) selectItems(priv ed25519.PrivateKey, today string, due []item) ([][]byte, []item, int) {
	type cand struct {
		it     item
		signed []byte
		rank   []byte
	}
	var cs []cand
	failed := 0
	for _, it := range due {
		b, err := p.cfg.Signers[it.Kind](priv, it.Payload)
		if err != nil || len(b) == 0 || len(b) > len(it.Payload)+SignerOverhead {
			failed++
			continue
		}
		cs = append(cs, cand{it, b, cohortRank(priv.Seed(), today, it)})
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].it.Due != cs[j].it.Due {
			return cs[i].it.Due < cs[j].it.Due
		}
		return bytes.Compare(cs[i].rank, cs[j].rank) < 0
	})
	var batch [][]byte
	var carried []item
	used, full := 0, false
	for _, c := range cs {
		if n := ItemSlots(len(c.signed)); !full && used+n <= UsableSlots {
			batch, used = append(batch, c.signed), used+n
			continue
		}
		full = true
		carried = append(carried, c.it)
	}
	return batch, carried, failed
}

// cohortRank orders one cohort: ascending HMAC-SHA256 of the item, keyed
// by the epoch's key and the day, so it carries no queue information and
// a carried cohort is drawn afresh each day. A variable so a test can
// impose an adversarial order.
var cohortRank = func(seed []byte, today string, it item) []byte {
	h := hmac.New(sha256.New, seed)
	h.Write([]byte("pubid cohort order\x00" + today + "\x00" + it.Kind + "\x00"))
	h.Write(it.Payload)
	return h.Sum(nil)
}

// ItemSlots is the whole slots a signed item of n bytes takes in a batch,
// its length header included.
func ItemSlots(n int) int { return (n + itemHeader + SlotSize - 1) / SlotSize }

// batchMagic opens every batch; its version follows.
const batchMagic = "AOSB"

// Batch is an opened batch.
type Batch struct {
	Day   string
	Key   ed25519.PublicKey
	Items [][]byte
	Len   int // the sealed bytes; anything after them is padding
}

// SealBatch encodes and signs one day's batch: magic, version 1, the day,
// the public key, the item count, each item behind its 4-byte length, and
// an ed25519 signature over all of it. The count and lengths sit inside
// the signed envelope, so a frame padded after it shows nothing outside
// (OSS-6s-a7). A zero-item batch is the cover batch (OSS-6s-a2).
func SealBatch(priv ed25519.PrivateKey, day string, items [][]byte) ([]byte, error) {
	if !isDay(day) || len(items) > Slots {
		return nil, errors.New("pubid: bad batch")
	}
	b := append([]byte(batchMagic), 1)
	b = append(b, day...)
	b = append(b, priv.Public().(ed25519.PublicKey)...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(items)))
	for _, it := range items {
		if len(it) > Slots*SlotSize {
			return nil, errors.New("pubid: bad batch")
		}
		b = binary.BigEndian.AppendUint32(b, uint32(len(it)))
		b = append(b, it...)
	}
	return append(b, ed25519.Sign(priv, b)...), nil
}

// OpenBatch parses a sealed batch from the front of b and checks its
// signature against the key it names; bytes after it are ignored.
func OpenBatch(b []byte) (Batch, error) {
	bad := errors.New("pubid: bad batch")
	if len(b) < BatchOverhead || string(b[:len(batchMagic)]) != batchMagic || b[len(batchMagic)] != 1 {
		return Batch{}, bad
	}
	o := len(batchMagic) + 1
	out := Batch{Day: string(b[o : o+10]), Key: ed25519.PublicKey(slices.Clone(b[o+10 : o+10+ed25519.PublicKeySize]))}
	o += 10 + ed25519.PublicKeySize
	n := int(binary.BigEndian.Uint16(b[o:]))
	o += 2
	if !isDay(out.Day) || n > Slots {
		return Batch{}, bad
	}
	for range n {
		if len(b)-o < itemHeader {
			return Batch{}, bad
		}
		l := int(binary.BigEndian.Uint32(b[o:]))
		o += itemHeader
		if l > len(b)-o {
			return Batch{}, bad
		}
		out.Items = append(out.Items, slices.Clone(b[o:o+l]))
		o += l
	}
	if len(b)-o < ed25519.SignatureSize || !ed25519.Verify(out.Key, b[:o], b[o:o+ed25519.SignatureSize]) {
		return Batch{}, bad
	}
	out.Len = o + ed25519.SignatureSize
	return out, nil
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
