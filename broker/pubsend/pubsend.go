// Package pubsend sends the publication identity's daily batches
// (OSS-6s-a). Each batch goes out as one frame of FrameSize bytes, the
// sealed batch followed by padding, so every day looks the same on the
// wire. A ledger keyed by (day, SHA-256 of the batch) makes sending
// idempotent and fixes each frame's padding on its first attempt, so a
// retry repeats the same bytes. The network sits behind Transport
// (OSS-6s-b); this package imports none.
package pubsend

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/pubid"
)

// FrameSize is every frame's length: the batch and its padding.
const FrameSize = pubid.Slots * pubid.SlotSize

// MaxWaiting is how many frames wait for an unreachable transport before
// the oldest is dropped. Provisional until OSS-6p sets it (ASSUMPTIONS S4).
const MaxWaiting = 7

// maxConfirmed is how many confirmed keys the ledger keeps: more than a
// year of days, so a key is still known when the same batch comes back.
const maxConfirmed = 400

// seedSize is the padding seed's length, an AES-256 key.
const seedSize = 32

// Transport carries one frame to the relays (OSS-6s-b). An error means
// the frame may or may not have arrived; it is sent again, byte for byte.
type Transport interface {
	Send(frame []byte) error
}

// Config sets up a Sender.
type Config struct {
	Path      string // the ledger file
	Transport Transport
	// Log is the owner-visible log (OSS-1), the only place a dropped frame
	// is reported. Required.
	Log  func(string)
	Rand io.Reader // padding seeds; nil means crypto/rand
}

type entry struct {
	Day   string `json:"day"`
	Hash  string `json:"hash"`
	Batch []byte `json:"batch,omitempty"`
	Seed  []byte `json:"seed,omitempty"`
}

type ledger struct {
	Waiting   []entry `json:"waiting"`
	Confirmed []entry `json:"confirmed"`
}

// Sender is a pubid.Sender over a Transport.
type Sender struct {
	cfg Config
	mu  sync.Mutex // guards st and the ledger file
	st  ledger
}

var _ pubid.Sender = (*Sender)(nil)

// New opens the ledger at cfg.Path, or starts an empty one if there is
// none. A damaged ledger is an error, never taken as empty: that would
// send a waiting batch again with other padding.
func New(cfg Config) (*Sender, error) {
	if cfg.Path == "" || cfg.Transport == nil || cfg.Log == nil {
		return nil, errors.New("pubsend: Path, Transport and Log are required")
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	dir := filepath.Dir(cfg.Path)
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	if err := sweepTemp(dir); err != nil {
		return nil, err
	}
	s := &Sender{cfg: cfg}
	b, err := os.ReadFile(cfg.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&s.st); err != nil {
		return nil, fmt.Errorf("pubsend: ledger: %w", err)
	}
	if err := s.st.validate(); err != nil {
		return nil, fmt.Errorf("pubsend: ledger: %w", err)
	}
	return s, nil
}

func (l *ledger) validate() error {
	if len(l.Waiting) > MaxWaiting || len(l.Confirmed) > maxConfirmed {
		return errors.New("too many entries")
	}
	seen := map[ledgerKey]bool{}
	for _, e := range l.Confirmed {
		if e.Batch != nil || e.Seed != nil || !keyOK(e) {
			return fmt.Errorf("bad confirmed key %q", e.Day)
		}
		seen[key(e)] = true
	}
	for _, e := range l.Waiting {
		if !keyOK(e) || len(e.Seed) != seedSize || seen[key(e)] {
			return fmt.Errorf("bad waiting entry %q", e.Day)
		}
		if _, err := check(e.Day, e.Batch); err != nil {
			return err
		}
		if hashOf(e.Batch) != e.Hash {
			return fmt.Errorf("waiting entry %q: hash does not match", e.Day)
		}
		seen[key(e)] = true
	}
	return nil
}

// ledgerKey is what makes two publications the same (OSS-6s-a4).
type ledgerKey struct{ day, hash string }

func key(e entry) ledgerKey { return ledgerKey{e.Day, e.Hash} }

func keyOK(e entry) bool {
	h, err := hex.DecodeString(e.Hash)
	return err == nil && len(h) == sha256.Size && hex.EncodeToString(h) == e.Hash && isDay(e.Day)
}

func isDay(s string) bool {
	t, err := time.Parse("2006-01-02", s)
	return err == nil && t.Format("2006-01-02") == s
}

func hashOf(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// check accepts a whole sealed batch for day that fits a frame.
func check(day string, batch []byte) (pubid.Batch, error) {
	b, err := pubid.OpenBatch(batch)
	switch {
	case err != nil:
		return b, fmt.Errorf("pubsend: %w", err)
	case b.Day != day:
		return b, fmt.Errorf("pubsend: a batch for %s published as %s", b.Day, day)
	case b.Len != len(batch) || len(batch) > FrameSize:
		return b, errors.New("pubsend: the batch is not exactly one sealed batch within a frame")
	}
	return b, nil
}

// Publish takes the day's sealed batch. A key already confirmed or
// waiting is a no-op; a new one is written to the ledger with a fresh
// padding seed before anything is sent. Publish returns once the batch is
// durable: a transport failure leaves it waiting for the next Flush and is
// not an error here, so the outbox does not hold it too.
func (s *Sender) Publish(day string, batch []byte) error {
	if _, err := check(day, batch); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := entry{Day: day, Hash: hashOf(batch)}
	known := false
	for _, l := range [][]entry{s.st.Confirmed, s.st.Waiting} {
		for _, e := range l {
			known = known || key(e) == key(k)
		}
	}
	if !known {
		seed := make([]byte, seedSize)
		if _, err := io.ReadFull(s.cfg.Rand, seed); err != nil {
			return fmt.Errorf("pubsend: padding seed: %w", err)
		}
		k.Batch, k.Seed = append([]byte(nil), batch...), seed
		// A failed save leaves the ledger as it was, so a retry writes it
		// again rather than finding the key only in memory.
		prev := s.st
		s.st.Waiting = append(s.st.Waiting, k)
		var dropped []string
		for len(s.st.Waiting) > MaxWaiting {
			dropped = append(dropped, s.st.Waiting[0].Day)
			s.st.Waiting = s.st.Waiting[1:]
		}
		if err := s.save(); err != nil {
			s.st = prev
			return err
		}
		for _, d := range dropped {
			s.cfg.Log(fmt.Sprintf("pubsend: dropped the unsent publication for %s: the transport was unreachable for more than %d publications", d, MaxWaiting))
		}
	}
	_ = s.flush()
	return nil
}

// Flush sends what waits, oldest first, and stops at the first transport
// error, which it returns. Each frame sent is recorded as confirmed.
func (s *Sender) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flush()
}

func (s *Sender) flush() error {
	for len(s.st.Waiting) > 0 {
		e := s.st.Waiting[0]
		f, err := frame(e)
		if err != nil {
			return err
		}
		if err := s.cfg.Transport.Send(f); err != nil {
			return fmt.Errorf("pubsend: sending %s: %w", e.Day, err)
		}
		s.st.Waiting = s.st.Waiting[1:]
		s.st.Confirmed = append(s.st.Confirmed, entry{Day: e.Day, Hash: e.Hash})
		s.st.Confirmed = s.st.Confirmed[max(0, len(s.st.Confirmed)-maxConfirmed):]
		if err := s.save(); err != nil {
			return err
		}
	}
	return nil
}

// frame is the batch followed by AES-256-CTR keystream under the entry's
// seed (zero IV: each seed keys one frame), out to FrameSize.
func frame(e entry) ([]byte, error) {
	c, err := aes.NewCipher(e.Seed)
	if err != nil {
		return nil, err
	}
	f := make([]byte, FrameSize)
	pad := f[len(e.Batch):]
	cipher.NewCTR(c, make([]byte, aes.BlockSize)).XORKeyStream(pad, pad)
	copy(f, e.Batch)
	return f, nil
}

func (s *Sender) save() error {
	b, err := json.Marshal(s.st)
	if err != nil {
		return err
	}
	return writeAtomic(s.cfg.Path, b)
}

// writeAtomic, checkDir and sweepTemp follow pubid's (identity.go,
// publisher.go): the ledger is replaced by rename, synced with its
// directory, in a directory only this user can change.
func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pubsend-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok || int(st.Uid) != os.Geteuid():
		return fmt.Errorf("pubsend: %s belongs to another user", dir)
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("pubsend: %s is writable by others", dir)
	}
	return nil
}

func sweepTemp(dir string) error {
	names, err := filepath.Glob(filepath.Join(dir, ".pubsend-*"))
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
