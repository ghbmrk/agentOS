package run

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// Counter is a count that only goes up and lives off the log's disk: the
// TPM's NV counter on a trusted host (tpmseal.Counter). Increment adds one.
type Counter interface {
	Read() (uint64, error)
	Increment() error
}

// CounterAnchor is the trusted host's anchor (LOG-2, STO-1: "the core's TPM
// monotonic counter, advanced with every head"). The counter holds only a
// number, so the signed head is kept in a file beside the log, and the
// counter numbers that file's writes. Each write is signed with the head key
// over its number, its head and the head before it. A file from an earlier
// write carries a number behind the counter, so a drive rolled back to it,
// log and file together, is refused at open (ASSUMPTIONS LOG-anchor-tpm-a).
//
// Put writes the file first and then advances the counter. A crash between
// the two leaves the file one ahead; Open then takes the head before it, so
// a Put that never returned confirms nothing, as with any anchor whose Put
// failed (kernel.Open drops the widening it covered).
type CounterAnchor struct {
	mu     sync.Mutex
	dir    string
	c      Counter
	sign   ed25519.PrivateKey
	n      uint64       // the counter's value, which numbers the file on disk
	head   *kernel.Head // nil until the first Put
	broken bool
	stop   func(i int) bool // tests: crash the file write after step i
}

const (
	anchorName   = "anchor"
	domainAnchor = "agentos.anchor.v1\x00"
	maxAnchor    = 4 << 10
)

var (
	// ErrAnchorMissing: no head file. Only enrollment starts one
	// (InitCounterAnchor); a deleted file is not read as a new box.
	ErrAnchorMissing = errors.New("run: the anchor's head file is missing")
	// ErrAnchorRolledBack: the head file is from an earlier write than the
	// counter has counted, so the drive was rolled back.
	ErrAnchorRolledBack = errors.New("run: the anchor's head file is older than its counter")
	// ErrAnchorAhead: the head file is more than one write ahead of the
	// counter, which no crash leaves: another counter, or a forged file.
	ErrAnchorAhead = errors.New("run: the anchor's head file is ahead of its counter")
	// ErrAnchorCorrupt: the head file does not parse or its signature fails.
	ErrAnchorCorrupt = errors.New("run: the anchor's head file is corrupt")
	// ErrAnchorExists: InitCounterAnchor over a head file already there.
	ErrAnchorExists = errors.New("run: the anchor's head file already exists")
	// ErrAnchorBroken: a Put failed part way; nothing more is anchored
	// until the anchor is opened again.
	ErrAnchorBroken = errors.New("run: the anchor failed a write; reopen it")
	// ErrAnchorBehind: a head behind, or forking from, the anchored one.
	ErrAnchorBehind = errors.New("run: the head is behind or forks from the anchored head")
)

// anchorRec is one write of the head file. Head is the anchored head; Prev
// is the head the write before it anchored, taken when the counter missed
// this write.
type anchorRec struct {
	V    int          `json:"v"`
	N    uint64       `json:"n"`
	Head *kernel.Head `json:"head,omitempty"`
	Prev *kernel.Head `json:"prev,omitempty"`
}

type anchorFile struct {
	Rec json.RawMessage `json:"rec"`
	Sig []byte          `json:"sig"`
}

func anchorMsg(rec []byte) []byte { return append([]byte(domainAnchor), rec...) }

// InitCounterAnchor starts the head file in dir at the counter's current
// value, with no head. Enrollment alone calls it, on a box with no log (STO-2c).
func InitCounterAnchor(dir string, c Counter, sign ed25519.PrivateKey) error {
	if err := private(dir, true); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, anchorName)); err == nil {
		return ErrAnchorExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	n, err := c.Read()
	if err != nil {
		return err
	}
	b, err := signAnchor(sign, anchorRec{V: 1, N: n})
	if err != nil {
		return err
	}
	return writeAtomic(dir, anchorName, b, nil)
}

// OpenCounterAnchor loads the head file in dir and checks it against the
// counter. It fails closed: a missing, rolled-back, ahead or unsigned file is
// an error, so kernel.Open never runs against an anchor it cannot trust.
// It then rewrites the file at the next number, so no record a failed Put
// may have left (a temporary copied off the drive) can match the counter
// later.
func OpenCounterAnchor(dir string, c Counter, sign ed25519.PrivateKey) (*CounterAnchor, error) {
	if err := private(dir, true); err != nil {
		return nil, err
	}
	rec, err := readAnchor(dir, sign.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	n, err := c.Read()
	if err != nil {
		return nil, err
	}
	a := &CounterAnchor{dir: dir, c: c, sign: sign, n: n}
	switch {
	case rec.N == n:
		a.head = rec.Head
	case n < ^uint64(0) && rec.N == n+1:
		a.head = rec.Prev
	case rec.N < n:
		return nil, ErrAnchorRolledBack
	default:
		return nil, ErrAnchorAhead
	}
	if err := a.write(a.head, a.head); err != nil {
		return nil, err
	}
	return a, nil
}

func readAnchor(dir string, pub ed25519.PublicKey) (anchorRec, error) {
	f, err := os.OpenFile(filepath.Join(dir, anchorName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return anchorRec{}, ErrAnchorMissing
	}
	if err != nil {
		return anchorRec{}, err
	}
	defer f.Close()
	if err := privateFile(f); err != nil {
		return anchorRec{}, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAnchor+1))
	if err != nil {
		return anchorRec{}, err
	}
	var af anchorFile
	var rec anchorRec
	if len(b) > maxAnchor || json.Unmarshal(b, &af) != nil || !ed25519.Verify(pub, anchorMsg(af.Rec), af.Sig) ||
		json.Unmarshal(af.Rec, &rec) != nil || rec.V != 1 {
		return anchorRec{}, ErrAnchorCorrupt
	}
	for _, h := range []*kernel.Head{rec.Head, rec.Prev} {
		if h != nil && !h.Valid(pub) {
			return anchorRec{}, ErrAnchorCorrupt
		}
	}
	if rec.Prev != nil && (rec.Head == nil || rec.Prev.Seq > rec.Head.Seq) {
		return anchorRec{}, ErrAnchorCorrupt
	}
	return rec, nil
}

func signAnchor(sign ed25519.PrivateKey, rec anchorRec) ([]byte, error) {
	rb, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return json.Marshal(anchorFile{Rec: rb, Sig: ed25519.Sign(sign, anchorMsg(rb))})
}

// write puts head at the next number, then advances the counter. Any
// failure breaks the anchor until it is opened again, so a number is never
// written twice with different heads.
func (a *CounterAnchor) write(head, prev *kernel.Head) error {
	if a.n == ^uint64(0) {
		a.broken = true
		return errors.New("run: anchor counter at its limit")
	}
	b, err := signAnchor(a.sign, anchorRec{V: 1, N: a.n + 1, Head: head, Prev: prev})
	if err == nil {
		err = writeAtomic(a.dir, anchorName, b, a.stop)
	}
	if err == nil {
		err = a.c.Increment()
	}
	if err != nil {
		a.broken = true
		return err
	}
	a.n++
	return nil
}

// Put anchors h. It returns only once the counter has counted the write.
func (a *CounterAnchor) Put(h kernel.Head) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.broken {
		return ErrAnchorBroken
	}
	if a.head != nil && (h.Seq < a.head.Seq || h.Seq == a.head.Seq && h.Hash != a.head.Hash) {
		return ErrAnchorBehind
	}
	if err := a.write(&h, a.head); err != nil {
		return err
	}
	a.head = &h
	return nil
}

// Latest is the last head whose write the counter counted.
func (a *CounterAnchor) Latest() (kernel.Head, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.head == nil {
		return kernel.Head{}, false
	}
	return *a.head, true
}

// Number is the counter value the file on disk carries (tests and status).
func (a *CounterAnchor) Number() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}
