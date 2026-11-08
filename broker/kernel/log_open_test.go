package kernel_test

// REQ: KRN-1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// Open is the Log's only constructor: a zero Log and a nil *Log refuse every
// call with ErrNoLog and hold no entries, and Boot refuses them, so nothing
// panics on a Log Open did not make; a copy of an opened Log is the same log,
// so an append through either shows in both and in the store (KRN-1, #4574).
// Catches a nil record reached through Log.p, and copies that diverge.
func TestLogOpenIsTheOnlyConstructor(t *testing.T) {
	for _, l := range []*kernel.Log{{}, nil} {
		if _, err := l.Append(1, kernel.TTaskOpened, 1, map[string]string{"task": "t"}); !errors.Is(err, kernel.ErrNoLog) {
			t.Fatalf("append to a Log Open did not make: %v", err)
		}
		if err := l.Anchor(); !errors.Is(err, kernel.ErrNoLog) {
			t.Fatalf("anchor of a Log Open did not make: %v", err)
		}
		if l.Entries() != nil || l.Len() != 0 {
			t.Fatal("a Log Open did not make holds entries")
		}
		if _, err := kernel.Boot(l, nil, nil, 0); !errors.Is(err, kernel.ErrNoLog) {
			t.Fatalf("boot over a Log Open did not make: %v", err)
		}
	}

	r := newRig(t)
	n := r.k.Log().Len()
	cp := *r.k.Log()
	must(t, r.k.OpenTask(1, "t1", 0))
	if cp.Len() != n+1 || r.k.Log().Len() != n+1 {
		t.Fatalf("after one append the copy has %d entries and the log %d, want %d", cp.Len(), r.k.Log().Len(), n+1)
	}
	if _, err := cp.Append(2, kernel.TTaskOpened, 1, map[string]string{"task": "t2"}); err != nil {
		t.Fatal(err)
	}
	re, err := kernel.Open(cfg(r))
	must(t, err)
	if !kernel.Same(re.Entries(), r.k.Log().Entries()) || !kernel.Same(cp.Entries(), re.Entries()) {
		t.Fatal("a copy of the log diverged from it or from the store")
	}
}

// failStore is a store whose Append or Truncate fails while set.
type failStore struct {
	kernel.MemStore
	appendErr, truncErr bool
}

func (s *failStore) Append(b []byte) error {
	if s.appendErr {
		return errors.New("disk full")
	}
	return s.MemStore.Append(b)
}

func (s *failStore) Truncate(n int) error {
	if s.truncErr {
		return errors.New("read-only")
	}
	return s.MemStore.Truncate(n)
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// logCfg is a log config over st and a, keyed like the rig's.
func logCfg(st kernel.Store, a kernel.Anchor) kernel.Config {
	h := gen(3)
	return kernel.Config{Store: st, Anchor: a, Key: logKey, Pub: h.pub, Sign: h.priv, Rand: rand.NewChaCha8([32]byte{2})}
}

// appendN appends n task entries named by prefix to l.
func appendN(t *testing.T, l *kernel.Log, prefix string, n int) {
	t.Helper()
	for i := range n {
		_, err := l.Append(int64(i), kernel.TTaskOpened, 1, map[string]string{"task": fmt.Sprintf("%s%d", prefix, i)})
		must(t, err)
	}
}

// frames splits a store's bytes into its length-prefixed frames.
func frames(b []byte) [][]byte {
	var out [][]byte
	for len(b) >= 4 {
		n := 4 + int(binary.BigEndian.Uint32(b))
		out = append(out, b[:n])
		b = b[n:]
	}
	return out
}

// The log's own checks each hold (LOG-1, LOG-2, KRN-1, KRN-5): an entry
// sealed under the right key and seq but chained to another history is
// corrupt; a log opens with no anchor; an anchored head that does not
// verify is corrupt; opening a log with nothing to drop writes nothing; a
// nonce the random source cannot give, or a failed write, refuses the
// append, and after a failed write the log refuses all until reopened; a
// head is signed only with a signer and an anchor, and an empty log has
// none to sign. Catches any of those checks dropped.
func TestLogChecksHold(t *testing.T) {
	a, b := &kernel.MemStore{}, &kernel.MemStore{}
	la, err := kernel.Open(logCfg(a, nil))
	must(t, err)
	lb, err := kernel.Open(logCfg(b, nil))
	must(t, err)
	if err := la.Anchor(); !errors.Is(err, kernel.ErrNoSigner) {
		t.Fatalf("anchor with no anchor: %v", err)
	}
	appendN(t, la, "a", 3)
	appendN(t, lb, "b", 3)
	fa, fb := frames(a.B), frames(b.B)
	mixed := &kernel.MemStore{B: bytes.Join([][]byte{fa[0], fa[1], fb[2], fa[2]}, nil)}
	if _, err := kernel.Open(logCfg(mixed, nil)); !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("an entry chained to another history: %v", err)
	}
	if l, err := kernel.Open(logCfg(&kernel.MemStore{B: a.B}, nil)); err != nil || l.Len() != 3 {
		t.Fatalf("a log with no anchor: %v", err)
	}

	bad := &kernel.MemAnchor{}
	must(t, bad.Put(kernel.SignHead(gen(9).priv, 3, la.Entries()[2].Hash())))
	if _, err := kernel.Open(logCfg(&kernel.MemStore{B: a.B}, bad)); !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("a head another key signed: %v", err)
	}

	st := &failStore{MemStore: kernel.MemStore{B: a.B}}
	anc := &kernel.MemAnchor{}
	l, err := kernel.Open(logCfg(st, anc))
	must(t, err)
	must(t, l.Anchor())
	st.truncErr = true
	if _, err := kernel.Open(logCfg(st, anc)); err != nil {
		t.Fatalf("an anchored log with nothing to drop was cut: %v", err)
	}
	st.truncErr = false

	empty, err := kernel.Open(logCfg(&kernel.MemStore{}, &kernel.MemAnchor{}))
	must(t, err)
	if err := empty.Anchor(); err != nil {
		t.Fatalf("anchoring an empty log: %v", err)
	}
	c := logCfg(&kernel.MemStore{}, nil)
	c.Rand = failReader{}
	nr, err := kernel.Open(c)
	must(t, err)
	if _, err := nr.Append(1, kernel.TTaskOpened, 1, map[string]string{"task": "t"}); err == nil || nr.Len() != 0 {
		t.Fatalf("an append with no nonce: %v", err)
	}

	st.appendErr = true
	if _, err := l.Append(9, kernel.TTaskOpened, 1, map[string]string{"task": "x"}); err == nil {
		t.Fatal("a failed write was not refused")
	}
	st.appendErr = false
	if _, err := l.Append(10, kernel.TTaskOpened, 1, map[string]string{"task": "y"}); !errors.Is(err, kernel.ErrBroken) {
		t.Fatalf("after a failed write: %v", err)
	}
}
