package run

// REQ: LOG-2, STO-1

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

// fakeCounter is the TPM counter's contract: it only goes up. failInc fails
// the next Increment, as a power cut or a TPM error between the file write
// and the count would.
type fakeCounter struct {
	n       uint64
	failInc bool
}

func (c *fakeCounter) Read() (uint64, error) { return c.n, nil }
func (c *fakeCounter) Increment() error {
	if c.failInc {
		c.failInc = false
		return errors.New("fake: increment failed")
	}
	c.n++
	return nil
}

func headKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func head(priv ed25519.PrivateKey, seq uint64) kernel.Head {
	return kernel.SignHead(priv, seq, kernel.Hash{byte(seq)})
}

// newAnchor enrolls an anchor in a fresh directory, on a counter that starts
// where a TPM's might (not at zero), and opens it.
func newAnchor(t *testing.T) (string, *fakeCounter, ed25519.PrivateKey, *CounterAnchor) {
	t.Helper()
	dir, c, priv := clerkDir(t), &fakeCounter{n: 1000}, headKey(t)
	if err := InitCounterAnchor(dir, c, priv); err != nil {
		t.Fatal(err)
	}
	a, err := OpenCounterAnchor(dir, c, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Latest(); ok {
		t.Fatal("a new anchor has a head")
	}
	return dir, c, priv, a
}

func put(t *testing.T, a *CounterAnchor, h kernel.Head) {
	t.Helper()
	if err := a.Put(h); err != nil {
		t.Fatal(err)
	}
}

func latest(t *testing.T, dir string, c Counter, priv ed25519.PrivateKey) kernel.Head {
	t.Helper()
	a, err := OpenCounterAnchor(dir, c, priv)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := a.Latest()
	if !ok {
		t.Fatal("no head")
	}
	return h
}

func anchorSnap(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, anchorName))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func anchorRestore(t *testing.T, dir string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, anchorName), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A head file put back from an earlier write, as a drive image restored
// whole would, is refused: the counter has counted later writes.
func TestCounterAnchorRefusesARolledBackFile(t *testing.T) {
	dir, c, priv, a := newAnchor(t)
	put(t, a, head(priv, 3))
	old := anchorSnap(t, dir)
	put(t, a, head(priv, 7))
	anchorRestore(t, dir, old)
	if _, err := OpenCounterAnchor(dir, c, priv); !errors.Is(err, ErrAnchorRolledBack) {
		t.Fatalf("rolled-back file: %v", err)
	}
	// The file enrollment wrote is the oldest of all.
	dir2, c2, priv2, a2 := newAnchor(t)
	fresh := anchorSnap(t, dir2)
	put(t, a2, head(priv2, 1))
	anchorRestore(t, dir2, fresh)
	if _, err := OpenCounterAnchor(dir2, c2, priv2); !errors.Is(err, ErrAnchorRolledBack) {
		t.Fatalf("file rolled back to enrollment: %v", err)
	}
}

// A deleted head file is refused, not read as a box with no head yet, so
// deleting it cannot switch the log's rollback check off.
func TestCounterAnchorRefusesAMissingFile(t *testing.T) {
	dir, c, priv, a := newAnchor(t)
	put(t, a, head(priv, 2))
	if err := os.Remove(filepath.Join(dir, anchorName)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCounterAnchor(dir, c, priv); !errors.Is(err, ErrAnchorMissing) {
		t.Fatalf("missing file: %v", err)
	}
	if err := InitCounterAnchor(dir, c, priv); err != nil {
		t.Fatal(err)
	}
	if err := InitCounterAnchor(dir, c, priv); !errors.Is(err, ErrAnchorExists) {
		t.Fatalf("init over a file: %v", err)
	}
}

// A file whose number or heads were edited, or that another key signed,
// is refused: the writer of the drive holds no head key.
func TestCounterAnchorRefusesAnEditedFile(t *testing.T) {
	dir, c, priv, a := newAnchor(t)
	put(t, a, head(priv, 3))
	put(t, a, head(priv, 5))
	good := anchorSnap(t, dir)
	var af anchorFile
	if err := json.Unmarshal(good, &af); err != nil {
		t.Fatal(err)
	}
	var rec anchorRec
	if err := json.Unmarshal(af.Rec, &rec); err != nil {
		t.Fatal(err)
	}
	edit := func(f func(r *anchorRec)) []byte {
		r := rec
		f(&r)
		rb, _ := json.Marshal(r)
		b, _ := json.Marshal(anchorFile{Rec: rb, Sig: af.Sig})
		return b
	}
	older := head(priv, 3)
	other := headKey(t)
	resigned, _ := signAnchor(other, anchorRec{V: 1, N: rec.N, Head: rec.Head, Prev: rec.Prev})
	for name, b := range map[string][]byte{
		"number":       edit(func(r *anchorRec) { r.N++ }),
		"head swapped": edit(func(r *anchorRec) { r.Head = &older }),
		"no head":      edit(func(r *anchorRec) { r.Head, r.Prev = nil, nil }),
		"other key":    resigned,
		"not json":     []byte("{"),
	} {
		anchorRestore(t, dir, b)
		if _, err := OpenCounterAnchor(dir, c, priv); !errors.Is(err, ErrAnchorCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	anchorRestore(t, dir, good)
	if h := latest(t, dir, c, priv); h.Seq != 5 {
		t.Fatalf("good file: seq %d", h.Seq)
	}
}

// A file more than one write ahead of the counter is refused: no crash
// leaves one (a different TPM, or a counter that was reset).
func TestCounterAnchorRefusesAFileAheadOfItsCounter(t *testing.T) {
	dir, c, priv, a := newAnchor(t)
	put(t, a, head(priv, 1))
	if _, err := OpenCounterAnchor(dir, &fakeCounter{n: c.n - 2}, priv); !errors.Is(err, ErrAnchorAhead) {
		t.Fatalf("file ahead: %v", err)
	}
}

// A Put whose file landed but whose count did not returns an error and
// breaks the anchor. Reopened, the anchor takes the head before it: a Put
// that failed confirms nothing.
func TestCounterAnchorCrashBetweenWriteAndCount(t *testing.T) {
	dir, c, priv, a := newAnchor(t)
	put(t, a, head(priv, 4))
	c.failInc = true
	if err := a.Put(head(priv, 9)); err == nil {
		t.Fatal("Put returned nil with the count failed")
	}
	if err := a.Put(head(priv, 10)); !errors.Is(err, ErrAnchorBroken) {
		t.Fatalf("Put after a failed Put: %v", err)
	}
	if h, _ := a.Latest(); h.Seq != 4 {
		t.Fatalf("Latest after a failed Put: seq %d", h.Seq)
	}
	b, err := OpenCounterAnchor(dir, c, priv)
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := b.Latest(); h.Seq != 4 {
		t.Fatalf("reopened: seq %d, want 4", h.Seq)
	}
	put(t, b, head(priv, 9))
	if h := latest(t, dir, c, priv); h.Seq != 9 {
		t.Fatalf("after the retry: seq %d", h.Seq)
	}
}

// A crash at any step of the file write leaves an anchor that opens on the
// last counted head, and the head file a failed Put left behind (here its
// temporary, as a copy taken off the drive) never matches the counter later.
func TestCounterAnchorCrashDuringTheFileWrite(t *testing.T) {
	for step := 0; step < 6; step++ {
		dir, c, priv, a := newAnchor(t)
		put(t, a, head(priv, 2))
		a.stop = func(i int) bool { return i == step }
		if err := a.Put(head(priv, 6)); err == nil {
			t.Fatalf("step %d: Put returned nil", step)
		}
		stray, _ := os.ReadFile(filepath.Join(dir, anchorName+".tmp"))
		if step >= 4 {
			stray = anchorSnap(t, dir)
		}
		if h := latest(t, dir, c, priv); h.Seq != 2 {
			t.Fatalf("step %d: reopened on seq %d, want 2", step, h.Seq)
		}
		b, err := OpenCounterAnchor(dir, c, priv)
		if err != nil {
			t.Fatal(err)
		}
		put(t, b, head(priv, 8))
		if len(stray) == 0 {
			continue
		}
		anchorRestore(t, dir, stray)
		if _, err := OpenCounterAnchor(dir, c, priv); !errors.Is(err, ErrAnchorRolledBack) && !errors.Is(err, ErrAnchorCorrupt) {
			t.Fatalf("step %d: the failed Put's file: %v", step, err)
		}
	}
}

// A head behind or forking from the anchored one is refused without
// breaking the anchor.
func TestCounterAnchorRefusesAHeadBehind(t *testing.T) {
	_, _, priv, a := newAnchor(t)
	put(t, a, head(priv, 5))
	fork := kernel.SignHead(priv, 5, kernel.Hash{0xff})
	for _, h := range []kernel.Head{head(priv, 4), fork} {
		if err := a.Put(h); !errors.Is(err, ErrAnchorBehind) {
			t.Fatalf("seq %d: %v", h.Seq, err)
		}
	}
	put(t, a, head(priv, 6))
}

// Through kernel.Open: a widening the anchor confirmed survives a reopen,
// a log cut back under a good anchor is refused, and a drive rolled back
// whole, log and head file together, is refused before the log is read.
func TestCounterAnchorUnderTheLog(t *testing.T) {
	dir, c, priv, a := newAnchor(t)
	st := &kernel.MemStore{}
	cfg := kernel.Config{Store: st, Anchor: a, Key: [32]byte{7}, Pub: priv.Public().(ed25519.PublicKey), Sign: priv, Rand: rand.Reader}
	l, err := kernel.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(1, kernel.TStop, 1, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if err := l.Anchor(); err != nil {
		t.Fatal(err)
	}
	oldLog, oldFile := append([]byte(nil), st.B...), anchorSnap(t, dir)
	if _, err := l.Append(2, kernel.TResume, 1, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if err := l.Anchor(); err != nil {
		t.Fatal(err)
	}

	reopen := func(store *kernel.MemStore) (*kernel.Log, error) {
		b, err := OpenCounterAnchor(dir, c, priv)
		if err != nil {
			return nil, err
		}
		cfg.Store, cfg.Anchor = store, b
		return kernel.Open(cfg)
	}
	l2, err := reopen(&kernel.MemStore{B: append([]byte(nil), st.B...)})
	if err != nil || l2.Len() != 2 {
		t.Fatalf("reopen: len %v, %v", l2, err)
	}
	if _, err := reopen(&kernel.MemStore{B: oldLog}); !errors.Is(err, kernel.ErrTruncated) {
		t.Fatalf("log cut back: %v", err)
	}
	anchorRestore(t, dir, oldFile)
	if _, err := reopen(&kernel.MemStore{B: oldLog}); !errors.Is(err, ErrAnchorRolledBack) {
		t.Fatalf("drive rolled back whole: %v", err)
	}
}

// The same on the TPM's own counter (swtpm): enrollment, a Put, and a
// rolled-back head file refused after a power cycle.
func TestCounterAnchorOnTheTPMCounter(t *testing.T) {
	s := swtpm.Start(t)
	srk, err := tpmseal.Identity(s.TPM())
	if err != nil {
		t.Fatal(err)
	}
	id, auth := make([]byte, 16), make([]byte, 16)
	rand.Read(id)
	rand.Read(auth)
	ref, err := tpmseal.DefineCounter(s.TPM(), srk, id, auth)
	if err != nil {
		t.Fatal(err)
	}
	c := tpmseal.Counter{TPM: s.TPM(), SRK: srk, Ref: ref, Auth: auth}
	dir, priv := clerkDir(t), headKey(t)
	if err := InitCounterAnchor(dir, c, priv); err != nil {
		t.Fatal(err)
	}
	a, err := OpenCounterAnchor(dir, c, priv)
	if err != nil {
		t.Fatal(err)
	}
	put(t, a, head(priv, 1))
	old := anchorSnap(t, dir)
	put(t, a, head(priv, 2))
	s.Reboot()
	if h := latest(t, dir, c, priv); h.Seq != 2 {
		t.Fatalf("after power cycle: seq %d", h.Seq)
	}
	anchorRestore(t, dir, old)
	if _, err := OpenCounterAnchor(dir, c, priv); !errors.Is(err, ErrAnchorRolledBack) {
		t.Fatalf("rolled-back file on the TPM counter: %v", err)
	}
}
