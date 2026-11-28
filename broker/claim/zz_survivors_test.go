package claim

// REQ: HW-10

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
)

// Tests that pin claim's error paths, journal lines and bounds, each named
// for the mutant it kills (mutgate on #6598).

// stateWith returns a sealed box's state on disk with edit applied to its
// JSON fields, in a memory store.
func stateWith(t *testing.T, edit func(map[string]any)) *change.MemStore {
	t.Helper()
	b, _ := newBox(t)
	raw, err := b.st.Load()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	ms := &change.MemStore{}
	if err := ms.Save(out); err != nil {
		t.Fatal(err)
	}
	return ms
}

func bootOne() (string, error) { return "boot-1", nil }

// Seal takes its salt from the reader it is given, journals the seal, and
// fails on a short reader or a failed save (claim.go Seal).
func TestSealSaltJournalAndErrors(t *testing.T) {
	code, err := NewCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{7}, 16)
	ms := &change.MemStore{}
	var journal []string
	if err := Seal(ms, code, bytes.NewReader(salt), func(e string) { journal = append(journal, e) }); err != nil {
		t.Fatal(err)
	}
	raw, _ := ms.Load()
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Salt, salt) {
		t.Fatalf("salt %x, not the reader's", s.Salt)
	}
	if len(journal) != 1 || journal[0] != EventSealed {
		t.Fatalf("journal %q", journal)
	}
	if err := Seal(&change.MemStore{}, code, bytes.NewReader(salt[:3]), nil); err == nil {
		t.Fatal("sealed with a short salt")
	}
	journal = nil
	full := &change.MemStore{Fail: errors.New("disk full")}
	if err := Seal(full, code, nil, func(e string) { journal = append(journal, e) }); err == nil || len(journal) != 0 {
		t.Fatalf("failed save: %v, journal %q", err, journal)
	}
}

// Claimed reads the state without opening it, and refuses what it cannot
// read (claim.go Claimed).
func TestClaimedReadsTheState(t *testing.T) {
	if _, err := Claimed(nil); err == nil {
		t.Fatal("no store")
	}
	if _, err := Claimed(&loadFail{}); err == nil || errors.Is(err, ErrNoCode) {
		t.Fatalf("read error: %v", err)
	}
	if _, err := Claimed(&change.MemStore{}); !errors.Is(err, ErrNoCode) {
		t.Fatalf("empty store: %v", err)
	}
	garbage := &change.MemStore{}
	garbage.Save([]byte("{garbage"))
	var syn *json.SyntaxError
	if _, err := Claimed(garbage); !errors.As(err, &syn) {
		t.Fatalf("garbage: %v", err)
	}
	claimed := &change.MemStore{}
	claimed.Save([]byte(`{"claimed":true}`))
	if got, err := Claimed(claimed); !got || err != nil {
		t.Fatalf("claimed state: %v %v", got, err)
	}
	b, _ := newBox(t)
	if got, err := Claimed(b.st); got || err != nil {
		t.Fatalf("sealed state: %v %v", got, err)
	}
}

// Open needs a store, reads the kernel boot id by default, and refuses an
// unclaimed state without a code even when its cost is in bounds.
func TestOpenChecksItsConfigAndState(t *testing.T) {
	if _, err := Open(Config{}); err == nil {
		t.Fatal("opened without a store")
	}
	b, _ := newBox(t)
	_, kerr := KernelBootID()
	if _, err := Open(Config{Store: b.st}); (err != nil) != (kerr != nil) {
		t.Fatalf("default boot id: open %v, kernel %v", err, kerr)
	}
	noCode := stateWith(t, func(m map[string]any) { delete(m, "verifier") })
	if _, err := Open(Config{Store: noCode, BootID: bootOne}); err == nil || !strings.Contains(err.Error(), "neither") {
		t.Fatalf("state without a code: %v", err)
	}
}

// A restart that lifts a lock saves the unlocked state before it opens and
// journals the unlock.
func TestARestartUnlockIsSavedAndJournaled(t *testing.T) {
	b, _, _ := lockedBox(t)
	b.boot = "boot-2"
	boot2 := func() (string, error) { return "boot-2", nil }
	if _, err := Open(Config{Store: failStore{b.st}, BootID: boot2}); err == nil {
		t.Fatal("an unsavable unlock opened")
	}
	b.journal = nil
	if c := b.start(); c.Status().Locked {
		t.Fatal("still locked after a restart")
	}
	if len(b.journal) != 1 || b.journal[0] != EventUnlocked {
		t.Fatalf("journal %q", b.journal)
	}
}

// However many locks, a boot allows one wrong code (claim.go allowed).
func TestManyLocksStillAllowOneWrongCode(t *testing.T) {
	ms := stateWith(t, func(m map[string]any) { m["locks"] = 10 })
	c, err := Open(Config{Store: ms, BootID: bootOne})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Status().TriesLeft; got != 1 {
		t.Fatalf("tries left after 10 locks: %d", got)
	}
}

// The cost bounds are inclusive at the ceiling, and a cost of no threads
// is refused even where the floor would let it through.
func TestCodeCostBounds(t *testing.T) {
	ceil := map[string]any{"time": kdfCeiling.Time, "memory_kib": kdfCeiling.MemoryKiB, "threads": kdfCeiling.Threads}
	if _, err := Open(Config{Store: stateWith(t, func(m map[string]any) { m["kdf"] = ceil }), BootID: bootOne}); err != nil {
		t.Fatalf("a cost at the ceiling: %v", err)
	}
	old := kdfFloor
	t.Cleanup(func() { kdfFloor = old })
	kdfFloor = KDF{Time: 1, MemoryKiB: 8, Threads: 0}
	none := map[string]any{"time": 1, "memory_kib": 8, "threads": 0}
	if _, err := Open(Config{Store: stateWith(t, func(m map[string]any) { m["kdf"] = none }), BootID: bootOne}); err == nil {
		t.Fatal("a cost with no threads opened")
	}
}

// A state sealed without the prefix verifier has no reserve.
func TestNoPrefixNoReserve(t *testing.T) {
	c, err := Open(Config{Store: stateWith(t, func(m map[string]any) { delete(m, "prefix") }), BootID: bootOne})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Status().Reserve; got != 0 {
		t.Fatalf("reserve without a prefix: %d", got)
	}
}

// Claimed releases the lock: Status after it returns.
func TestClaimedReleasesTheLock(t *testing.T) {
	b, _ := newBox(t)
	c := b.start()
	if c.Claimed() || c.Claimed() || c.Status().Claimed {
		t.Fatal("claimed before the claim")
	}
}

// stateOf reads the box's state from disk.
func stateOf(t *testing.T, b *box) state {
	t.Helper()
	raw, err := b.st.Load()
	if err != nil {
		t.Fatal(err)
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func lastEvent(b *box) string {
	if len(b.journal) == 0 {
		return ""
	}
	return b.journal[len(b.journal)-1]
}

// Each answer of Try writes its journal line and its counts.
func TestTryJournalsAndCounts(t *testing.T) {
	b, code := newBox(t)
	c := b.start()

	// A code of exactly the prefix's length is checked against the prefix:
	// it spends the reserve, not the shared count.
	if _, err := c.Try(Normalize(code)[:PrefixSymbols]); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("prefix-length code: %v", err)
	}
	if st := c.Status(); st.Reserve != ReserveTries-1 || st.TriesLeft != MaxWrong {
		t.Fatalf("prefix-length code counted as %+v", st)
	}
	if s := stateOf(t, b); s.Total != 1 {
		t.Fatalf("total after a reserve try: %d", s.Total)
	}
	want := fmt.Sprintf("%s (1 of %d this boot, 1 in all)", EventReserve, ReserveTries)
	if lastEvent(b) != want {
		t.Fatalf("reserve journal %q", lastEvent(b))
	}

	// A code whose prefix is wrong costs one derivation only.
	old := derive
	n := 0
	derive = func(k KDF, salt []byte, domain, s string) []byte { n++; return old(k, salt, domain, s) }
	if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	derive = old
	if n != 1 {
		t.Fatalf("a wrong-prefix code made %d derivations", n)
	}

	// The shared count locks after MaxWrong, journaling the lock; then a
	// code is refused.
	for i := 1; i < MaxWrong; i++ {
		c.Try(wrongCode(code))
	}
	if lastEvent(b) != EventLocked || !c.Status().Locked {
		t.Fatalf("lock journal %q", lastEvent(b))
	}
	if s := stateOf(t, b); s.Total != 1+MaxWrong {
		t.Fatalf("total after the lock: %d", s.Total)
	}
	if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrLocked) || lastEvent(b) != EventRefused {
		t.Fatalf("locked screen: %v, journal %q", err, lastEvent(b))
	}

	// The sticker's code still claims through the reserve, journaled.
	tok, err := c.Try(code)
	if err != nil || lastEvent(b) != EventClaimed {
		t.Fatalf("claim: %v, journal %q", err, lastEvent(b))
	}
	if _, err := c.Try(code); !errors.Is(err, ErrAlreadyClaimed) || lastEvent(b) != EventAgain {
		t.Fatalf("second claim: %v, journal %q", err, lastEvent(b))
	}
	if !c.Claimant(tok) {
		t.Fatal("claimant")
	}
}

// A count that cannot be saved locks the screen for the process and
// journals it, on the shared count and on the reserve; later codes are
// refused.
func TestUnsavedCountsJournalTheLock(t *testing.T) {
	for name, try := range map[string]func(string) string{"shared": wrongCode, "reserve": ownerTypo} {
		b, code := newBox(t)
		c := b.start()
		c.store = failStore{c.store}
		if _, err := c.Try(try(code)); !errors.Is(err, ErrLocked) || lastEvent(b) != EventLocked {
			t.Fatalf("%s: %v, journal %q", name, err, lastEvent(b))
		}
		if _, err := c.Try(code); !errors.Is(err, ErrLocked) || lastEvent(b) != EventRefused {
			t.Fatalf("%s stuck: %v, journal %q", name, err, lastEvent(b))
		}
	}
}

// The re-claim window journals each answer, and a re-claim that cannot
// draw a token fails and keeps the earlier one.
func TestReclaimJournalsAndRandomness(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	tok, err := c.TryFrom(code, phoneA)
	if err != nil {
		t.Fatal(err)
	}
	c.rand = bytes.NewReader(nil)
	if got, err := c.TryFrom(code, phoneA); err == nil || got != "" {
		t.Fatalf("re-claim without randomness: %q %v", got, err)
	}
	if !c.Claimant(tok) {
		t.Fatal("a failed re-claim dropped the claimant")
	}

	b, code = newBox(t)
	c = b.start()
	if _, err := c.TryFrom(code, phoneA); err != nil {
		t.Fatal(err)
	}
	if _, err := c.TryFrom(wrongCode(code), phoneA); !errors.Is(err, ErrAlreadyClaimed) || lastEvent(b) != EventAgain {
		t.Fatalf("wrong re-claim: %v, journal %q", err, lastEvent(b))
	}
	tok, err = c.TryFrom(code, phoneA)
	if err != nil || lastEvent(b) != EventAnswered {
		t.Fatalf("re-claim: %v, journal %q", err, lastEvent(b))
	}
	if !c.Claimant(tok) || lastEvent(b) != EventBurned {
		t.Fatalf("claimant back: journal %q", lastEvent(b))
	}
}

// NewSetupNet fails on a reader that runs out for the name or for the
// password; Marshal refuses a network NewSetupNet would not make.
func TestSetupNetErrors(t *testing.T) {
	if _, err := NewSetupNet(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("no randomness for the name: %v", err)
	}
	n, err := NewSetupNet(bytes.NewReader(make([]byte, CodeSymbols)))
	if !errors.Is(err, io.EOF) || n != (SetupNet{}) {
		t.Fatalf("no randomness for the password: %+v %v", n, err)
	}
	if _, err := (SetupNet{SSID: "x"}).Marshal(); err == nil {
		t.Fatal("marshalled an invalid network")
	}
	h := sha256.Sum256(nil)
	if _, err := NewSetupNet(bytes.NewReader(append(h[:], h[:]...))); err != nil {
		t.Fatalf("enough randomness: %v", err)
	}
}

// onceFailing fails its first read and then reads from r.
type onceFailing struct {
	failed bool
	r      io.Reader
}

func (o *onceFailing) Read(p []byte) (int, error) {
	if !o.failed {
		o.failed = true
		return 0, io.ErrUnexpectedEOF
	}
	return o.r.Read(p)
}

// A name that cannot be drawn fails NewSetupNet even when the reader
// recovers for the password.
func TestSetupNetNameError(t *testing.T) {
	h := sha256.Sum256(nil)
	if _, err := NewSetupNet(&onceFailing{r: bytes.NewReader(bytes.Repeat(h[:], 4))}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("name error: %v", err)
	}
}

// KernelBootID is the kernel's boot_id, trimmed, wherever it can be read.
func TestKernelBootIDReadsBootID(t *testing.T) {
	raw, rerr := os.ReadFile("/proc/sys/kernel/random/boot_id")
	id, err := KernelBootID()
	if rerr != nil {
		if err == nil {
			t.Fatalf("boot id %q from an unreadable file", id)
		}
		return
	}
	if err != nil || id != strings.TrimSpace(string(raw)) || id == "" {
		t.Fatalf("boot id %q %v, file %q", id, err, raw)
	}
}
