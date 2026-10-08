package pubsend

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/pubid"
)

// REQ: OSS-6

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// wire is a fake Transport: it records every frame it is handed and, when
// down, refuses it; with lost set it records the frame (the far side has
// it) and still reports an error.
type wire struct {
	frames [][]byte
	down   bool
	lost   bool
	during func()
}

var errDown = errors.New("unreachable")

func (w *wire) Send(frame []byte) error {
	if w.during != nil {
		w.during()
	}
	if w.down {
		return errDown
	}
	w.frames = append(w.frames, append([]byte(nil), frame...))
	if w.lost {
		return errDown
	}
	return nil
}

type rig struct {
	dir  string
	w    *wire
	logs []string
	s    *Sender
	priv ed25519.PrivateKey
}

func newRig(t *testing.T) *rig {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	g := &rig{dir: t.TempDir(), w: &wire{}, priv: priv}
	g.reopen(t)
	return g
}

func (g *rig) reopen(t *testing.T) {
	t.Helper()
	var err error
	g.s, err = New(Config{Path: filepath.Join(g.dir, "ledger.json"), Transport: g.w,
		Log: func(s string) { g.logs = append(g.logs, s) }})
	must(t, err)
}

func (g *rig) batch(t *testing.T, day string, items ...string) []byte {
	t.Helper()
	var it [][]byte
	for _, s := range items {
		it = append(it, []byte(s))
	}
	b, err := pubid.SealBatch(g.priv, day, it)
	must(t, err)
	return b
}

func dayN(n int) string {
	return time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n).Format("2006-01-02")
}

// OSS-6s-a1 and a2, end to end: a pubid.Publisher sending through pubsend
// puts one frame of exactly FrameSize bytes on the wire every counted day,
// on days with 0, 1 and many items and on an overflow day, and an empty
// day's frame is a signed zero-item cover batch under that day's key.
func TestOSS6sA1A2OneConstantFrameEveryCountedDay(t *testing.T) {
	dir := t.TempDir()
	w := &wire{}
	s, err := New(Config{Path: filepath.Join(dir, "ledger.json"), Transport: w, Log: func(string) {}})
	must(t, err)
	now := pubid.Reference.Add(10 * time.Hour)
	clock := func() time.Time { return now }
	id, err := pubid.Open(filepath.Join(dir, "pubid.json"), clock)
	must(t, err)
	var m time.Duration
	signer := func(priv ed25519.PrivateKey, p []byte) ([]byte, error) {
		return append(append([]byte(nil), priv.Public().(ed25519.PublicKey)...), p...), nil
	}
	p, err := pubid.NewPublisher(pubid.Config{Path: filepath.Join(dir, "outbox.json"), Identity: id, Sender: s,
		Now: clock, Signers: map[string]pubid.Signer{"artifact": signer}, MaxDelayDays: 1,
		Mono: func() time.Duration { m += 24 * time.Hour; return m }})
	must(t, err)
	// Items queued the day before each test day, one slot each: a full
	// day is UsableSlots of them, and 16 overflow it by one, which carries.
	queue := map[int]int{3: 1, 4: pubid.UsableSlots, 5: 16}
	want := map[int]int{3: 0, 4: 1, 5: pubid.UsableSlots, 6: pubid.UsableSlots, 7: 1, 8: 0}
	for d := 0; d <= 8; d++ {
		now = pubid.Reference.Add(time.Duration(d)*24*time.Hour + 12*time.Hour)
		before := len(w.frames)
		must(t, p.Release())
		if d < 2 {
			continue // the clock's first two days only build the chain
		}
		if len(w.frames) != before+1 {
			t.Fatalf("day %d: %d frames", d, len(w.frames)-before)
		}
		f := w.frames[len(w.frames)-1]
		if len(f) != FrameSize {
			t.Fatalf("day %d: frame %d bytes, want %d", d, len(f), FrameSize)
		}
		b, err := pubid.OpenBatch(f)
		must(t, err)
		priv, _, err := id.Key()
		must(t, err)
		if b.Day != now.UTC().Format("2006-01-02") || !b.Key.Equal(priv.Public()) {
			t.Fatalf("day %d: batch for %s", d, b.Day)
		}
		if n, ok := want[d]; ok && len(b.Items) != n {
			t.Fatalf("day %d: %d items, want %d", d, len(b.Items), n)
		}
		for i := range queue[d] {
			must(t, p.Queue("artifact", append([]byte(fmt.Sprint(d, i, ":")), make([]byte, 1000)...)))
		}
	}
}

// OSS-6s-a4: the ledger key is (day, SHA-256 of the unpadded batch). The
// same key again is a no-op, even after a restart; a different batch for
// a day already confirmed (a clock set far back) is new and is sent.
func TestOSS6sA4IdempotentByDayAndHash(t *testing.T) {
	g := newRig(t)
	a := g.batch(t, dayN(0), "a")
	must(t, g.s.Publish(dayN(0), a))
	must(t, g.s.Publish(dayN(0), a))
	g.reopen(t)
	must(t, g.s.Publish(dayN(0), a))
	if len(g.w.frames) != 1 {
		t.Fatalf("one key sent %d times", len(g.w.frames))
	}
	b := g.batch(t, dayN(0), "b")
	must(t, g.s.Publish(dayN(0), b))
	if len(g.w.frames) != 2 || !bytes.HasPrefix(g.w.frames[1], b) {
		t.Fatal("a different batch for a confirmed day was dropped")
	}
	if err := g.s.Publish(dayN(1), a); err == nil {
		t.Fatal("a batch published under another day")
	}
	if err := g.s.Publish(dayN(0), a[:len(a)-1]); err == nil {
		t.Fatal("a broken batch was accepted")
	}
	if err := g.s.Publish(dayN(0), append(append([]byte(nil), a...), 0)); err == nil {
		t.Fatal("a batch with trailing bytes was accepted")
	}
}

// OSS-6s-a5: when the transport took the data but reported an error, the
// retry sends byte-identical frames: one logical publication, one version.
func TestOSS6sA5RetryRepeatsTheSameBytes(t *testing.T) {
	g := newRig(t)
	a := g.batch(t, dayN(0))
	g.w.lost = true
	must(t, g.s.Publish(dayN(0), a)) // durable in the ledger; the transport error waits
	if err := g.s.Flush(); err == nil {
		t.Fatal("a failing transport reported success")
	}
	g.reopen(t)
	g.w.lost = false
	must(t, g.s.Flush())
	must(t, g.s.Flush())
	if len(g.w.frames) != 3 {
		t.Fatalf("%d attempts", len(g.w.frames))
	}
	for _, f := range g.w.frames[1:] {
		if !bytes.Equal(f, g.w.frames[0]) {
			t.Fatal("a retry sent different bytes")
		}
	}
	if len(g.logs) != 0 {
		t.Fatalf("a transport error reached the owner log: %q", g.logs)
	}
}

// OSS-6s-a6: the ledger is written atomically; a crash after the
// transport accepted and before the ledger recorded it re-sends the same
// frame on restart, never a second different one.
func TestOSS6sA6CrashBeforeTheLedgerRecords(t *testing.T) {
	g := newRig(t)
	path := filepath.Join(g.dir, "ledger.json")
	var snap []byte
	g.w.during = func() {
		var err error
		snap, err = os.ReadFile(path)
		must(t, err)
	}
	a := g.batch(t, dayN(0), "a")
	must(t, g.s.Publish(dayN(0), a))
	g.w.during = nil
	// The crash: the ledger as it was while the transport held the frame.
	must(t, os.WriteFile(path, snap, 0o600))
	must(t, os.WriteFile(filepath.Join(g.dir, ".pubsend-123"), []byte("half"), 0o600))
	g.reopen(t)
	must(t, g.s.Flush())
	if len(g.w.frames) != 2 || !bytes.Equal(g.w.frames[0], g.w.frames[1]) {
		t.Fatalf("%d frames after the crash, or they differ", len(g.w.frames))
	}
	if _, err := os.Stat(filepath.Join(g.dir, ".pubsend-123")); err == nil {
		t.Fatal("a crash's temporary file was left")
	}
	must(t, g.s.Publish(dayN(0), a))
	if len(g.w.frames) != 2 {
		t.Fatal("confirmed after the retry, still sent again")
	}
	sum := sha256.Sum256(a)
	// A damaged ledger is refused, never taken as empty (which would
	// re-send with new padding).
	for name, body := range map[string]string{
		"not json":   "{",
		"unknown":    `{"waiting":[],"confirmed":[],"x":1}`,
		"bad hash":   `{"waiting":[],"confirmed":[{"day":"2026-01-08","hash":"00"}]}`,
		"bad day":    `{"waiting":[],"confirmed":[{"day":"8 Jan","hash":"` + strings.Repeat("0", 64) + `"}]}`,
		"short seed": strings.Replace(string(snap), `"seed":"`, `"seed":"AAAA`, 1),
		"other hash": strings.Replace(string(snap), hex.EncodeToString(sum[:]), strings.Repeat("0", 64), 1),
	} {
		must(t, os.WriteFile(path, []byte(body), 0o600))
		if _, err := New(Config{Path: path, Transport: g.w, Log: func(string) {}}); err == nil {
			t.Errorf("%s: a damaged ledger loaded", name)
		}
	}
}

// OSS-6s-a7: the frame is the signed batch followed by padding; padding
// is a keyed stream over a fresh random seed, so two frames of the same
// batch differ only in padding and the padding carries no structure. The
// item count is inside the signed envelope: changing it breaks the
// signature, and nothing outside the batch gives a length.
func TestOSS6sA7PaddingRevealsNothing(t *testing.T) {
	g := newRig(t)
	a := g.batch(t, dayN(0))
	must(t, g.s.Publish(dayN(0), a))
	h := newRig(t)
	h.priv = g.priv
	must(t, h.s.Publish(dayN(0), a))
	f1, f2 := g.w.frames[0], h.w.frames[0]
	if !bytes.HasPrefix(f1, a) || !bytes.HasPrefix(f2, a) {
		t.Fatal("the frame does not start with the batch")
	}
	pad1, pad2 := f1[len(a):], f2[len(a):]
	if bytes.Equal(pad1, pad2) {
		t.Fatal("two seeds gave the same padding")
	}
	// A crude check that the padding is not structured: no long run of one
	// byte, and every byte value turns up.
	var seen [256]int
	for _, c := range pad1 {
		seen[c]++
	}
	for v, n := range seen {
		if n == 0 || n > 2*len(pad1)/256 {
			t.Fatalf("byte %d appears %d times in %d bytes of padding", v, n, len(pad1))
		}
	}
	bad := append([]byte(nil), f1...)
	bad[4+1+10+32+1]++ // the low byte of the item count
	if _, err := pubid.OpenBatch(bad); err == nil {
		t.Fatal("a changed item count still verifies")
	}
}

// OSS-6s-a8: the sender reaches the network only through Transport; it
// links no network package, no process runner and no owner store, and
// pubid's own fence still holds.
func TestOSS6sA8ImportFence(t *testing.T) {
	for _, pkg := range []string{".", "../pubid"} {
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list: %v\n%s", err, out)
		}
		for _, p := range strings.Fields(string(out)) {
			if strings.HasPrefix(p, "github.com/ghbmrk/agentos/broker/") &&
				p != "github.com/ghbmrk/agentos/broker/pubid" && p != "github.com/ghbmrk/agentos/broker/pubsend" {
				t.Errorf("%s links %s", pkg, p)
			}
			if p == "net" || strings.HasPrefix(p, "net/") || p == "os/exec" || p == "crypto/tls" {
				t.Errorf("%s links %s", pkg, p)
			}
		}
	}
}

// OSS-6s-a9: with the transport unreachable, frames wait in order, at
// most MaxWaiting of them; past that the oldest is dropped and the drop
// goes to the owner-visible log only, naming no content. When the
// transport is back, what waits leaves oldest first.
func TestOSS6sA9BoundedBacklogDropsTheOldest(t *testing.T) {
	g := newRig(t)
	g.w.down = true
	var batches [][]byte
	for d := range MaxWaiting + 2 {
		b := g.batch(t, dayN(d), "secret-item")
		batches = append(batches, b)
		must(t, g.s.Publish(dayN(d), b))
	}
	if len(g.logs) != 2 {
		t.Fatalf("%d drops logged, want 2: %q", len(g.logs), g.logs)
	}
	for _, l := range g.logs {
		if strings.Contains(l, "secret") || !strings.Contains(l, "dropped") {
			t.Fatalf("drop log %q", l)
		}
	}
	g.reopen(t)
	g.w.down = false
	must(t, g.s.Flush())
	if len(g.w.frames) != MaxWaiting {
		t.Fatalf("%d frames left after the outage, want %d", len(g.w.frames), MaxWaiting)
	}
	for i, f := range g.w.frames {
		if !bytes.HasPrefix(f, batches[i+2]) {
			t.Fatalf("frame %d out of order", i)
		}
	}
}

// Config is checked: the owner log is required, since a drop must reach it.
func TestOSS6sA9OwnerLogRequired(t *testing.T) {
	if _, err := New(Config{Path: filepath.Join(t.TempDir(), "l.json"), Transport: &wire{}}); err == nil {
		t.Fatal("a sender without the owner log")
	}
}
