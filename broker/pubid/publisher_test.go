package pubid

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// REQ: OSS-6

type sent struct {
	day   string
	batch [][]byte
}

type fakeSender struct {
	got  []sent
	fail error
}

func (f *fakeSender) Publish(day string, batch [][]byte) error {
	f.got = append(f.got, sent{day, append([][]byte(nil), batch...)})
	return f.fail
}

// signer marks each payload with the public key that signed it.
func signer(priv ed25519.PrivateKey, payload []byte) ([]byte, error) {
	return append(append([]byte(nil), priv.Public().(ed25519.PublicKey)...), payload...), nil
}

// fixedRand returns the same byte forever, so every delay draw is the same.
type fixedRand byte

func (r fixedRand) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

type rig struct {
	c    *clock
	dir  string
	id   *Identity
	out  *fakeSender
	p    *Publisher
	rand fixedRand
}

func newRig(t *testing.T, r fixedRand) *rig {
	t.Helper()
	g := &rig{c: &clock{Reference.Add(2*24*time.Hour + 10*time.Hour)}, dir: t.TempDir(), out: &fakeSender{}, rand: r}
	var err error
	g.id, err = Open(filepath.Join(g.dir, "pubid.json"), g.c.now)
	must(t, err)
	g.reopen(t)
	return g
}

func (g *rig) reopen(t *testing.T) {
	t.Helper()
	var err error
	g.p, err = NewPublisher(Config{
		Path: filepath.Join(g.dir, "outbox.json"), Identity: g.id, Sender: g.out, Now: g.c.now,
		Signers: map[string]Signer{"artifact": signer, "attestation": signer}, Rand: g.rand,
	})
	must(t, err)
}

// day moves the clock to hour h (UTC) of n days after the rig's first day.
func (g *rig) day(n int, h time.Duration) {
	g.c.t = Reference.Add(time.Duration(2+n)*24*time.Hour + h)
}

// Nothing is published when it is queued: each item waits a drawn number
// of whole days (1 to MaxDelayDays), then leaves in that day's one batch
// at the fixed release time, so neither the hour nor the day an event
// happened shows in when it is published (OSS-6).
func TestOSS6PublicationsAreBatchedAndDelayed(t *testing.T) {
	for _, c := range []struct {
		r     fixedRand
		delay int
	}{{0, 1}, {1, 2}, {2, 3}, {3, 1}, {255, 1}} {
		g := newRig(t, c.r)
		must(t, g.p.Queue("artifact", []byte("a")))
		must(t, g.p.Release())
		for d := 1; d < c.delay; d++ {
			g.day(d, 23*time.Hour)
			must(t, g.p.Release())
		}
		g.day(c.delay, DefaultReleaseAt-time.Minute)
		must(t, g.p.Release())
		if len(g.out.got) != 0 {
			t.Fatalf("rand %d: published early: %+v", c.r, g.out.got)
		}
		g.day(c.delay, DefaultReleaseAt)
		must(t, g.p.Release())
		if len(g.out.got) != 1 || g.out.got[0].day != g.c.t.Format("2006-01-02") {
			t.Fatalf("rand %d: want one batch on day +%d, got %+v", c.r, c.delay, g.out.got)
		}
	}
}

// One batch a day, sorted, every item signed with the epoch's key at the
// time it leaves, so queue order and queue time do not show.
func TestOSS6BatchIsSortedSignedAndOncePerDay(t *testing.T) {
	g := newRig(t, 0)
	for _, p := range []string{"c", "a", "b"} {
		must(t, g.p.Queue("attestation", []byte(p)))
	}
	g.day(1, 12*time.Hour)
	must(t, g.p.Release())
	must(t, g.p.Queue("artifact", []byte("d")))
	must(t, g.p.Release())
	if len(g.out.got) != 1 {
		t.Fatalf("batches %d", len(g.out.got))
	}
	k, _, err := g.id.Key()
	must(t, err)
	pub := k.Public().(ed25519.PublicKey)
	var payloads []string
	for _, b := range g.out.got[0].batch {
		if !bytes.HasPrefix(b, pub) {
			t.Fatal("item not signed with the current key")
		}
		payloads = append(payloads, string(b[len(pub):]))
	}
	if len(payloads) != 3 || payloads[0] != "a" || payloads[1] != "b" || payloads[2] != "c" {
		t.Fatalf("batch %v", payloads)
	}
	// d waits for the next day's batch.
	g.day(2, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 2 || len(g.out.got[1].batch) != 1 {
		t.Fatalf("second batch %+v", g.out.got)
	}
	// Nothing left: no empty batch.
	g.day(3, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 2 {
		t.Fatal("empty batch published")
	}
}

// A clock stepped back behind the last published day publishes nothing
// until it is past that day again.
func TestOSS6ClockSteppedBackPublishesNothing(t *testing.T) {
	g := newRig(t, 0)
	must(t, g.p.Queue("artifact", []byte("a")))
	g.day(1, 12*time.Hour)
	must(t, g.p.Release())
	must(t, g.p.Queue("artifact", []byte("b")))
	g.day(5, 12*time.Hour)
	must(t, g.p.Release()) // b leaves on day 5
	must(t, g.p.Queue("artifact", []byte("c")))
	g.day(-1, 12*time.Hour)
	must(t, g.p.Queue("artifact", []byte("d"))) // due day 0, before the last batch
	g.day(3, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 2 {
		t.Fatalf("published with the clock behind the last batch: %+v", g.out.got)
	}
	g.day(6, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 3 || len(g.out.got[2].batch) != 2 {
		t.Fatalf("after the clock caught up: %+v", g.out.got)
	}
}

// A batch that was formed but not confirmed is resent byte for byte for
// its own day, even after a restart or a key rotation, and nothing new
// joins it; so a day is published at most once and a crash cannot make
// the same items appear under two keys.
func TestOSS6FailedBatchIsResentUnchanged(t *testing.T) {
	g := newRig(t, 0)
	must(t, g.p.Queue("artifact", []byte("a")))
	g.out.fail = errors.New("offline")
	g.day(1, 12*time.Hour)
	if err := g.p.Release(); err == nil {
		t.Fatal("send error lost")
	}
	first := g.out.got[0]
	must(t, g.p.Queue("artifact", []byte("b")))
	g.out.fail = nil
	g.c.t = Reference.Add(EpochLength + 12*time.Hour) // a new epoch
	g.reopen(t)
	must(t, g.p.Release())
	if len(g.out.got) != 2 || g.out.got[1].day != first.day || !bytes.Equal(g.out.got[1].batch[0], first.batch[0]) || len(g.out.got[1].batch) != 1 {
		t.Fatalf("resend %+v, want %+v", g.out.got[1], first)
	}
	// The next release forms the next batch, with b, under the new key.
	g.c.t = g.c.t.Add(24 * time.Hour)
	must(t, g.p.Release())
	k, e, err := g.id.Key()
	must(t, err)
	if e != 1 || len(g.out.got) != 3 || !bytes.HasPrefix(g.out.got[2].batch[0], k.Public().(ed25519.PublicKey)) {
		t.Fatalf("after resend: %+v", g.out.got)
	}
}

// Turning sharing off stops what is already queued: Clear discards every
// waiting item and an unconfirmed batch, durably, and nothing of it is
// published afterwards (UX on #163).
func TestOSS6ClearStopsWhatIsQueued(t *testing.T) {
	g := newRig(t, 0)
	must(t, g.p.Queue("artifact", []byte("a")))
	g.out.fail = errors.New("offline")
	g.day(1, 12*time.Hour)
	if err := g.p.Release(); err == nil {
		t.Fatal("send error lost")
	}
	must(t, g.p.Queue("artifact", []byte("b")))
	n, err := g.p.Clear()
	must(t, err)
	if n != 2 || g.p.Len() != 0 {
		t.Fatalf("Clear discarded %d, %d left", n, g.p.Len())
	}
	g.out.fail = nil
	g.reopen(t)
	for d := 2; d <= 5; d++ {
		g.day(d, 12*time.Hour)
		must(t, g.p.Release())
	}
	if len(g.out.got) != 1 {
		t.Fatalf("published after Clear: %+v", g.out.got[1:])
	}
}

// Only known kinds, bounded payloads and a bounded queue are accepted;
// a refusal never says what the payload was.
func TestOSS6QueueIsBounded(t *testing.T) {
	g := newRig(t, 0)
	if err := g.p.Queue("diary", []byte("x")); err == nil {
		t.Error("unknown kind queued")
	}
	if err := g.p.Queue("artifact", nil); err == nil {
		t.Error("empty payload queued")
	}
	if err := g.p.Queue("artifact", make([]byte, MaxPayload+1)); err == nil {
		t.Error("oversized payload queued")
	}
	for i := 0; i < MaxQueue; i++ {
		must(t, g.p.Queue("artifact", []byte{byte(i), byte(i >> 8)}))
	}
	if err := g.p.Queue("artifact", []byte("one more")); !errors.Is(err, ErrFull) {
		t.Errorf("queue past MaxQueue: %v", err)
	}
	// The queue survives a restart.
	g.reopen(t)
	if n := g.p.Len(); n != MaxQueue {
		t.Fatalf("after restart %d queued", n)
	}
}

// Config errors are refused at start.
func TestOSS6PublisherConfig(t *testing.T) {
	g := newRig(t, 0)
	base := Config{Path: filepath.Join(g.dir, "x.json"), Identity: g.id, Sender: g.out, Signers: map[string]Signer{"a": signer}}
	for name, mod := range map[string]func(*Config){
		"no path":     func(c *Config) { c.Path = "" },
		"no identity": func(c *Config) { c.Identity = nil },
		"no sender":   func(c *Config) { c.Sender = nil },
		"no signers":  func(c *Config) { c.Signers = nil },
		"nil signer":  func(c *Config) { c.Signers = map[string]Signer{"a": nil} },
		"late":        func(c *Config) { c.ReleaseAt = 24 * time.Hour },
		"delay":       func(c *Config) { c.MaxDelayDays = -1 },
	} {
		c := base
		mod(&c)
		if _, err := NewPublisher(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewPublisher(base); err != nil {
		t.Fatal(err)
	}
}
