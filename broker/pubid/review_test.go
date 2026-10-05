package pubid

// REQ: OSS-6

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// canary is a synthetic payload that must never appear in an error.
var canary = []byte("CANARY-pubid-7f3a")

// A clock stepped far ahead and then corrected neither freezes rotation
// nor stops publication (L3 MUST 1 on #163).
func TestOSS6ForwardClockStepDoesNotFreezePublication(t *testing.T) {
	g := newRig(t, 0)
	must(t, g.p.Queue("artifact", []byte("a")))
	g.c.t = g.c.t.Add(100 * 365 * 24 * time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 1 {
		t.Fatalf("the far-future batch: %+v", g.out.got)
	}
	g.day(0, 12*time.Hour)
	must(t, g.p.Queue("artifact", []byte("b")))
	g.day(1, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 2 || g.out.got[1].day != g.c.t.Format("2006-01-02") {
		t.Fatalf("after the clock was corrected: %+v", g.out.got)
	}
	k, e, err := g.id.Key()
	must(t, err)
	if e != EpochOf(g.c.t) || !bytes.HasPrefix(g.out.got[1].batch[0], k.Public().(ed25519.PublicKey)) {
		t.Fatalf("signed with a key from the wrong clock: epoch %d", e)
	}
}

// After the clock steps back by a day, the day already published is not
// published again (L3 SHOULD 1 on #163).
func TestOSS6NoSecondBatchForADay(t *testing.T) {
	g := newRig(t, 0)
	must(t, g.p.Queue("artifact", []byte("a")))
	g.day(1, 12*time.Hour)
	must(t, g.p.Release())
	g.day(0, 12*time.Hour)
	must(t, g.p.Queue("artifact", []byte("b"))) // due day 1
	g.day(1, 13*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 1 {
		t.Fatalf("a second batch for one day: %+v", g.out.got)
	}
	g.day(2, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 2 || g.out.got[1].day == g.out.got[0].day {
		t.Fatalf("next day: %+v", g.out.got)
	}
}

// A restored outbox is checked: items of a kind no longer signed are
// dropped, never a crash, and anything malformed is refused (L3 MUST 2).
func TestOSS6LoadedOutboxIsValidated(t *testing.T) {
	g := newRig(t, 0)
	must(t, g.p.Queue("attestation", []byte("x")))
	must(t, g.p.Queue("artifact", []byte("y")))
	path := filepath.Join(g.dir, "outbox.json")
	p, err := NewPublisher(Config{Path: path, Identity: g.id, Sender: g.out, Now: g.c.now,
		Signers: map[string]Signer{"artifact": signer}, Rand: g.rand})
	must(t, err)
	if p.Len() != 1 {
		t.Fatalf("items %d", p.Len())
	}
	// The drop is saved: the dropped kind does not come back.
	if q, err := NewPublisher(Config{Path: path, Identity: g.id, Sender: g.out, Now: g.c.now,
		Signers: map[string]Signer{"artifact": signer, "attestation": signer}}); err != nil || q.Len() != 1 {
		t.Fatalf("after reload: %v", err)
	}
	g.day(1, 12*time.Hour)
	must(t, p.Release())
	if len(g.out.got) != 1 || len(g.out.got[0].batch) != 1 {
		t.Fatalf("%+v", g.out.got)
	}
	good := `"kind":"artifact","payload":"eA==","due":"2026-01-08"`
	for name, body := range map[string]string{
		"unknown field": `{"items":[],"extra":1}`,
		"bad due":       `{"items":[{` + strings.Replace(good, "2026-01-08", "tomorrow", 1) + `}]}`,
		"empty payload": `{"items":[{` + strings.Replace(good, "eA==", "", 1) + `}]}`,
		"bad day":       `{"items":[],"days":["2026-1-8"]}`,
		"bad pending":   `{"items":[],"pending":{"day":"8 Jan","batch":["eA=="]}}`,
		"empty pending": `{"items":[],"pending":{"day":"2026-01-08","batch":[]}}`,
		"too many":      `{"items":[` + strings.TrimSuffix(strings.Repeat("{"+good+"},", MaxQueue+1), ",") + `]}`,
	} {
		must(t, os.WriteFile(path, []byte(body), 0o600))
		if _, err := NewPublisher(Config{Path: path, Identity: g.id, Sender: g.out, Now: g.c.now,
			Signers: map[string]Signer{"artifact": signer}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	big := `{"items":[{"kind":"artifact","payload":"` + strings.Repeat("A", (MaxPayload/3+1)*4) + `","due":"2026-01-08"}]}`
	must(t, os.WriteFile(path, []byte(big), 0o600))
	if _, err := NewPublisher(Config{Path: path, Identity: g.id, Sender: g.out, Signers: map[string]Signer{"artifact": signer}}); err == nil {
		t.Error("an oversized payload was accepted")
	}
	must(t, os.WriteFile(path, []byte(`{"items":[{`+good+`}],"days":["2026-01-07"],"pending":{"day":"2026-01-07","batch":["eA=="]}}`), 0o600))
	if _, err := NewPublisher(Config{Path: path, Identity: g.id, Sender: g.out, Signers: map[string]Signer{"artifact": signer}}); err != nil {
		t.Fatalf("a well-formed outbox: %v", err)
	}
}

// One item that fails to sign is dropped; the rest leave, and the error
// carries no payload (L3 SHOULD 2 and 4 on #163).
func TestOSS6UnsignableItemDoesNotBlockTheOutbox(t *testing.T) {
	g := newRig(t, 0)
	bad := func(priv ed25519.PrivateKey, payload []byte) ([]byte, error) {
		if bytes.Equal(payload, canary) {
			return nil, fmt.Errorf("cannot sign %s", payload)
		}
		return signer(priv, payload)
	}
	p, err := NewPublisher(Config{Path: filepath.Join(g.dir, "o2.json"), Identity: g.id, Sender: g.out, Now: g.c.now,
		Signers: map[string]Signer{"artifact": bad}, Rand: g.rand})
	must(t, err)
	must(t, p.Queue("artifact", canary))
	must(t, p.Queue("artifact", []byte("ok")))
	g.day(1, 12*time.Hour)
	err = p.Release()
	if err == nil || bytes.Contains([]byte(err.Error()), canary) || !strings.Contains(err.Error(), "1 items") {
		t.Fatalf("error %v", err)
	}
	if len(g.out.got) != 1 || len(g.out.got[0].batch) != 1 || p.Len() != 0 {
		t.Fatalf("published %+v, left %d", g.out.got, p.Len())
	}
	// Only the unsignable item, alone: nothing leaves, and it is gone.
	must(t, p.Queue("artifact", canary))
	g.day(3, 12*time.Hour)
	if err := p.Release(); err == nil || p.Len() != 0 || len(g.out.got) != 1 {
		t.Fatalf("alone: %v, left %d, batches %d", err, p.Len(), len(g.out.got))
	}
	g.day(4, 12*time.Hour)
	must(t, p.Release())
	if len(g.out.got) != 1 {
		t.Fatalf("an empty batch went out: %+v", g.out.got)
	}
}

// Refusals never echo the payload or the caller's kind (L3 SHOULD 4).
func TestOSS6RefusalsNeverEchoThePayload(t *testing.T) {
	g := newRig(t, 0)
	for _, err := range []error{
		g.p.Queue(string(canary), canary),
		g.p.Queue("artifact", append(bytes.Repeat([]byte("x"), MaxPayload), canary...)),
	} {
		if err == nil || strings.Contains(err.Error(), string(canary)) {
			t.Fatalf("refusal %v", err)
		}
	}
}

// Fixed choices are pinned (L3 SHOULD 5 on #163).
func TestOSS6Defaults(t *testing.T) {
	g := newRig(t, 0)
	p, err := NewPublisher(Config{Path: filepath.Join(g.dir, "d.json"), Identity: g.id, Sender: g.out, Signers: map[string]Signer{"a": signer}})
	must(t, err)
	if DefaultReleaseAt != 5*time.Hour || p.cfg.ReleaseAt != DefaultReleaseAt || p.cfg.Rand != rand.Reader ||
		p.cfg.MaxDelayDays != DefaultMaxDelayDays || DefaultMaxDelayDays != 3 {
		t.Fatalf("defaults %+v", p.cfg)
	}
	// The caller's signer map is copied: changing it later changes nothing.
	m := map[string]Signer{"a": signer}
	p, err = NewPublisher(Config{Path: filepath.Join(g.dir, "e.json"), Identity: g.id, Sender: g.out, Signers: m})
	must(t, err)
	delete(m, "a")
	if err := p.Queue("a", []byte("x")); errors.Is(err, ErrFull) || err != nil {
		t.Fatalf("queue after the caller's map changed: %v", err)
	}
}

// Items queued under a clock far ahead are redrawn once the clock is
// right, at release and on load, so they leave and the queue is not
// frozen (L3 round 2 MUST on #163).
func TestOSS6FarFutureDueIsRedrawn(t *testing.T) {
	g := newRig(t, 0)
	right := g.c.t
	g.c.t = right.Add(100 * 365 * 24 * time.Hour)
	for i := 0; i < MaxQueue; i++ {
		must(t, g.p.Queue("artifact", []byte{byte(i), 1}))
	}
	if err := g.p.Queue("artifact", []byte("x")); !errors.Is(err, ErrFull) {
		t.Fatalf("queue: %v", err)
	}
	g.c.t = right
	g.day(1, 12*time.Hour)
	must(t, g.p.Release()) // redrawn: each waits 1 to MaxDelayDays from now
	if len(g.out.got) != 0 {
		t.Fatal("redrawn items left at once")
	}
	g.day(2, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 1 || len(g.out.got[0].batch) != MaxQueue || g.p.Len() != 0 {
		t.Fatalf("after the clock was corrected: %d batches, %d left", len(g.out.got), g.p.Len())
	}
	must(t, g.p.Queue("artifact", []byte("y")))

	// On load too.
	h := newRig(t, 0)
	h.c.t = right.Add(100 * 365 * 24 * time.Hour)
	must(t, h.p.Queue("artifact", []byte("z")))
	h.c.t = right
	h.reopen(t)
	if d := h.p.st.Items[0].Due; d > day(right.AddDate(0, 0, DefaultMaxDelayDays)) {
		t.Fatalf("due %s not redrawn on load", d)
	}
}

// A clock before the public reference, or too far ahead for a four-digit
// year, neither queues nor publishes; a clock behind the last batch does
// not shorten the delay (L3 round 2 SHOULD 1 and 3).
func TestOSS6ImplausibleClock(t *testing.T) {
	g := newRig(t, 0)
	right := g.c.t
	for _, at := range []time.Time{time.Unix(0, 0), Reference.Add(-time.Hour), time.Date(9999, 12, 30, 12, 0, 0, 0, time.UTC)} {
		g.c.t = at
		if err := g.p.Queue("artifact", []byte("a")); !errors.Is(err, ErrClock) {
			t.Fatalf("%v: %v", at, err)
		}
	}
	g.c.t = right
	must(t, g.p.Queue("artifact", []byte("a")))
	g.c.t = time.Date(9999, 12, 31, 12, 0, 0, 0, time.UTC)
	must(t, g.p.Release())
	if len(g.out.got) != 0 {
		t.Fatal("published in year 9999")
	}
	g.reopen(t)
	// Published on day 1; the clock steps back to day -1: what is queued
	// then still waits at least a day past day 1.
	g.day(1, 12*time.Hour)
	must(t, g.p.Release())
	g.day(-1, 12*time.Hour)
	must(t, g.p.Queue("artifact", []byte("b")))
	if d := g.p.st.Items[0].Due; d <= g.out.got[0].day {
		t.Fatalf("due %s, last batch %s", d, g.out.got[0].day)
	}
}

// A day is never published twice, even after a far-future batch and a
// corrected clock (L3 round 2 SHOULD 2).
func TestOSS6NoDayTwiceAfterAWrongClock(t *testing.T) {
	g := newRig(t, 0)
	must(t, g.p.Queue("artifact", []byte("a")))
	g.day(1, 12*time.Hour)
	must(t, g.p.Release())
	right := g.c.t
	must(t, g.p.Queue("artifact", []byte("b")))
	g.c.t = right.Add(100 * 365 * 24 * time.Hour)
	must(t, g.p.Release())
	g.c.t = right
	must(t, g.p.Queue("artifact", []byte("c")))
	g.day(1, 20*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 2 {
		t.Fatalf("day 1 published again: %+v", g.out.got)
	}
	g.day(5, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 3 {
		t.Fatalf("publication did not resume: %d", len(g.out.got))
	}
	for i, a := range g.out.got {
		for _, b := range g.out.got[i+1:] {
			if a.day == b.day {
				t.Fatalf("day %s twice", a.day)
			}
		}
	}
}

// Temporary files a crash left are swept at start, and an identity
// directory others can write is refused (L3 round 2 SHOULD 4, nit).
func TestOSS6StartSweepsAndChecksTheDirectory(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, ".pubid-123")
	must(t, os.WriteFile(stale, []byte("old seed"), 0o600))
	c := &clock{Reference.Add(time.Hour)}
	id, err := Open(filepath.Join(dir, "pubid.json"), c.now)
	must(t, err)
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Open left a stale temporary file")
	}
	must(t, os.WriteFile(stale, []byte("old outbox"), 0o600))
	_, err = NewPublisher(Config{Path: filepath.Join(dir, "o.json"), Identity: id, Sender: &fakeSender{}, Signers: map[string]Signer{"a": signer}})
	must(t, err)
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("NewPublisher left a stale temporary file")
	}
	must(t, os.Chmod(dir, 0o777))
	defer os.Chmod(dir, 0o700)
	if _, err := Open(filepath.Join(dir, "pubid.json"), c.now); err == nil {
		t.Fatal("a directory others can write was accepted")
	}
}

// Loading under an implausible clock redraws nothing, so the delay is not
// lost; the outbox remembers at most maxDays published days.
func TestOSS6LoadUnderAWrongClockAndDayHistory(t *testing.T) {
	g := newRig(t, 0)
	right := g.c.t
	must(t, g.p.Queue("artifact", []byte("a")))
	due := g.p.st.Items[0].Due
	g.c.t = time.Unix(0, 0)
	g.reopen(t)
	g.c.t = right
	g.reopen(t)
	if d := g.p.st.Items[0].Due; d != due {
		t.Fatalf("due moved from %s to %s under a wrong clock", due, d)
	}
	for n := 1; n <= maxDays+6; n++ {
		g.day(n-1, 13*time.Hour)
		must(t, g.p.Queue("artifact", []byte{byte(n), 2}))
		g.day(n, 12*time.Hour)
		must(t, g.p.Release())
	}
	if len(g.p.st.Days) != maxDays {
		t.Fatalf("%d days remembered", len(g.p.st.Days))
	}
	g.reopen(t)
	path := filepath.Join(g.dir, "outbox.json")
	days := `"` + strings.TrimSuffix(strings.Repeat(`2026-01-08","`, maxDays+1), `","`) + `"`
	must(t, os.WriteFile(path, []byte(`{"items":[],"days":[`+days+`]}`), 0o600))
	if _, err := NewPublisher(Config{Path: path, Identity: g.id, Sender: g.out, Signers: map[string]Signer{"a": signer}}); err == nil {
		t.Fatal("an outbox with too many days was accepted")
	}
}
