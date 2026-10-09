package pubid

// REQ: OSS-6

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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
	if len(g.out.got) != 0 {
		t.Fatalf("a jump counted as days passing: %+v", g.out.got)
	}
	g.day(0, 12*time.Hour)
	must(t, g.p.Release())
	must(t, g.p.Queue("artifact", []byte("b")))
	g.day(1, 12*time.Hour)
	must(t, g.p.Release()) // after a jump, the first one-day step only rebuilds the chain
	g.day(2, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 1 || len(g.out.got[0].batch) != 2 || g.out.got[0].day != g.c.t.Format("2006-01-02") {
		t.Fatalf("after the clock was corrected: %+v", g.out.got)
	}
	k, e, err := g.id.Key()
	must(t, err)
	if e != EpochOf(g.c.t) || !bytes.HasPrefix(g.out.got[0].batch[0], k.Public().(ed25519.PublicKey)) {
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
	must(t, g.p.Release())
	must(t, g.p.Queue("artifact", []byte("b")))
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
	good := `"kind":"artifact","payload":"eA==","wait":2`
	priv, _, err := g.id.Key()
	must(t, err)
	raw, err := SealBatch(priv, "2026-01-07", [][]byte{[]byte("x")})
	must(t, err)
	sealed := base64.StdEncoding.EncodeToString(raw)
	for name, body := range map[string]string{
		"unknown field": `{"items":[],"extra":1}`,
		"no wait":       `{"items":[{` + strings.Replace(good, `"wait":2`, `"wait":0`, 1) + `}]}`,
		"long wait":     `{"items":[{` + strings.Replace(good, `"wait":2`, `"wait":257`, 1) + `}]}`,
		"bad seen":      `{"items":[],"seen":"today"}`,
		"empty payload": `{"items":[{` + strings.Replace(good, "eA==", "", 1) + `}]}`,
		"bad day":       `{"items":[],"days":["2026-1-8"]}`,
		"bad pending":   `{"items":[],"pending":{"day":"8 Jan","batch":"` + sealed + `"}}`,
		"other day":     `{"items":[],"pending":{"day":"2026-01-08","batch":"` + sealed + `"}}`,
		"unsealed":      `{"items":[],"pending":{"day":"2026-01-07","batch":"eA=="}}`,
		"empty pending": `{"items":[],"pending":{"day":"2026-01-08","batch":""}}`,
		"too many":      `{"items":[` + strings.TrimSuffix(strings.Repeat("{"+good+"},", MaxQueue+1), ",") + `]}`,
	} {
		must(t, os.WriteFile(path, []byte(body), 0o600))
		if _, err := NewPublisher(Config{Path: path, Identity: g.id, Sender: g.out, Now: g.c.now,
			Signers: map[string]Signer{"artifact": signer}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	big := `{"items":[{"kind":"artifact","payload":"` + strings.Repeat("A", (MaxPayload/3+1)*4) + `","wait":1}]}`
	must(t, os.WriteFile(path, []byte(big), 0o600))
	if _, err := NewPublisher(Config{Path: path, Identity: g.id, Sender: g.out, Signers: map[string]Signer{"artifact": signer}}); err == nil {
		t.Error("an oversized payload was accepted")
	}
	must(t, os.WriteFile(path, []byte(`{"items":[{`+good+`}],"days":["2026-01-07"],"pending":{"day":"2026-01-07","batch":"`+sealed+`"}}`), 0o600))
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
		Signers: map[string]Signer{"artifact": bad}, Rand: g.rand, Mono: g.mono})
	must(t, err)
	g.warm(t, p)
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
	g.day(2, 12*time.Hour)
	if err := p.Release(); err == nil || p.Len() != 0 || len(g.out.got) != 1 {
		t.Fatalf("alone: %v, left %d, batches %d", err, p.Len(), len(g.out.got))
	}
	g.day(3, 12*time.Hour)
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
		p.cfg.MaxDelayDays != DefaultMaxDelayDays || DefaultMaxDelayDays != 3 || minCountGap != 20*time.Hour ||
		p.cfg.Mono == nil || p.cfg.Mono() <= 0 {
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

// Items queued under a clock far ahead carry no date, so once the clock
// is right they leave after their delay and a full queue drains (L3
// round 2 MUST on #163).
func TestOSS6FarAheadQueueDrains(t *testing.T) {
	g := newRig(t, 0)
	right := g.c.t
	g.c.t = right.Add(100 * 365 * 24 * time.Hour)
	must(t, g.p.Release())
	for i := 0; i < MaxQueue; i++ {
		must(t, g.p.Queue("artifact", []byte{byte(i), 1}))
	}
	if err := g.p.Queue("artifact", []byte("x")); !errors.Is(err, ErrFull) {
		t.Fatalf("queue: %v", err)
	}
	g.c.t = right
	g.reopen(t)
	must(t, g.p.Release()) // a jump back counts nothing
	// Queued under a clock no release counted, each waits a day more, and
	// the first day after the jump only rebuilds the chain. Each item takes
	// a slot, so the full queue then leaves UsableSlots a day, carried in
	// cohort order (OSS-6s-a3).
	for d := 1; d <= 3; d++ {
		g.day(d, 12*time.Hour)
		must(t, g.p.Release())
	}
	if len(g.out.got) != 1 || len(g.out.got[0].batch) != UsableSlots {
		t.Fatalf("after the clock was corrected: %d batches, %d left", len(g.out.got), g.p.Len())
	}
	days := (MaxQueue + UsableSlots - 1) / UsableSlots
	for d := 4; d < 3+days; d++ {
		g.day(d, 12*time.Hour)
		must(t, g.p.Release())
	}
	if len(g.out.got) != days || g.p.Len() != 0 {
		t.Fatalf("drained in %d batches, %d left", len(g.out.got), g.p.Len())
	}
}

// L3 round 4 MUST 1, as probed: queued at 02:00 with a 3-day delay; a
// reboot after the release time with the clock 1 to 60 days behind, and a
// release; the clock is corrected. The item never leaves before its third
// day, with no reopen in between; after a jump it leaves by its fifth.
func TestOSS6ClockBehindKeepsTheDelay(t *testing.T) {
	for _, back := range []int{1, 2, 10, 25, 26, 27, 28, 29, 40, 60} {
		g := newRig(t, 2) // every delay is 3 days
		for d := 1; d < 10; d++ {
			g.day(d, 12*time.Hour)
			must(t, g.p.Release())
		}
		g.day(10, 2*time.Hour)
		must(t, g.p.Queue("artifact", []byte("a")))
		g.day(10-back, 6*time.Hour)
		must(t, g.p.Release())
		for d := 10; d < 13; d++ {
			for h := 6; h < 24; h++ {
				g.day(d, time.Duration(h)*time.Hour)
				must(t, g.p.Release())
			}
		}
		if len(g.out.got) != 0 {
			t.Fatalf("back %d days: left on %s", back, g.out.got[0].day)
		}
		for d := 13; d <= 15; d++ {
			g.day(d, 6*time.Hour)
			must(t, g.p.Release())
		}
		if len(g.out.got) != 1 {
			t.Fatalf("back %d days: %+v", back, g.out.got)
		}
	}
}

// A delay longer than any clock threshold is kept whole (L3 round 4 MUST
// 2): there is no threshold.
func TestOSS6LongDelayIsKept(t *testing.T) {
	g := newRig(t, 0)
	p, err := NewPublisher(Config{Path: filepath.Join(g.dir, "long.json"), Identity: g.id, Sender: g.out, Now: g.c.now,
		Signers: map[string]Signer{"a": signer}, MaxDelayDays: 60, Rand: fixedRand(59), Mono: g.mono})
	must(t, err)
	g.day(0, 6*time.Hour)
	g.warm(t, p)
	must(t, p.Queue("a", []byte("x")))
	for d := 1; d < 60; d++ {
		g.day(d, 6*time.Hour)
		must(t, p.Release())
	}
	if len(g.out.got) != 0 {
		t.Fatalf("a 60-day delay left on %s", g.out.got[0].day)
	}
	g.day(60, 6*time.Hour)
	must(t, p.Release())
	if len(g.out.got) != 1 {
		t.Fatal("did not leave on day 60")
	}
}

// A clock before the public reference, or too far ahead for a four-digit
// year, neither queues nor counts (L3 round 2 SHOULD 3).
func TestOSS6ImplausibleClock(t *testing.T) {
	g := newRig(t, 0)
	right := g.c.t
	for _, at := range []time.Time{time.Unix(0, 0), Reference.Add(-time.Hour), time.Date(10000, 1, 1, 12, 0, 0, 0, time.UTC)} {
		g.c.t = at
		if err := g.p.Queue("artifact", []byte("a")); !errors.Is(err, ErrClock) {
			t.Fatalf("%v: %v", at, err)
		}
	}
	g.c.t = right
	must(t, g.p.Queue("artifact", []byte("a")))
	g.c.t = time.Date(10000, 1, 1, 12, 0, 0, 0, time.UTC)
	must(t, g.p.Release())
	if len(g.out.got) != 0 || g.p.st.Seen != day(right) {
		t.Fatal("counted in year 10000")
	}
	g.reopen(t)
	g.day(1, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 1 {
		t.Fatal("did not leave once the clock was plausible")
	}
}

// A day is never published twice, after a far-future batch and a corrected
// clock, or after days counted under a clock 5 to 28 days ahead (L3 round
// 2 SHOULD 2; round 4 SHOULD 1).
func TestOSS6NoDayTwiceAfterAWrongClock(t *testing.T) {
	for _, ahead := range []int{36500, 5, 10, 28} {
		g := newRig(t, 0)
		for d := 0; d < 3; d++ {
			g.day(d, 12*time.Hour)
			must(t, g.p.Queue("artifact", []byte{byte(d), 1}))
			must(t, g.p.Release())
		}
		// The clock runs ahead for a week, publishing every day.
		for d := 3; d < 10; d++ {
			g.day(d+ahead, 12*time.Hour)
			must(t, g.p.Release())
			must(t, g.p.Queue("artifact", []byte{byte(d), 2}))
		}
		// Corrected, it runs right for two months.
		for d := 10; d < 70; d++ {
			g.day(d, 12*time.Hour)
			must(t, g.p.Release())
			must(t, g.p.Queue("artifact", []byte{byte(d), 3}))
		}
		days := map[string]bool{}
		for _, b := range g.out.got {
			if days[b.day] {
				t.Fatalf("ahead %d: day %s twice", ahead, b.day)
			}
			days[b.day] = true
		}
		if len(g.out.got) < 60-ahead%60 || g.p.Len() > 1 {
			t.Fatalf("ahead %d: publication did not resume: %d batches, %d left", ahead, len(g.out.got), g.p.Len())
		}
	}
}

// Temporary files a crash left are swept at start, and a directory that
// is a symlink, belongs to another user, or is writable by its group or by
// anyone is refused, for the identity and the outbox alike (L3 round 2
// SHOULD 4; round 3 SHOULD 3; round 4 SHOULD 2).
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
	open := func(d string) []error {
		_, e1 := Open(filepath.Join(d, "pubid.json"), c.now)
		_, e2 := NewPublisher(Config{Path: filepath.Join(d, "o.json"), Identity: id, Sender: &fakeSender{}, Signers: map[string]Signer{"a": signer}})
		return []error{e1, e2}
	}
	for _, mode := range []os.FileMode{0o720, 0o702, 0o777} {
		d := filepath.Join(t.TempDir(), "d")
		must(t, os.Mkdir(d, 0o700))
		must(t, os.Chmod(d, mode))
		for _, err := range open(d) {
			if err == nil {
				t.Fatalf("mode %o accepted", mode)
			}
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	must(t, os.Symlink(dir, link))
	for _, err := range open(link) {
		if err == nil {
			t.Fatal("a symlinked directory was accepted")
		}
	}
	if os.Geteuid() == 0 {
		d := filepath.Join(t.TempDir(), "theirs")
		must(t, os.Mkdir(d, 0o700))
		must(t, os.Chown(d, 4242, 4242))
		for _, err := range open(d) {
			if err == nil {
				t.Fatal("another user's directory was accepted")
			}
		}
	}
}

// The outbox remembers the newest maxDays counted days, and a step back of
// a day publishes nothing; loading under a wrong clock changes nothing.
func TestOSS6DayHistory(t *testing.T) {
	g := newRig(t, 0)
	right := g.c.t
	must(t, g.p.Queue("artifact", []byte("a")))
	g.c.t = time.Unix(0, 0)
	g.reopen(t)
	g.c.t = right
	g.reopen(t)
	if it := g.p.st.Items[0]; it.Wait != 1 {
		t.Fatalf("item changed under a wrong clock: %+v", it)
	}
	for n := 1; n <= maxDays+6; n++ {
		g.day(n, 12*time.Hour)
		must(t, g.p.Release())
		must(t, g.p.Queue("artifact", []byte{byte(n), byte(n >> 8), 2}))
	}
	if len(g.p.st.Days) != maxDays || g.p.st.Days[maxDays-1] != g.out.got[len(g.out.got)-1].day {
		t.Fatalf("%d days remembered, newest %s", len(g.p.st.Days), g.p.st.Days[len(g.p.st.Days)-1])
	}
	n := len(g.out.got)
	g.day(maxDays+5, 13*time.Hour)
	must(t, g.p.Release())
	g.day(maxDays+6, 13*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != n {
		t.Fatal("a day was published twice after a one-day step back")
	}
}

// An outbox in a directory others can write is refused: they could swap
// in items for the box to sign (L3 round 3 SHOULD 3).
func TestOSS6OutboxDirectoryMode(t *testing.T) {
	g := newRig(t, 0)
	dir := filepath.Join(t.TempDir(), "open")
	must(t, os.Mkdir(dir, 0o700))
	must(t, os.Chmod(dir, 0o777))
	if _, err := NewPublisher(Config{Path: filepath.Join(dir, "o.json"), Identity: g.id, Sender: g.out, Signers: map[string]Signer{"a": signer}}); err == nil {
		t.Fatal("an outbox directory others can write was accepted")
	}
}
