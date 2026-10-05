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
		"unknown field": `{"items":[],"last":"","extra":1}`,
		"bad due":       `{"items":[{` + strings.Replace(good, "2026-01-08", "tomorrow", 1) + `}],"last":""}`,
		"empty payload": `{"items":[{` + strings.Replace(good, "eA==", "", 1) + `}],"last":""}`,
		"bad last":      `{"items":[],"last":"2026-1-8"}`,
		"bad pending":   `{"items":[],"last":"","pending":{"day":"8 Jan","batch":["eA=="]}}`,
		"empty pending": `{"items":[],"last":"","pending":{"day":"2026-01-08","batch":[]}}`,
		"too many":      `{"items":[` + strings.TrimSuffix(strings.Repeat("{"+good+"},", MaxQueue+1), ",") + `],"last":""}`,
	} {
		must(t, os.WriteFile(path, []byte(body), 0o600))
		if _, err := NewPublisher(Config{Path: path, Identity: g.id, Sender: g.out, Now: g.c.now,
			Signers: map[string]Signer{"artifact": signer}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	big := `{"items":[{"kind":"artifact","payload":"` + strings.Repeat("A", (MaxPayload/3+1)*4) + `","due":"2026-01-08"}],"last":""}`
	must(t, os.WriteFile(path, []byte(big), 0o600))
	if _, err := NewPublisher(Config{Path: path, Identity: g.id, Sender: g.out, Signers: map[string]Signer{"artifact": signer}}); err == nil {
		t.Error("an oversized payload was accepted")
	}
	must(t, os.WriteFile(path, []byte(`{"items":[{`+good+`}],"last":"2026-01-07","pending":{"day":"2026-01-07","batch":["eA=="]}}`), 0o600))
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
