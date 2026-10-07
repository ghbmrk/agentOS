package pubid

// REQ: OSS-6

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

type memPost struct {
	bodies [][]byte
	days   []string
	fail   error
}

func (m *memPost) Post(day string, body []byte) error {
	if m.fail != nil {
		return m.fail
	}
	m.days = append(m.days, day)
	m.bodies = append(m.bodies, append([]byte(nil), body...))
	return nil
}

func TestWireIsConstantAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	tr := &memPost{}
	w := &Wire{Path: filepath.Join(dir, "sent.json"), Post: tr, Size: 128}
	if err := w.Publish("2026-10-07", [][]byte{[]byte("one")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Publish("2026-10-07", [][]byte{[]byte("one")}); err != nil {
		t.Fatal(err)
	}
	if len(tr.bodies) != 1 || len(tr.bodies[0]) != 128 {
		t.Fatalf("first send: %d bodies, len %d", len(tr.bodies), len(tr.bodies[0]))
	}
	// A different batch for a day already published is sent (N1).
	if err := w.Publish("2026-10-07", [][]byte{[]byte("two")}); err != nil {
		t.Fatal(err)
	}
	if len(tr.bodies) != 2 || len(tr.bodies[1]) != 128 {
		t.Fatalf("second batch: %d", len(tr.bodies))
	}
	if err := w.Pulse("2026-10-08"); err != nil {
		t.Fatal(err)
	}
	if len(tr.bodies) != 3 || len(tr.bodies[2]) != 128 {
		t.Fatalf("empty day: %d", len(tr.bodies))
	}
	if err := w.Pulse("2026-10-08"); err != nil || len(tr.bodies) != 3 {
		t.Fatalf("pulse repeated: %d %v", len(tr.bodies), err)
	}
	if err := w.Pulse("2026-10-07"); err != nil || len(tr.bodies) != 3 {
		t.Fatalf("pulse after a real batch: %d %v", len(tr.bodies), err)
	}
	// A restart remembers the accepted hash and does not send it again,
	// and still sends a batch it has not accepted.
	w2 := &Wire{Path: w.Path, Post: tr, Size: 128}
	if err := w2.Publish("2026-10-07", [][]byte{[]byte("one")}); err != nil || len(tr.bodies) != 3 {
		t.Fatalf("restart resent: %d %v", len(tr.bodies), err)
	}
	if err := w2.Publish("2026-10-07", [][]byte{[]byte("three")}); err != nil || len(tr.bodies) != 4 {
		t.Fatalf("restart new batch: %d %v", len(tr.bodies), err)
	}
}

func TestWireRefusesABatchThatWouldChangeTheLength(t *testing.T) {
	tr := &memPost{}
	w := &Wire{Path: filepath.Join(t.TempDir(), "sent.json"), Post: tr, Size: 16}
	err := w.Publish("2026-10-07", [][]byte{bytes.Repeat([]byte("x"), 32)})
	if err == nil || len(tr.bodies) != 0 {
		t.Fatalf("oversize: %v, sent %d", err, len(tr.bodies))
	}
}

func TestWireDoesNotRememberAFailedSend(t *testing.T) {
	tr := &memPost{fail: errors.New("down")}
	w := &Wire{Path: filepath.Join(t.TempDir(), "sent.json"), Post: tr, Size: 64}
	if err := w.Publish("2026-10-07", [][]byte{[]byte("a")}); err == nil {
		t.Fatal("accepted a failed send")
	}
	tr.fail = nil
	if err := w.Publish("2026-10-07", [][]byte{[]byte("a")}); err != nil || len(tr.bodies) != 1 {
		t.Fatalf("retry: %d %v", len(tr.bodies), err)
	}
}
