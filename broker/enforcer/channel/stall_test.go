package channel

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// REQ: NET-2

// stallTimeout is the tests' write bound: short, so a stalled write ends
// quickly, and far below the 5 s every wait here allows.
const stallTimeout = 50 * time.Millisecond

// inTime runs f and returns its error, failing the test if f takes 5 s.
func inTime(t *testing.T, what string, f func() error) error {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- f() }()
	select {
	case err := <-errc:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: still blocked after 5 s", what)
		return nil
	}
}

// stalledRig is a rig whose core has said hello and then stops reading.
func stalledRig(t *testing.T) (*rig, *client) {
	t.Helper()
	r := newRig(t, func(c *Config) { c.SendTimeout = stallTimeout })
	cl := r.dial()
	waitLines(t, r, 1)
	return r, cl
}

// TestStalledCoreCannotHoldAlert (#4307, NET-2 Texts and calls): a core
// that stops reading fails Channel.Alert within the send timeout, and once
// one write has passed its deadline every later send on that connection
// fails at once, Alert and Challenge alike, rather than waiting a timeout
// each or writing after a frame that may be cut short. The core's next
// frame then ends the connection unacted. Revert mutants: no write
// deadline (Alert blocks); no stop after a stalled write (the second
// Alert waits on its own deadline, here an hour); no check in Serve's
// loop (the announce is acted on and logged).
func TestStalledCoreCannotHoldAlert(t *testing.T) {
	r, cl := stalledRig(t)
	a := wire.Alert{Kind: wire.AlertText, Text: "a text"}
	start := time.Now()
	err := inTime(t, "an alert to a core that stopped reading", func() error { return r.ch.Alert(a) })
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("an alert to a core that stopped reading: %v, want the write deadline", err)
	}
	if d := time.Since(start); d < stallTimeout {
		t.Errorf("the alert failed after %v, before its %v deadline", d, stallTimeout)
	}

	// Any later write would wait an hour, so only the stop answers at once.
	r.ch.mu.Lock()
	s := r.ch.session
	r.ch.mu.Unlock()
	s.mu.Lock()
	s.timeout = time.Hour
	s.mu.Unlock()
	if err := inTime(t, "a second alert", func() error { return r.ch.Alert(a) }); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a second alert after a stalled write: %v, want the first's error", err)
	}
	if err := inTime(t, "a challenge", func() error { return r.ch.Challenge(7, []byte{1}) }); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a challenge after a stalled write: %v, want the first's error", err)
	}
	r.ch.mu.Lock()
	held := len(r.ch.challenges)
	r.ch.mu.Unlock()
	if held != 0 {
		t.Errorf("%d challenges held after their write failed", held)
	}

	n := len(r.events())
	cl.send(wire.Announce{ID: 1})
	select {
	case err := <-cl.done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("the connection ended with %v, want the stalled write's error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a frame after a stalled write did not end the connection")
	}
	for _, e := range r.events()[n:] {
		if e.Kind == KindAnnounce {
			t.Errorf("a request was acted on after the core stopped reading: %+v", e)
		}
	}
}

// TestStalledCoreKeepsAlertLog (#4307, Security delta on #4287 comment
// 6544047963 point 2): with the channel as the alert log's Send and a
// core that stops reading, every alert raised still returns and reaches
// the local log, the later ones as well as the first, so a stalled core
// holds up neither the record nor the light. Revert mutant: no write
// deadline (the first Raise never returns and the rest queue behind it).
func TestStalledCoreKeepsAlertLog(t *testing.T) {
	r, _ := stalledRig(t)
	log, err := alert.New(alert.Config{Send: r.ch.Alert, Light: &bulb{}, Journal: &journal{}})
	if err != nil {
		t.Fatal(err)
	}
	const raised = 5
	err = inTime(t, "raising alerts with the core stalled", func() error {
		for i := range raised {
			if _, err := log.Raise(alert.UnusualUnlock, fmt.Sprintf("door%d", i)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	recs := log.Log()
	if len(recs) != raised {
		t.Fatalf("%d alerts in the log, want %d", len(recs), raised)
	}
	for _, rec := range recs {
		if rec.Sent {
			t.Errorf("alert %d marked sent to a core that never read it", rec.ID)
		}
	}
}

// bulb is a light that takes every colour.
type bulb struct{}

func (*bulb) Show(alert.Colour) error { return nil }

// journal is an alert journal in memory.
type journal struct {
	mu sync.Mutex
	b  []byte
}

func (j *journal) Load() ([]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]byte(nil), j.b...), nil
}

func (j *journal) Append(p []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.b = append(j.b, p...)
	return nil
}

func (j *journal) Truncate(n int) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.b = j.b[:n]
	return nil
}
