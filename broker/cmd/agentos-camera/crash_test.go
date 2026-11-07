package main

// REQ: DEV-10, KRN-7

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// REV-CHK-save (#4192): a settings save that stops before its rename, as a
// crash would, fails the owner's step and leaves memory and the file on the
// old settings: a refused connect adds no camera, a refused disconnect keeps
// the camera, a refused RESUME keeps the STOP and opens no stream, and a
// restart reads the same.
func TestStoppedSaveKeepsTheOldSettings(t *testing.T) {
	for step := 0; step < 4; step++ {
		b := newBox(t)
		if err := b.h.connect(b.rec("porch", "continuous", 0)); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "a stream", func() bool { return b.node.conns.Load() == 1 })
		if err := b.h.stop(); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the stream to close", func() bool { return b.node.conns.Load() == 0 })
		b.h.mu.Lock()
		b.h.saveStop = func(i int) bool { return i == step }
		b.h.mu.Unlock()

		if err := b.h.connect(b.rec("yard", "off", 0)); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: connect: got %v, want ErrStopped", step, err)
		}
		if err := b.h.disconnect("porch"); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: disconnect: got %v, want ErrStopped", step, err)
		}
		dials := b.node.dials.Load()
		if err := b.h.resume(); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: resume: got %v, want ErrStopped", step, err)
		}
		// The effect, not the rolled-back flag: no stream is dialed after a
		// refused RESUME (#5048 Potency 1).
		stays(t, "no dial after a refused RESUME", func() bool { return b.node.dials.Load() == dials && b.node.conns.Load() == 0 })
		b.h.mu.Lock()
		n, stopped := len(b.h.st.Cameras), b.h.st.Stopped
		b.h.mu.Unlock()
		b.feed.mu.Lock()
		_, yard := b.feed.added["yard"]
		b.feed.mu.Unlock()
		if n != 1 || !stopped || yard || b.node.conns.Load() != 0 {
			t.Fatalf("step %d: memory moved on a stopped save: %d cameras, stopped %v", step, n, stopped)
		}
		b.restart()
		if st := b.status(); !strings.Contains(st, "porch") || strings.Contains(st, "yard") || !strings.Contains(st, "stopped (STOP)") {
			t.Fatalf("step %d: the file moved on a stopped save:\n%s", step, st)
		}
		b.halt()
	}
}

// stays fails unless cond holds throughout 300ms, the window a run started
// before a refused save would need to dial.
func stays(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if !cond() {
			t.Fatalf("%s: it did not hold", what)
		}
	}
}
