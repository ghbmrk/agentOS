package camera

// REQ: DEV-3, KRN-7

import (
	"strings"
	"testing"
	"time"
)

// hookEvents passes each event to on before it records it.
type hookEvents struct {
	events
	on func(Event)
}

func (h *hookEvents) Emit(e Event) error {
	if h.on != nil {
		h.on(e)
	}
	return h.events.Emit(e)
}

// TestOffAfterTamperEvent (#4431): STATUS reads off only once the
// key-refused event is out, so a reader who sees "off" finds the event.
// It fails if turnOff marks the node off before it emits.
func TestOffAfterTamperEvent(t *testing.T) {
	h := &hookEvents{}
	r := newRig(t, func(c *Config, _ *Node) { c.Events = h })
	var during []string
	h.on = func(e Event) {
		if e.Kind == KeyRefused {
			during = r.c.Status()
		}
	}
	if !r.c.turnOff(r.c.nodes[testID], r.c.nodes[testID].pin) {
		t.Fatal("turnOff refused a current pin")
	}
	if len(during) != 1 || strings.Contains(during[0], "off") {
		t.Fatalf("STATUS during the tamper event = %q, want not yet off", during)
	}
	if st := r.c.Status(); len(st) != 1 || !strings.Contains(st[0], "off") {
		t.Fatalf("STATUS after = %q, want off", st)
	}
}

// TestRepinDuringTamperEventWins (#4431): a re-pin the owner makes while
// the key-refused event is going out waits for it and then wins, so the
// node is not left off under its new pin. It fails if turnOff sets off
// without holding owner changes across the event.
func TestRepinDuringTamperEventWins(t *testing.T) {
	h := &hookEvents{}
	r := newRig(t, func(c *Config, _ *Node) { c.Events = h })
	_, other := newCert(t)
	done := make(chan error, 1)
	h.on = func(e Event) {
		if e.Kind != KeyRefused {
			return
		}
		go func() { done <- r.c.Repin(testID, other) }()
		select {
		case err := <-done:
			done <- err // an unguarded turnOff lets it land here
		case <-time.After(50 * time.Millisecond):
		}
	}
	r.c.turnOff(r.c.nodes[testID], r.c.nodes[testID].pin)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	r.c.mu.Lock()
	off, pin := r.c.nodes[testID].off, r.c.nodes[testID].pin.Key
	r.c.mu.Unlock()
	if off || pin != other {
		t.Fatalf("off = %v under the new pin %v, want on", off, pin == other)
	}
}
