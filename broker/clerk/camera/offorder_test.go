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

// TestRepinDuringTamperEventWins (#4431, #4450): turnOff holds the
// delivery lock while the key-refused event goes out, so a re-pin the owner
// makes then waits for it and wins, and the node is not left off under its
// new pin. It fails at once if turnOff emits without the lock or emits no
// event, and fails rather than hangs if the re-pin never returns.
func TestRepinDuringTamperEventWins(t *testing.T) {
	h := &hookEvents{}
	r := newRig(t, func(c *Config, _ *Node) { c.Events = h })
	n := r.c.nodes[testID]
	_, other := newCert(t)
	done := make(chan error, 1)
	var fired, held bool
	h.on = func(e Event) {
		if e.Kind != KeyRefused {
			return
		}
		fired = true
		if held = !n.deliver.TryLock(); !held {
			n.deliver.Unlock()
		}
		go func() { done <- r.c.Repin(testID, other) }()
	}
	r.c.turnOff(n, n.pin)
	if !fired {
		t.Fatal("turnOff raised no key-refused event")
	}
	if !held {
		t.Fatal("turnOff emitted the key-refused event without the delivery lock")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the re-pin never returned")
	}
	r.c.mu.Lock()
	off, pin := n.off, n.pin.Key
	r.c.mu.Unlock()
	if off || pin != other {
		t.Fatalf("off = %v under the new pin %v, want on", off, pin == other)
	}
}

// TestTurnOffAfterRemove (#4450): a Remove that lands between a mismatched
// dial and turnOff leaves nothing to turn off, so no "off" line and no
// key-refused event name the removed camera. It fails if turnOff does not
// check the node is still the clerk's.
func TestTurnOffAfterRemove(t *testing.T) {
	r := newRig(t)
	n := r.c.nodes[testID]
	r.c.Remove(testID)
	if r.c.turnOff(n, n.pin) {
		t.Fatal("turnOff turned off a removed camera")
	}
	if ev := r.ev.of(KeyRefused); len(ev) != 0 {
		t.Fatalf("key-refused events for a removed camera: %v", ev)
	}
	if l := r.log.all(); strings.Contains(l, "off:") {
		t.Fatalf("log for a removed camera: %q", l)
	}
}

// TestTurnOffAfterRemoveThenAdd (#4392): a Remove and then an Add of the
// same camera ID, under the same pin, between a mismatched dial and turnOff
// make a new node, which the old dial says nothing about. turnOff refuses,
// so the stream ends errRepinned, and the new node is not off, and no "off"
// line or key-refused event names it. It fails if turnOff compares IDs (or
// IDs and keys) rather than the node itself.
func TestTurnOffAfterRemoveThenAdd(t *testing.T) {
	r := newRig(t)
	old := r.c.nodes[testID]
	pin := old.pin
	r.c.Remove(testID)
	if err := r.c.Add(pin); err != nil {
		t.Fatal(err)
	}
	if r.c.turnOff(old, pin) {
		t.Fatal("turnOff for the removed node turned off the camera added again under its ID")
	}
	r.c.mu.Lock()
	n := r.c.nodes[testID]
	off := n != nil && n.off
	r.c.mu.Unlock()
	if n == nil || n == old || off {
		t.Fatalf("the camera added again: node %v (the old one: %v), off %v", n != nil, n == old, off)
	}
	if ev := r.ev.of(KeyRefused); len(ev) != 0 {
		t.Fatalf("key-refused events for the camera added again: %v", ev)
	}
	if l := r.log.all(); strings.Contains(l, "off:") {
		t.Fatalf("log for the camera added again: %q", l)
	}
}

// TestSilentAfterSilentEvent (#4450): STATUS reads silent only once the
// silent event is out, the order #4431 set for off. It fails if markSilent
// sets the flag before it emits.
func TestSilentAfterSilentEvent(t *testing.T) {
	h := &hookEvents{}
	r := newRig(t, func(c *Config, _ *Node) { c.Events = h })
	var during []string
	h.on = func(e Event) {
		if e.Kind == Silent {
			during = r.c.Status()
		}
	}
	r.c.markSilent(r.c.nodes[testID], testID)
	if len(during) != 1 || strings.Contains(during[0], "silent") {
		t.Fatalf("STATUS during the silent event = %q, want not yet silent", during)
	}
	if st := r.c.Status(); len(st) != 1 || !strings.Contains(st[0], "silent") {
		t.Fatalf("STATUS after = %q, want silent", st)
	}
	r.c.markSilent(r.c.nodes[testID], testID)
	if ev := h.of(Silent); len(ev) != 1 {
		t.Fatalf("%d silent events for one silence, want 1", len(ev))
	}
	if n := strings.Count(r.log.all(), "camera "+testID+": silent past its interval"); n != 1 {
		t.Fatalf("%d silent lines for one silence, want 1", n)
	}
}
