package main

// REQ: DEV-4, DEV-10, KRN-7

import (
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/homekit"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REV-CHK-save (#4192): a devices-file save that stops before its rename,
// as a crash would, fails the owner's step and leaves memory and the file
// as they were: a refused bounds confirmation keeps every setpoint
// actuate-physical, a refused disconnect keeps the device, and a refused
// RESUME keeps the STOP; a restart reads the same, and the steps go through
// once the save does.
func TestStoppedSaveKeepsTheOldDevices(t *testing.T) {
	for step := 0; step < 4; step++ {
		b := newBox(t)
		b.list(1)
		if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the link to open", func() bool { return b.stateOf("hall") == "open" })
		before := b.file()
		b.h.mu.Lock()
		b.h.saveStop = func(i int) bool { return i == step }
		b.h.mu.Unlock()

		if err := b.h.bounds("hall", homekit.CharTargetTemperature, 18, 23); !errors.Is(err, errSave) {
			t.Fatalf("step %d: bounds: got %v, want errSave", step, err)
		}
		if v, _ := b.h.verb("hall", homekit.CharTargetTemperature, 21); v != string(key.ActuatePhysical) {
			t.Fatalf("step %d: a refused bounds save left the setpoint %s", step, v)
		}
		b.h.mu.Lock()
		ldBounds := len(b.h.find("hall").ld.Bounds)
		b.h.mu.Unlock()
		if ldBounds != 0 {
			t.Fatalf("step %d: a refused bounds save left the link holding %d bounds", step, ldBounds)
		}
		opens := get(b, func(a *fakeAcc) int { return a.opens })
		if _, err := b.h.disconnect("hall"); !errors.Is(err, errSave) {
			t.Fatalf("step %d: disconnect: got %v, want errSave", step, err)
		}
		if b.stateOf("hall") == "" || b.file() != before {
			t.Fatalf("step %d: a refused disconnect dropped the device: %s", step, b.file())
		}
		// The device's runner starts again: a link reopens (#5048 Potency 3).
		waitFor(t, "the link to reopen after a refused disconnect", func() bool { return get(b, func(a *fakeAcc) int { return a.opens }) > opens+1 })
		b.h.stop() // its own save is stopped too; the links close regardless
		opens = get(b, func(a *fakeAcc) int { return a.opens })
		if err := b.h.resume(); !errors.Is(err, errSave) {
			t.Fatalf("step %d: resume: got %v, want errSave", step, err)
		}
		// The effect, not the rolled-back flag: no link opens after a
		// refused RESUME (#5048 Potency 2).
		for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			if n := get(b, func(a *fakeAcc) int { return a.opens }); n != opens {
				t.Fatalf("step %d: a refused RESUME opened %d link(s)", step, n-opens)
			}
		}
		if s := b.stateOf("hall"); s != "stopped" || b.file() != before {
			t.Fatalf("step %d: after a refused RESUME hall is %q, file %s", step, s, b.file())
		}

		b.restart()
		if b.stateOf("hall") == "" || b.file() != before {
			t.Fatalf("step %d: the file moved on a stopped save: %s", step, b.file())
		}
		if v, _ := b.h.verb("hall", homekit.CharTargetTemperature, 21); v != string(key.ActuatePhysical) {
			t.Fatalf("step %d: after a restart the setpoint is %s", step, v)
		}
		if removed, err := b.h.disconnect("hall"); err != nil || b.stateOf("hall") != "" {
			t.Fatalf("step %d: disconnect once the save goes through: %v, removed %v", step, err, removed)
		}
		b.halt()
	}
}
