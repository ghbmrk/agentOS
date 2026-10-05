package clock

// REQ: TIM-1

import "testing"

func TestTIM1SyncedReadsKernel(t *testing.T) {
	// The answer depends on the host; the read itself must work unprivileged.
	if _, err := Synced(); err != nil {
		t.Fatalf("Synced: %v", err)
	}
}

func TestTIM1BootClock(t *testing.T) {
	a := bootElapsed()
	if a <= 0 || bootID() == "" {
		t.Fatalf("boot elapsed %v, id %q", a, bootID())
	}
	if b := bootElapsed(); b < a {
		t.Fatalf("CLOCK_BOOTTIME went back: %v then %v", a, b)
	}
}
