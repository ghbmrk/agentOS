package clock

// REQ: TIM-1

import "testing"

func TestTIM1SyncedReadsKernel(t *testing.T) {
	// The answer depends on the host; the read itself must work unprivileged.
	if _, err := Synced(); err != nil {
		t.Fatalf("Synced: %v", err)
	}
}
