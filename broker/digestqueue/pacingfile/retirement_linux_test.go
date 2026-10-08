package pacingfile

import (
	"testing"
	"time"
)

// REQ: CH-15, CH-11
func TestLeaseClosePublishesRetirementBeforeWaitingForIOMutex(t *testing.T) {
	s := openLease(t, leasePath(t))
	health, ok := any(s).(interface{ PacingHealth() error })
	if !ok {
		t.Fatal("lease has no retirement health")
	}
	if health.PacingHealth() != nil {
		t.Fatal("healthy lease refused")
	}
	// Model another operation holding the lease I/O mutex; this is not a
	// filesystem latency qualification or a claim that synchronous I/O is cancelled.
	s.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for health.PacingHealth() == nil {
		select {
		case <-timer.C:
			s.mu.Unlock()
			<-done
			t.Fatal("Close retirement waited for IO mutex")
		case <-tick.C:
		}
	}
	select {
	case <-done:
		s.mu.Unlock()
		t.Fatal("Close released before active operation")
	default:
	}
	s.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if health.PacingHealth() != ErrStorage {
		t.Fatal("closed health recovered")
	}
}
