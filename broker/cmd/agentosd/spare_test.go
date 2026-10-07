package main

import "testing"

// REQ: W3-off-a
func TestW3OffASpareNoteClearsOnceRunning(t *testing.T) {
	n := &spareNote{}
	n.Off("")
	if got := n.Line(); got != learningOffNote {
		t.Fatalf("off: %q", got)
	}
	n.Off("disk")
	if got := n.Line(); got != "Spare-time work: not running (disk)." {
		t.Fatalf("cause: %q", got)
	}
	n.Clear()
	if got := n.Line(); got != "" {
		t.Fatalf("running: %q", got)
	}
}
