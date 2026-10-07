package main

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/daemon"
)

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

// REQ: W3-off-a
func TestW3OffALearningOffUsesSpareNote(t *testing.T) {
	var cfg daemon.Config
	n := &spareNote{}
	cfg.Notes = append(cfg.Notes, n.Line)
	learningOff(&cfg, n, "disk")
	if n.Line() != "Spare-time work: not running (disk)." {
		t.Fatalf("note: %q", n.Line())
	}
	if len(cfg.Notes) != 1 || cfg.Notes[0]() != n.Line() {
		t.Fatalf("notes len %d", len(cfg.Notes))
	}
	n.Clear()
	if cfg.Notes[0]() != "" {
		t.Fatal("cleared note still shows")
	}
}
