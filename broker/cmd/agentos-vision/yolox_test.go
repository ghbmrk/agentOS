package main

// REQ: DEV-7

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/vision"
)

// TestSuppressKeepsDisjointBoxes (MUT-kill-6409-vision, #6457): boxes of
// one class apart on both axes have no overlap, however close their
// negative widths' product comes to their areas: both are kept.
func TestSuppressKeepsDisjointBoxes(t *testing.T) {
	a := scored{class: vision.Person, score: 0.9, x0: 0, y0: 0, x1: 100, y1: 100}
	b := scored{class: vision.Person, score: 0.8, x0: 180, y0: 180, x1: 280, y1: 280}
	if v := iou(a, b); v != 0 {
		t.Fatalf("iou of disjoint boxes: %v", v)
	}
	if out := suppress([]scored{a, b}, 640, 640); len(out) != 2 {
		t.Fatalf("%+v, want both boxes", out)
	}
}
