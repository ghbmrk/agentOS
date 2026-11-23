package main

// REQ: DEV-7

import (
	"encoding/binary"
	"testing"

	"github.com/ghbmrk/agentos/broker/vision"
)

// thermalBase is the flat background of the frames below, 0 °C.
const thermalBase = 27315

// y16Frame is a w by h y16 frame whose sample at (x, y) is at(x, y).
func y16Frame(w, h int, at func(x, y int) int) vision.Frame {
	f := vision.Frame{Format: vision.FormatY16, Width: w, Height: h, Data: make([]byte, 2*w*h)}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			binary.LittleEndian.PutUint16(f.Data[2*(y*w+x):], uint16(at(x, y)))
		}
	}
	return f
}

// inBox reports whether (x, y) is inside b, x1 and y1 exclusive.
func inBox(b vision.Box, x, y int) bool { return x >= b.X0 && x < b.X1 && y >= b.Y0 && y < b.Y1 }

// TestHeatBlobBoxAndConfidence (MUT-kill-6409-vision, #6457): on a flat
// background a body's box is exactly its warm samples, a cold sample
// scanned before it adds nothing to it, and its confidence comes from its
// mean excess: twice the threshold is 50 + 50/3 percent. A body in the
// frame's corner is filled without stepping off the frame.
func TestHeatBlobBoxAndConfidence(t *testing.T) {
	for _, body := range []vision.Box{{X0: 5, Y0: 5, X1: 8, Y1: 8}, {X0: 0, Y0: 0, X1: 3, Y1: 3}, {X0: 17, Y0: 17, X1: 20, Y1: 20}} {
		f := y16Frame(20, 20, func(x, y int) int {
			if inBox(body, x, y) {
				return thermalBase + 2*thermalContrast
			}
			return thermalBase
		})
		ds := heatBlobs(f)
		if len(ds) != 1 || ds[0].Class != vision.Warm || ds[0].Box != body || ds[0].Conf != 50+50/3 {
			t.Errorf("body %+v: %+v", body, ds)
		}
	}
}

// TestHeatBlobCountsEachSampleOnce: a body of thermalMinArea-1 samples is
// too small, so its first sample is not counted again when its neighbour
// is filled.
func TestHeatBlobCountsEachSampleOnce(t *testing.T) {
	f := y16Frame(20, 20, func(x, y int) int {
		if y == 5 && x >= 5 && x < 5+thermalMinArea-1 {
			return thermalBase + 2*thermalContrast
		}
		return thermalBase
	})
	if ds := heatBlobs(f); len(ds) != 0 {
		t.Fatalf("a body of %d samples: %+v", thermalMinArea-1, ds)
	}
}

// TestHeatBlobsBestFirst: a warmer body scanned after a cooler one comes
// first.
func TestHeatBlobsBestFirst(t *testing.T) {
	cool, warm := vision.Box{X0: 2, Y0: 2, X1: 5, Y1: 5}, vision.Box{X0: 12, Y0: 12, X1: 15, Y1: 15}
	f := y16Frame(20, 20, func(x, y int) int {
		switch {
		case inBox(cool, x, y):
			return thermalBase + 3*thermalContrast/2
		case inBox(warm, x, y):
			return thermalBase + 3*thermalContrast
		}
		return thermalBase
	})
	ds := heatBlobs(f)
	if len(ds) != 2 || ds[0].Box != warm || ds[1].Box != cool || ds[0].Conf <= ds[1].Conf {
		t.Fatalf("%+v, want the warmer body first", ds)
	}
}

// TestHeatBlobSpreadRaisesTheThreshold: on a background whose samples
// spread d = 100 from its median (a fifth at it, the rest d either side),
// a sample is warm only thermalSpread*d over the median, so a body
// 450 over it (past thermalContrast, under 6d) is noise and one 1200 over
// it is a body.
func TestHeatBlobSpreadRaisesTheThreshold(t *testing.T) {
	const d = 100
	faint, body := vision.Box{X0: 2, Y0: 2, X1: 5, Y1: 5}, vision.Box{X0: 12, Y0: 12, X1: 15, Y1: 15}
	f := y16Frame(20, 20, func(x, y int) int {
		switch {
		case inBox(faint, x, y):
			return thermalBase + 450
		case inBox(body, x, y):
			return thermalBase + 1200
		}
		return thermalBase + [5]int{0, -d, -d, d, d}[(y*20+x)%5]
	})
	v := make([]uint16, 20*20)
	for i := range v {
		v[i] = binary.LittleEndian.Uint16(f.Data[2*i:])
	}
	if med, spread := background(v); med != thermalBase || spread != d {
		t.Fatalf("background %d, spread %d, want %d and %d", med, spread, thermalBase, d)
	}
	if ds := heatBlobs(f); len(ds) != 1 || ds[0].Box != body {
		t.Fatalf("%+v, want only the body at %+v", ds, body)
	}
}
