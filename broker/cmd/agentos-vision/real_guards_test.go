//go:build linux && vision_onnx && vision_real

package main

// REQ: DEV-7

import (
	"math"
	"math/rand"
	"path/filepath"
	"runtime/debug"
	"testing"
)

// The real runtime's guards for D-207 and VIS-A7 (#3792), run by
// .github/workflows/vision-real.yml with the pinned models and face set:
// the runtime encodes no face it is told not to, and leaves no encoding
// in memory once its caller has zeroed the copy it was given. The
// garbage collector is off in each, so freed memory is not reused and
// keeps whatever was left in it (as TestThermalLeavesNoFrameCopy).

// realRuntime is the real runtime from AGENTOS_VISION_MODELS, loaded.
func realRuntime(t *testing.T) Runtime {
	t.Helper()
	rt := newRuntime(realDir(t, "AGENTOS_VISION_MODELS"), 2)
	if _, err := rt.Load(); err != nil {
		t.Fatalf("the real runtime did not load: %v", err)
	}
	return rt
}

// maskEncoding is the first 64 bytes of v, little-endian, XOR a random
// key, and the key, so the test never holds the run it looks for.
func maskEncoding(rng *rand.Rand, v []float32) (masked, key []byte) {
	const n = 64
	key = make([]byte, n)
	rng.Read(key)
	masked = make([]byte, n)
	for i := range masked {
		masked[i] = byte(math.Float32bits(v[i/4])>>(8*(i%4))) ^ key[i]
	}
	return masked, key
}

// encoderRuns is how many times the real runtime's current load has
// run the face encoder.
func encoderRuns(t *testing.T, rt Runtime) int64 {
	t.Helper()
	l, ok := rt.(*onnxRuntime).current()
	if !ok {
		t.Fatal("the real runtime has no load")
	}
	return l.encodes.Load()
}

// TestRealEnrolZeroesEncoderOutput (#3792 item 2): once Encode has
// returned an enrolment portrait's encoding and the caller has zeroed
// it, no run of its bytes is left in memory, so the encoder zeroed its
// own output tensor.
func TestRealEnrolZeroesEncoderOutput(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	dir := realDir(t, "AGENTOS_VISION_FACES")
	rt := realRuntime(t)
	rng := rand.New(rand.NewSource(1))
	p := frameOf(t, filepath.Join(dir, "images", faceNames(t, dir)[0]), false)
	v, err := rt.Encode(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	masked, key := maskEncoding(rng, v)
	if found := scanMemory(t, masked, key); found == 0 {
		t.Fatal("the scanner did not find the encoding while the caller held it")
	}
	clear(v)
	clear(p.Data)
	if found := scanMemory(t, masked, key); found != 0 {
		t.Fatalf("the encoding is left in memory (%d places) after Encode", found)
	}
}

// TestRealFacesNotEncodedWhenNoneEnrolled (#3792 item 1; D-207): on
// sightings of people whose faces Detect encodes when told to, Detect
// told not to (as the service does while it holds no template) reports
// no encoding on any face, runs the face encoder not once, and leaves
// none of the frame's encoding in memory: each frame's encoding, taken
// first and zeroed, is not found again after the call. The runtime gives
// the same encoding for the same frame, which the test checks first.
func TestRealFacesNotEncodedWhenNoneEnrolled(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	dir := realDir(t, "AGENTOS_VISION_FACES")
	names := faceNames(t, dir)
	rt := realRuntime(t)
	rng := rand.New(rand.NewSource(2))
	encoded := 0
	for _, n := range names[:8] {
		f := sighting(rng, frameOf(t, filepath.Join(dir, "images", n), false), 1280, 720, 0.4, 0.8, false)
		runs := encoderRuns(t, rt)
		seen, err := rt.Detect(f, true)
		if err != nil {
			t.Fatalf("detect: %v", err)
		}
		var masked, key []byte
		for _, s := range seen {
			if len(s.Face) > 0 && masked == nil {
				masked, key = maskEncoding(rng, s.Face)
			}
			clear(s.Face)
		}
		if masked == nil {
			continue
		}
		encoded++
		if encoderRuns(t, rt) == runs {
			t.Fatal("a face was encoded with no encoder run counted")
		}
		if encoded == 1 {
			again, err := rt.Detect(f, true)
			if err != nil {
				t.Fatalf("detect: %v", err)
			}
			if found := scanMemory(t, masked, key); found == 0 {
				t.Fatal("the same frame gave another encoding, or the scanner did not find it")
			}
			for _, s := range again {
				clear(s.Face)
			}
		}
		runs = encoderRuns(t, rt)
		seen, err = rt.Detect(f, false)
		if err != nil {
			t.Fatalf("detect: %v", err)
		}
		if got := encoderRuns(t, rt) - runs; got != 0 {
			t.Fatalf("%s: the face encoder ran %d times although Detect was told not to encode", n, got)
		}
		for _, s := range seen {
			if len(s.Face) != 0 {
				t.Fatalf("%s: a face was encoded although Detect was told not to", n)
			}
		}
		if found := scanMemory(t, masked, key); found != 0 {
			t.Fatalf("%s: the face's encoding is left in memory (%d places) after this frame's Detect calls", n, found)
		}
		clear(f.Data)
	}
	if encoded < 6 {
		t.Fatalf("only %d of 8 sightings had a face encoded when told to", encoded)
	}
}
