//go:build linux && vision_onnx && vision_real

package main

// REQ: DEV-7

import (
	"encoding/binary"
	"math"
	"math/rand"
	"path/filepath"
	"runtime/debug"
	"testing"

	ort "github.com/yalue/onnxruntime_go"

	"github.com/ghbmrk/agentos/broker/vision"
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

// maskBytes is b XOR a random key, and the key, as maskEncoding.
func maskBytes(rng *rand.Rand, b []byte) (masked, key []byte) {
	key = make([]byte, len(b))
	rng.Read(key)
	masked = make([]byte, len(b))
	for i := range masked {
		masked[i] = b[i] ^ key[i]
	}
	return masked, key
}

// maskFloats is maskBytes of v's bytes, little-endian; the byte copy is
// zeroed before it returns.
func maskFloats(rng *rand.Rand, v []float32) (masked, key []byte) {
	b := make([]byte, 4*len(v))
	defer clear(b)
	for i, x := range v {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(x))
	}
	return maskBytes(rng, b)
}

// plateRun is the run looked for in each plate buffer: 7 floats, one
// detector row's length.
const plateRun = 4 * plateRow

// maskedRun is a masked run and its key.
type maskedRun struct{ masked, key []byte }

// scanRuns is how many places in memory hold each of rs, in one pass.
func scanRuns(t *testing.T, rs []maskedRun) []int {
	t.Helper()
	found := make([]int, len(rs))
	scanMemoryFor(t, plateRun, 1, func(w []byte) bool {
		for k, r := range rs {
			j := 0
			for j < plateRun && w[j]^r.key[j] == r.masked[j] {
				j++
			}
			if j == plateRun {
				found[k]++
			}
		}
		return false
	})
	return found
}

// variedRun is the first index from from at which n values of at hold
// at least n/2 distinct values, so the run is not one also found in a
// flat background.
func variedRun(t *testing.T, n, from int, at func(int) uint32) int {
	t.Helper()
	for i := from; i < from+4096; i++ {
		d := map[uint32]bool{}
		for j := i; j < i+n; j++ {
			d[at(j)] = true
		}
		if len(d) >= n/2 {
			return i
		}
	}
	t.Fatal("no varied run across the plate")
	return 0
}

// TestRealPlatesLeaveNoCopy (#3805 point 1; DEV-7, VIS-A33): once the
// runtime's plate path has read a vehicle's plate and the caller has
// zeroed the frame, none of the buffers that held the plate is left in
// memory: the detector's input (the vehicle's pixels), its output rows
// (where the plate is), the reader's input (the plate's pixels) and the
// reader's output (its text). The test first runs the same path itself,
// on the same frame and sessions, takes a masked run of each buffer and
// zeroes its own copies; the runs give the same bytes for the same frame,
// which it checks by running it twice. ONNX Runtime frees its own copy of
// the detector's rows unzeroed (the binding copies a run-allocated output
// out and releases it; #3807), so the rows may be found as often after
// the plate path as after the test's own runs, and no more often.
func TestRealPlatesLeaveNoCopy(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	dir := realDir(t, "AGENTOS_VISION_PLATES")
	ps := loadPlates(t, dir)
	l, ro := realLoad(t)
	rng := rand.New(rand.NewSource(5))
	names := []string{"detector input", "detector rows", "reader input", "reader output"}
	// probe runs the plate path as l.plates does on the whole frame f and
	// returns masked runs of its four buffers, its own copies zeroed;
	// false when it reads no plate.
	probe := func(f vision.Frame) ([]maskedRun, bool) {
		rs := make([]maskedRun, len(names))
		in := make([]float32, 3*plateSize*plateSize)
		defer clear(in)
		pb := plateInput(f, rect{0, 0, f.Width, f.Height}, in)
		it, err := ort.NewTensor(ort.NewShape(1, 3, plateSize, plateSize), in)
		if err != nil {
			t.Fatal(err)
		}
		defer it.Destroy()
		outs := []ort.Value{nil}
		if err := l.plate.RunWithOptions([]ort.Value{it}, outs, ro); err != nil {
			t.Fatal(err)
		}
		defer outs[0].Destroy()
		rows := outs[0].(*ort.Tensor[float32]).GetData()
		defer clear(rows)
		pr, found := plateDecode(rows, pb)
		if !found {
			return nil, false
		}
		rs[1].masked, rs[1].key = maskFloats(rng, rows[:plateRow])
		// The pixel runs are taken across the plate, where they vary.
		py := int(float64(pr.y0+pr.y1)/2*pb.scale + pb.dy)
		px := int(float64(pr.x0)*pb.scale + pb.dx)
		at := variedRun(t, plateRow, py*plateSize+px, func(i int) uint32 { return math.Float32bits(in[i]) })
		rs[0].masked, rs[0].key = maskFloats(rng, in[at:at+plateRow])
		rin := make([]uint8, readerH*readerW*3)
		defer clear(rin)
		readerInput(f, pr, rin)
		at = variedRun(t, plateRun, len(rin)/2-readerW*3/2, func(i int) uint32 { return uint32(rin[i]) })
		rs[2].masked, rs[2].key = maskBytes(rng, rin[at:at+plateRun])
		rt, err := ort.NewTensor(ort.NewShape(1, readerH, readerW, 3), rin)
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Destroy()
		ot, err := ort.NewEmptyTensor[float32](ort.NewShape(1, readerSlots, int64(len(readerAlphabet))))
		if err != nil {
			t.Fatal(err)
		}
		defer ot.Destroy()
		if err := l.reader.RunWithOptions([]ort.Value{rt}, []ort.Value{ot}, ro); err != nil {
			t.Fatal(err)
		}
		read := ot.GetData()
		defer clear(read)
		if _, ok := readerDecode(read); !ok {
			return nil, false
		}
		rs[3].masked, rs[3].key = maskFloats(rng, read[:plateRow])
		for i, n := range scanRuns(t, rs) {
			if n == 0 {
				t.Fatalf("the scanner did not find the %s while the test held it", names[i])
			}
		}
		return rs, true
	}
	checked := 0
	for _, p := range ps[:20] {
		f := frameOf(t, filepath.Join(dir, p.name+"-front.jpg"), false)
		rs, ok := probe(f)
		if !ok {
			clear(f.Data)
			continue
		}
		// The same frame gives the same bytes: a second probe, under
		// fresh keys, finds a plate too, and once both have zeroed their
		// copies the first probe's runs are where only ONNX Runtime's
		// freed rows can be.
		if _, ok := probe(f); !ok {
			t.Fatal("a second run on the same frame found no plate")
		}
		base := scanRuns(t, rs)
		for i, n := range base {
			if n != 0 && i != 1 {
				t.Fatalf("%s: the test's own %s is left in memory (%d places)", p.name, names[i], n)
			}
		}
		seen := []Seen{{Detection: vision.Detection{Class: vision.Vehicle, Box: vision.Box{X1: f.Width, Y1: f.Height}, Conf: 90}}}
		if err := l.plates(f, ro, seen); err != nil {
			t.Fatal(err)
		}
		clear(f.Data)
		if seen[0].Plate == "" {
			t.Fatalf("%s: the plate path read no plate where the test's own run found one", p.name)
		}
		for i, n := range scanRuns(t, rs) {
			if n > base[i] {
				t.Errorf("%s: the plate path left its %s in memory (%d places, %d before it ran)", p.name, names[i], n, base[i])
			}
		}
		if checked++; checked == 2 {
			return
		}
	}
	t.Fatalf("a plate was read on only %d of 20 frames", checked)
}
