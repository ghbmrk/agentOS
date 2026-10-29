package main

// REQ: DEV-7, RES-2, RES-3

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/vision"
)

// row writes one detector output row at anchor k of out: a box centred
// at (cx, cy) of bw by bh input pixels on the grid of stride s, with the
// objectness and one class's score.
func row(out []float32, size, s, gx, gy int, cx, cy, bw, bh float64, obj float32, class int, score float32) {
	k := 0
	for _, st := range yoloxStrides {
		if st == s {
			break
		}
		k += (size / st) * (size / st)
	}
	k += gy*(size/s) + gx
	p := out[k*yoloxRow : (k+1)*yoloxRow]
	p[0] = float32(cx/float64(s) - float64(gx))
	p[1] = float32(cy/float64(s) - float64(gy))
	p[2] = float32(math.Log(bw / float64(s)))
	p[3] = float32(math.Log(bh / float64(s)))
	p[4] = obj
	p[5+class] = score
}

func TestYoloxDecodeMapsAndSuppresses(t *testing.T) {
	const size = yoloxSize
	out := make([]float32, yoloxAnchors(size)*yoloxRow)
	// A frame of 832x416 scaled by a half into the input.
	lb := letterbox{scale: 0.5}
	row(out, size, 8, 10, 10, 84, 84, 40, 80, 0.9, 0, 0.9)     // a person, 81%
	row(out, size, 16, 10, 10, 168, 168, 100, 60, 0.9, 2, 0.8) // a car, 72%
	row(out, size, 16, 11, 10, 170, 168, 100, 60, 0.9, 7, 0.7) // the same thing as a truck: suppressed
	row(out, size, 32, 5, 5, 176, 176, 64, 64, 0.9, 9, 0.9)    // a traffic light: off the list
	row(out, size, 8, 30, 30, 244, 244, 20, 20, 0.5, 16, 0.5)  // a dog at 25%: under the floor
	row(out, size, 8, 40, 20, 324, 164, 30, 30, 0.8, 17, 0.9)  // a horse: unknown-animal, 72%
	row(out, size, 32, 12, 5, 410, 176, 60, 60, 0.9, 21, 0.9)  // a bear over the right edge: clamped
	row(out, size, 32, 12, 12, 410, 410, 60, 60, 0.9, 0, 0.9)  // a person below the frame: dropped
	nan := make([]float32, yoloxRow)
	row(nan, size, 8, 0, 0, 4, 4, 8, 8, 0.9, 0, 0.9)
	nan[2] = float32(math.NaN())
	copy(out[1*yoloxRow:], nan) // a NaN box: dropped
	ds := yoloxDecode(out, size, lb, 832, 416)
	// Best first; equal scores keep the detector's row order.
	want := []vision.Detection{
		{Class: vision.Person, Box: vision.Box{X0: 128, Y0: 88, X1: 208, Y1: 248}, Conf: 81},
		{Class: vision.Bear, Box: vision.Box{X0: 760, Y0: 292, X1: 832, Y1: 412}, Conf: 81},
		{Class: vision.UnknownAnimal, Box: vision.Box{X0: 618, Y0: 298, X1: 678, Y1: 358}, Conf: 72},
		{Class: vision.Vehicle, Box: vision.Box{X0: 236, Y0: 276, X1: 436, Y1: 396}, Conf: 72},
	}
	if len(ds) != len(want) {
		t.Fatalf("decoded %d detections, want %d: %+v", len(ds), len(want), ds)
	}
	near := func(a, b int) bool { return a-b <= 1 && b-a <= 1 } // float32 rows
	for i, d := range ds {
		w, b := want[i], d.Box
		if d.Class != w.Class || d.Conf != w.Conf || d.Face != nil || d.Detection.Face != "" ||
			!near(b.X0, w.Box.X0) || !near(b.Y0, w.Box.Y0) || !near(b.X1, w.Box.X1) || !near(b.Y1, w.Box.Y1) {
			t.Errorf("detection %d: %+v, want %+v", i, d.Detection, w)
		}
	}
	if err := vision.CheckDetections(detections(ds), vision.FormatRGB24, 832, 416, nil); err != nil {
		t.Fatalf("decoded detections fail the client's check: %v", err)
	}
}

func detections(ss []Seen) []vision.Detection {
	ds := make([]vision.Detection, len(ss))
	for i, s := range ss {
		ds[i] = s.Detection
	}
	return ds
}

func TestYoloxDecodeBoundsTheReply(t *testing.T) {
	const size = yoloxSize
	out := make([]float32, yoloxAnchors(size)*yoloxRow)
	g := size / 8
	n := 0
	for gy := 0; gy < g; gy += 2 {
		for gx := 0; gx < g; gx += 2 {
			row(out, size, 8, gx, gy, float64(gx*8+4), float64(gy*8+4), 6, 6, 0.95, 0, 0.95-float32(n%50)/100)
			n++
		}
	}
	ds := yoloxDecode(out, size, letterbox{scale: 1}, size, size)
	if len(ds) != vision.MaxDetections {
		t.Fatalf("%d candidates gave %d detections, want %d", n, len(ds), vision.MaxDetections)
	}
	for i := 1; i < len(ds); i++ {
		if ds[i].Conf > ds[i-1].Conf {
			t.Fatalf("detections not best first: %d after %d", ds[i].Conf, ds[i-1].Conf)
		}
	}
	if err := vision.CheckDetections(detections(ds), vision.FormatRGB24, size, size, nil); err != nil {
		t.Fatal(err)
	}
}

func TestYoloxInputLetterboxes(t *testing.T) {
	// A 4x2 rgb24 frame, left half red, right half blue, into an 8-pixel
	// input: scaled by 2 to 8x4, the bottom half padded.
	f := vision.Frame{Format: vision.FormatRGB24, Width: 4, Height: 2, Data: make([]byte, 4*2*3)}
	for y := 0; y < 2; y++ {
		for x := 0; x < 4; x++ {
			p := f.Data[(y*4+x)*3:]
			if x < 2 {
				p[0] = 200
			} else {
				p[2] = 100
			}
		}
	}
	dst := make([]float32, 3*8*8)
	lb := yoloxInput(f, 8, dst)
	if lb.scale != 2 {
		t.Fatalf("scale %v, want 2", lb.scale)
	}
	at := func(c, x, y int) float32 { return dst[c*64+y*8+x] }
	// Planes are blue, green, red.
	if at(2, 0, 0) != 200 || at(0, 0, 0) != 0 || at(0, 7, 3) != 100 || at(2, 7, 3) != 0 {
		t.Errorf("colours misplaced: red plane %v, blue plane %v", at(2, 0, 0), at(0, 7, 3))
	}
	for c := 0; c < 3; c++ {
		if at(c, 3, 6) != yoloxPad {
			t.Errorf("plane %d not padded below the frame: %v", c, at(c, 3, 6))
		}
	}
	// A gray8 frame fills all three planes alike.
	g := vision.Frame{Format: vision.FormatGray8, Width: 2, Height: 2, Data: []byte{10, 20, 30, 40}}
	dst = make([]float32, 3*2*2)
	yoloxInput(g, 2, dst)
	for i := 0; i < 4; i++ {
		if dst[i] != dst[4+i] || dst[i] != dst[8+i] || dst[i] != float32(g.Data[i]) {
			t.Fatalf("gray frame planes differ: %v", dst)
		}
	}
}

// thermalScene renders a y16 frame of w by h in hundredths of a kelvin: a
// background at ambient with a gentle gradient and sensor noise, a sunlit
// wall a little warmer, an engine block too hot to be a body, and the
// given bodies as filled ellipses at body temperature.
func thermalScene(rng *rand.Rand, w, h int, ambient float64, bodies []vision.Box) vision.Frame {
	f := vision.Frame{Format: vision.FormatY16, Width: w, Height: h, Data: make([]byte, 2*w*h)}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			v := ambient + 80*float64(y)/float64(h) + rng.NormFloat64()*15
			if x > w*3/4 && y < h/3 {
				v += 150 // a wall warmed by the sun: under the contrast
			}
			if x > w/10 && x < w/10+12 && y > h*3/4 && y < h*3/4+8 {
				v = 27315 + 7000 // an engine at 70 °C
			}
			for _, b := range bodies {
				cx, cy := float64(b.X0+b.X1)/2, float64(b.Y0+b.Y1)/2
				rx, ry := float64(b.X1-b.X0)/2, float64(b.Y1-b.Y0)/2
				if dx, dy := (float64(x)+0.5-cx)/rx, (float64(y)+0.5-cy)/ry; dx*dx+dy*dy <= 1 {
					// A clothed body's surface: about 24 °C, and never
					// less than 4 K over a warm summer night.
					v = max(27315+2400, ambient+400) + rng.NormFloat64()*40
				}
			}
			binary.LittleEndian.PutUint16(f.Data[2*(y*w+x):], uint16(min(65535, max(0, v))))
		}
	}
	return f
}

// TestThermalDetect: heat-blob detection finds the synthetic thermal
// subjects (brief, part e): people and animals of several sizes, some
// far off, on Lepton and Boson sized frames, from frost to a warm summer
// night, while the engine, the sunlit wall and the noise give nothing.
func TestThermalDetect(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	found, total, false_ := 0, 0, 0
	for scene := 0; scene < 60; scene++ {
		w, h := 160, 120
		if scene%2 == 1 {
			w, h = 640, 512
		}
		ambient := 27315 - 500 + float64(scene%7)*500 // -5 °C to 25 °C
		var bodies []vision.Box
		for len(bodies) < 1+scene%4 {
			bw, bh := 3+rng.Intn(w/12), 6+rng.Intn(h/5) // upright people, some far off
			if rng.Intn(3) == 0 {
				bw, bh = bh, bw // animals, lying down
			}
			x, y := w/8+rng.Intn(w*5/8), h/8+rng.Intn(h/2)
			b := vision.Box{X0: x, Y0: y, X1: x + bw, Y1: y + bh}
			clear := true
			for _, o := range bodies {
				if b.X0 < o.X1+3 && o.X0 < b.X1+3 && b.Y0 < o.Y1+3 && o.Y0 < b.Y1+3 {
					clear = false
				}
			}
			if clear {
				bodies = append(bodies, b)
			}
		}
		f := thermalScene(rng, w, h, ambient, bodies)
		ds := heatBlobs(f)
		if err := vision.CheckDetections(detections(ds), vision.FormatY16, w, h, nil); err != nil {
			t.Fatalf("scene %d: %v", scene, err)
		}
		hit := make([]bool, len(ds))
		for _, b := range bodies {
			total++
			for i, d := range ds {
				if d.Class == vision.Warm && boxIoU(d.Box, b) >= 0.5 {
					found++
					hit[i] = true
					break
				}
			}
		}
		for i := range ds {
			if !hit[i] {
				false_++
			}
		}
	}
	recall := float64(found) / float64(total)
	t.Logf("thermal: %d of %d bodies found (%.3f), %d false detections", found, total, recall, false_)
	if recall < 0.95 || false_ > 0 {
		t.Fatalf("thermal recall %.3f (want at least 0.95) with %d false detections (want none)", recall, false_)
	}
	// A flat noisy frame and a frame hotter than any body give nothing.
	if ds := heatBlobs(thermalScene(rng, 160, 120, 27315, nil)); len(ds) != 0 {
		t.Fatalf("empty scene: %+v", ds)
	}
	hot := thermalScene(rng, 160, 120, 27315+3000, nil)
	if ds := heatBlobs(hot); len(ds) != 0 {
		t.Fatalf("a 30 °C scene: %+v", ds)
	}
}

func boxIoU(a, b vision.Box) float64 {
	ix := min(a.X1, b.X1) - max(a.X0, b.X0)
	iy := min(a.Y1, b.Y1) - max(a.Y0, b.Y0)
	if ix <= 0 || iy <= 0 {
		return 0
	}
	in := float64(ix * iy)
	return in / (float64((a.X1-a.X0)*(a.Y1-a.Y0)+(b.X1-b.X0)*(b.Y1-b.Y0)) - in)
}

func TestThermalBoundsTheReply(t *testing.T) {
	// A grid of small bodies, more than a reply may carry.
	w, h := 640, 512
	var bodies []vision.Box
	for y := 10; y+12 < h && len(bodies) < 200; y += 24 {
		for x := 10; x+6 < w && len(bodies) < 200; x += 16 {
			bodies = append(bodies, vision.Box{X0: x, Y0: y, X1: x + 6, Y1: y + 12})
		}
	}
	ds := heatBlobs(thermalScene(rand.New(rand.NewSource(1)), w, h, 27315, bodies))
	if len(ds) != vision.MaxDetections {
		t.Fatalf("%d bodies gave %d detections, want %d", len(bodies), len(ds), vision.MaxDetections)
	}
}

// TestPinsCheckEveryFile: the runtime loads a library or model only when
// its bytes hash to the pin (VIS-A27).
func TestPinsCheckEveryFile(t *testing.T) {
	saved := modelPins
	t.Cleanup(func() { modelPins = saved })
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "m.onnx"), []byte("model bytes"), 0o644)
	os.WriteFile(filepath.Join(dir, "other.onnx"), []byte("model bytes"), 0o644)
	os.Mkdir(filepath.Join(dir, "d.onnx"), 0o755)
	modelPins = "# comment\n" +
		"b4dd5bd4b5d6a1d6f68ce29b4d5d4ad0dcf2d1c86a7ae6a3e2f5d5fa1b78bb5b  wrong.onnx  https://example.invalid/wrong\n" +
		hashOf("model bytes") + "  m.onnx  https://example.invalid/m\n" +
		hashOf("model bytes") + "  d.onnx  https://example.invalid/d\n" +
		hashOf("model bytes") + "  absent.onnx  https://example.invalid/a\n"
	if b, err := readPinned(dir, "m.onnx"); err != nil || string(b) != "model bytes" {
		t.Fatalf("pinned file: %q, %v", b, err)
	}
	os.WriteFile(filepath.Join(dir, "wrong.onnx"), []byte("model bytes"), 0o644)
	for file, want := range map[string]error{
		"wrong.onnx":  ErrRefused, // hash not the pin
		"other.onnx":  ErrRefused, // not pinned at all
		"d.onnx":      ErrRefused, // not a regular file
		"absent.onnx": ErrMissing,
	} {
		if _, err := readPinned(dir, file); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", file, err, want)
		}
	}
	// The shipped pins name the library, the detector and the face models.
	modelPins = saved
	for _, file := range []string{"libonnxruntime.so.1.29.0", "yolox_tiny.onnx", "face_detection_yunet_2023mar.onnx", "face_recognition_sface_2021dec.onnx"} {
		if len(pinFor(file)) != 64 {
			t.Errorf("%s is not pinned", file)
		}
	}
}

// TestNoModelKeepsTheLoad: an op the build has no model for is
// Unavailable, and asking for it never reloads the detector.
func TestNoModelKeepsTheLoad(t *testing.T) {
	f := newFake()
	c := start(t, newService(Config{}, noModelSound{f}, nil))
	if _, err := c.Hello(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Sound(context.Background(), make([]byte, 3200)); vision.CauseOf(err) != vision.Unavailable {
			t.Fatalf("sound with no model: %v, want unavailable", err)
		}
	}
	if ds, err := c.Detect(context.Background(), gray(8, 8, 1)); err != nil || len(ds) != 1 {
		t.Fatalf("detect after: %+v, %v", ds, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loads != 1 {
		t.Fatalf("%d loads, want 1: an op without a model reloaded the runtime", f.loads)
	}
}

type noModelSound struct{ *fake }

func (noModelSound) Sound([]byte) ([]vision.Sound, error) { return nil, ErrNoModel }

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
