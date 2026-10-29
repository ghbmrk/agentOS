package main

// REQ: DEV-7

import (
	"errors"
	"math"
	"testing"

	"github.com/ghbmrk/agentos/broker/vision"
)

// yunetOuts is the face detector's twelve outputs, all zero.
func yunetOuts() [][]float32 {
	outs := make([][]float32, len(yunetOutputs))
	for i := range outs {
		g := yunetSize / yunetStrides[i%3]
		outs[i] = make([]float32, g*g*yunetWidth[i])
	}
	return outs
}

// yunetAnchor writes one anchor of the grid of stride s (index si) at row
// r and column c: scores, a box centred at (cx, cy) of bw by bh input
// pixels, and the landmarks at the given input pixels.
func yunetAnchor(outs [][]float32, si, r, c int, cls, obj float32, cx, cy, bw, bh float64, marks [5][2]float64) {
	s := float64(yunetStrides[si])
	k := r*(yunetSize/yunetStrides[si]) + c
	outs[si][k], outs[3+si][k] = cls, obj
	b := outs[6+si][4*k:]
	b[0], b[1] = float32(cx/s-float64(c)), float32(cy/s-float64(r))
	b[2], b[3] = float32(math.Log(bw/s)), float32(math.Log(bh/s))
	for m := range marks {
		outs[9+si][10*k+2*m] = float32(marks[m][0]/s - float64(c))
		outs[9+si][10*k+2*m+1] = float32(marks[m][1]/s - float64(r))
	}
}

func near2(a, b float64) bool { return math.Abs(a-b) < 0.01 }

// TestYunetDecode: the face detector's outputs decode as FaceDetectorYN
// decodes them (score the root of class times objectness, box and
// landmarks on the anchor's grid), mapped back through the letterbox; a
// weaker overlapping face is suppressed, and faces under the score or not
// finite are dropped.
func TestYunetDecode(t *testing.T) {
	outs := yunetOuts()
	marks := [5][2]float64{{150, 90}, {170, 90}, {160, 100}, {152, 110}, {168, 110}}
	yunetAnchor(outs, 0, 12, 20, 0.81, 1, 160, 100, 40, 48, marks) // score 0.9
	yunetAnchor(outs, 1, 6, 10, 0.64, 1, 162, 100, 40, 48, marks)  // 0.8, overlaps: suppressed
	yunetAnchor(outs, 2, 2, 2, 0.49, 1, 80, 80, 30, 30, marks)     // 0.7, apart: kept
	yunetAnchor(outs, 0, 40, 40, 0.25, 1, 330, 330, 30, 30, marks) // 0.5: under the score
	yunetAnchor(outs, 0, 60, 60, 1, 1, 490, 490, 30, 30, marks)    // NaN landmarks: dropped
	outs[9][10*(60*80+60)] = float32(math.NaN())
	fs := yunetDecode(outs, letterbox{scale: 0.5}, 1280, 960, yunetMinScore)
	if len(fs) != 2 {
		t.Fatalf("faces: %+v", fs)
	}
	f := fs[0]
	if !near2(f.score, 0.9) || !near2(f.x0, 280) || !near2(f.y0, 152) || !near2(f.x1, 360) || !near2(f.y1, 248) {
		t.Errorf("first face: %+v", f)
	}
	for m := range marks {
		if !near2(f.marks[m][0], 2*marks[m][0]) || !near2(f.marks[m][1], 2*marks[m][1]) {
			t.Errorf("landmark %d: %v, want %v", m, f.marks[m], marks[m])
		}
	}
	if !near2(fs[1].score, 0.7) || !near2(fs[1].x0, 130) {
		t.Errorf("second face: %+v", fs[1])
	}
	// A face half outside the frame is clamped to it.
	outs = yunetOuts()
	yunetAnchor(outs, 0, 1, 1, 1, 1, 4, 4, 20, 20, marks)
	if fs := yunetDecode(outs, letterbox{scale: 1}, 640, 640, yunetMinScore); len(fs) != 1 || fs[0].x0 != 0 || fs[0].y0 != 0 {
		t.Errorf("a face over the edge: %+v", fs)
	}
}

// TestSimilarityRecoversTransform: landmarks placed by a known similarity
// give it back, and landmarks all at one point give none.
func TestSimilarityRecoversTransform(t *testing.T) {
	a, b, tx, ty := 0.4*math.Cos(0.3), 0.4*math.Sin(0.3), -17.0, 23.0
	var marks [5][2]float64
	for i, m := range sfaceMarks {
		// The inverse of x' = a*x - b*y + tx, y' = b*x + a*y + ty.
		ux, uy := m[0]-tx, m[1]-ty
		n := a*a + b*b
		marks[i] = [2]float64{(a*ux + b*uy) / n, (-b*ux + a*uy) / n}
	}
	ga, gb, gtx, gty, ok := similarity(marks)
	if !ok || math.Abs(ga-a) > 1e-9 || math.Abs(gb-b) > 1e-9 || math.Abs(gtx-tx) > 1e-6 || math.Abs(gty-ty) > 1e-6 {
		t.Fatalf("got %v %v %v %v %v", ga, gb, gtx, gty, ok)
	}
	if _, _, _, _, ok := similarity([5][2]float64{{5, 5}, {5, 5}, {5, 5}, {5, 5}, {5, 5}}); ok {
		t.Fatal("one point gave a transform")
	}
}

// TestSfaceInputAligns: a face whose landmarks are SFace's own, shifted,
// is cut from the frame at that shift, in red, green and blue planes; a
// gray frame fills all three; outside the frame is black.
func TestSfaceInputAligns(t *testing.T) {
	const w, h = 300, 200
	f := vision.Frame{Format: vision.FormatRGB24, Width: w, Height: h, Data: make([]byte, w*h*3)}
	g := vision.Frame{Format: vision.FormatGray8, Width: w, Height: h, Data: make([]byte, w*h)}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			f.Data[(y*w+x)*3], f.Data[(y*w+x)*3+1], f.Data[(y*w+x)*3+2] = byte(x), byte(y), 7
			g.Data[y*w+x] = byte(x + y)
		}
	}
	var fc face
	for i, m := range sfaceMarks {
		fc.marks[i] = [2]float64{m[0] + 100, m[1] + 50}
	}
	dst := make([]float32, 3*sfaceSize*sfaceSize)
	if !sfaceInput(f, fc, dst) {
		t.Fatal("no transform")
	}
	plane := sfaceSize * sfaceSize
	for _, p := range [][2]int{{0, 0}, {50, 60}, {111, 111}} {
		x, y := p[0], p[1]
		i := y*sfaceSize + x
		if dst[i] != float32(x+100) || dst[plane+i] != float32(y+50) || dst[2*plane+i] != 7 {
			t.Errorf("(%d,%d): %v %v %v", x, y, dst[i], dst[plane+i], dst[2*plane+i])
		}
	}
	if !sfaceInput(g, fc, dst) || dst[0] != 150 || dst[plane] != 150 || dst[2*plane] != 150 {
		t.Errorf("gray: %v %v %v", dst[0], dst[plane], dst[2*plane])
	}
	for i := range fc.marks {
		fc.marks[i][0] += 250 // the face mostly right of the frame
	}
	sfaceInput(f, fc, dst)
	if dst[sfaceSize-1] != 0 || dst[2*plane+sfaceSize-1] != 0 {
		t.Errorf("outside the frame: %v", dst[sfaceSize-1])
	}
}

// person is a person detection with the given box.
func person(x0, y0, x1, y1 int) Seen {
	return Seen{Detection: vision.Detection{Class: vision.Person, Box: vision.Box{X0: x0, Y0: y0, X1: x1, Y1: y1}, Conf: 90}}
}

// faceAt is a face of side s at (x, y) with the given score.
func faceAt(x, y, s, score float64) face {
	return face{score: score, x0: x, y0: y, x1: x + s, y1: y + s}
}

// TestEncodeFacesBoundsAndAssigns: each person gets at most one face,
// the one whose centre its box holds (the smallest such box when they
// nest); a face on no person and a vehicle get nothing; faces too small
// to name, and those past maxFaces (the weakest), are unknown, with an
// empty encoding; and an encoder error zeroes every encoding made.
func TestEncodeFacesBoundsAndAssigns(t *testing.T) {
	var seen []Seen
	var fs []face
	for i := 0; i < 10; i++ {
		x := 100 * i
		seen = append(seen, person(x, 0, x+90, 300))
		fs = append(fs, faceAt(float64(x+20), 20, 40, 0.95-0.01*float64(i)))
	}
	seen = append(seen, person(0, 0, 1000, 700)) // around them all and the vehicle
	seen = append(seen, Seen{Detection: vision.Detection{Class: vision.Vehicle, Box: vision.Box{X0: 0, Y0: 500, X1: 100, Y1: 600}, Conf: 90}})
	fs = append(fs, faceAt(20, 520, 40, 0.99))  // on the vehicle only
	fs = append(fs, faceAt(2000, 20, 40, 0.99)) // on no one
	fs[2] = faceAt(220, 20, 20, 0.97)           // the best, but too small
	calls := 0
	err := encodeFaces(seen, fs, func(f face) ([]float32, error) {
		calls++
		return []float32{float32(f.score), 1}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != maxFaces {
		t.Errorf("%d encodings, want %d", calls, maxFaces)
	}
	for i, d := range seen {
		switch {
		case i == 2 || i == 8 || i == 9: // too small; the weakest, past the bound
			if d.Face == nil || len(d.Face) != 0 {
				t.Errorf("person %d: %v, want an empty encoding", i, d.Face)
			}
		case i < 10:
			if len(d.Face) != 2 || !near2(float64(d.Face[0]), 0.95-0.01*float64(i)) {
				t.Errorf("person %d: %v", i, d.Face)
			}
		case i == 10: // the large box holds the vehicle's face's centre
			if len(d.Face) != 2 || !near2(float64(d.Face[0]), 0.99) {
				t.Errorf("the large box: %v", d.Face)
			}
		default:
			if d.Face != nil {
				t.Errorf("the vehicle: %v", d.Face)
			}
		}
	}
	for i := range seen {
		seen[i].Face = nil
	}
	var made [][]float32
	n := 0
	err = encodeFaces(seen, fs, func(face) ([]float32, error) {
		if n++; n == 3 {
			return nil, errors.New("encoder failed")
		}
		v := []float32{1, 2}
		made = append(made, v)
		return v, nil
	})
	if err == nil {
		t.Fatal("the encoder's error was lost")
	}
	for _, v := range made {
		if v[0] != 0 || v[1] != 0 {
			t.Fatalf("an encoding was left after the error: %v", v)
		}
	}
}

// TestClearFace: an enrolment frame needs exactly one face at or above
// enrolMinScore, at least enrolMinSide on its shorter side; a weaker
// face beside it does not count.
func TestClearFace(t *testing.T) {
	good := faceAt(0, 0, enrolMinSide, enrolMinScore)
	for name, c := range map[string]struct {
		fs   []face
		want bool
	}{
		"one clear":         {[]face{good}, true},
		"and a weak one":    {[]face{good, faceAt(300, 0, 100, enrolMinScore-0.01)}, true},
		"two clear":         {[]face{good, faceAt(300, 0, 100, 0.95)}, false},
		"too small":         {[]face{faceAt(0, 0, enrolMinSide-1, 0.99)}, false},
		"none":              {nil, false},
		"only a weak one":   {[]face{faceAt(0, 0, 200, enrolMinScore-0.01)}, false},
		"narrow, tall face": {[]face{{score: 0.99, x0: 0, y0: 0, x1: enrolMinSide - 1, y1: 300}}, false},
	} {
		if _, ok := clearFace(c.fs); ok != c.want {
			t.Errorf("%s: %v, want %v", name, ok, c.want)
		}
	}
}
