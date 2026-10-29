package main

import (
	"math"
	"sort"

	"github.com/ghbmrk/agentos/broker/vision"
)

// The detector is YOLOX-Tiny (Apache-2.0), trained on COCO, run at a
// 416-pixel square input (VIS-A27). Its pre- and post-processing are here,
// in plain Go, so the default build tests them without the runtime; only
// the session itself is in runtime_onnx.go.
const (
	yoloxSize    = 416
	yoloxClasses = 80
	yoloxRow     = 5 + yoloxClasses // box (4), objectness, class scores
	yoloxPad     = 114              // the training letterbox's grey
	// yoloxMinScore is the least objectness times class score kept: the
	// tracker joins detections under 50% only to confirmed tracks
	// (VIS-A22), so lower ones carry nothing it uses.
	yoloxMinScore = 0.3
	// yoloxIoU is the overlap above which a box of one closed class is
	// suppressed by a better one: a car the model also calls a truck is
	// one vehicle.
	yoloxIoU = 0.45
)

// yoloxStrides are the detector's three output grids.
var yoloxStrides = [...]int{8, 16, 32}

// yoloxAnchors is the number of output rows at a square input of size.
func yoloxAnchors(size int) int {
	n := 0
	for _, s := range yoloxStrides {
		n += (size / s) * (size / s)
	}
	return n
}

// cocoClass maps the detector's 80 COCO classes onto the closed list
// (VIS-A28); a class not here is dropped. COCO has no deer, fox, coyote
// or drone, so this detector never names them: a deer reads as one of
// the hoofed classes (unknown-animal), and a fox or coyote most often
// as a dog.
var cocoClass = map[int]vision.Class{
	0:  vision.Person,
	2:  vision.Vehicle, // car
	3:  vision.Vehicle, // motorcycle
	5:  vision.Vehicle, // bus
	7:  vision.Vehicle, // truck
	14: vision.Bird,
	15: vision.Cat,
	16: vision.Dog,
	17: vision.UnknownAnimal, // horse
	18: vision.UnknownAnimal, // sheep
	19: vision.UnknownAnimal, // cow
	20: vision.UnknownAnimal, // elephant
	21: vision.Bear,
	22: vision.UnknownAnimal, // zebra
	23: vision.UnknownAnimal, // giraffe
}

// letterbox is how a frame was scaled into the square input: by scale,
// from its top-left corner, the rest padded.
type letterbox struct {
	scale float64
}

// yoloxInput writes f into dst, the detector's 1x3xSxS input: blue,
// green and red planes of 0 to 255, the frame scaled by bilinear sampling
// to fit with its aspect kept and the rest padded grey, as YOLOX was
// trained. A gray8 frame (an infrared night picture) fills all three
// planes. f is rgb24 or gray8, checked by the request.
func yoloxInput(f vision.Frame, size int, dst []float32) letterbox {
	return letterboxInput(f, size, yoloxPad, dst)
}

// letterboxInput is yoloxInput with the padding's value given: the face
// detector shares it (facemodels.go).
func letterboxInput(f vision.Frame, size int, pad float32, dst []float32) letterbox {
	scale := math.Min(float64(size)/float64(f.Width), float64(size)/float64(f.Height))
	nw := min(size, int(math.Round(float64(f.Width)*scale)))
	nh := min(size, int(math.Round(float64(f.Height)*scale)))
	plane := size * size
	for i := range dst[:3*plane] {
		dst[i] = pad
	}
	bpp := 3
	if f.Format == vision.FormatGray8 {
		bpp = 1
	}
	at := func(x, y, c int) float64 {
		if bpp == 1 {
			c = 0
		}
		return float64(f.Data[(y*f.Width+x)*bpp+c])
	}
	for y := 0; y < nh; y++ {
		sy := (float64(y)+0.5)/scale - 0.5
		y0 := int(math.Floor(sy))
		fy := sy - float64(y0)
		y1 := min(y0+1, f.Height-1)
		y0 = max(y0, 0)
		for x := 0; x < nw; x++ {
			sx := (float64(x)+0.5)/scale - 0.5
			x0 := int(math.Floor(sx))
			fx := sx - float64(x0)
			x1 := min(x0+1, f.Width-1)
			x0 = max(x0, 0)
			for c := 0; c < 3; c++ {
				v := (at(x0, y0, c)*(1-fx)+at(x1, y0, c)*fx)*(1-fy) + (at(x0, y1, c)*(1-fx)+at(x1, y1, c)*fx)*fy
				// rgb24 holds red first; the planes are blue, green, red.
				dst[(2-c)*plane+y*size+x] = float32(v)
			}
		}
	}
	return letterbox{scale: scale}
}

// scored is one candidate box in frame pixels, before suppression.
type scored struct {
	class          vision.Class
	score          float64
	x0, y0, x1, y1 float64
}

// yoloxDecode turns the detector's output rows (yoloxAnchors(size) rows
// of yoloxRow) into detections of the w by h frame: each row's box is
// decoded on its grid, kept if its best class is on the closed list and
// scores at least yoloxMinScore, mapped back through lb, suppressed
// against better boxes of its closed class, and the best MaxDetections
// returned with whole-pixel boxes inside the frame and a whole-percent
// confidence. A row that is not finite is dropped.
func yoloxDecode(out []float32, size int, lb letterbox, w, h int) []Seen {
	var cs []scored
	k := 0
	for _, s := range yoloxStrides {
		g := size / s
		for gy := 0; gy < g; gy++ {
			for gx := 0; gx < g; gx++ {
				p := out[k*yoloxRow : (k+1)*yoloxRow]
				k++
				best, bc := float32(0), -1
				for c := 0; c < yoloxClasses; c++ {
					if p[5+c] > best {
						best, bc = p[5+c], c
					}
				}
				class, ok := cocoClass[bc]
				score := float64(p[4]) * float64(best)
				if !ok || !(score >= yoloxMinScore) || score > 1 {
					continue
				}
				cx := (float64(p[0]) + float64(gx)) * float64(s)
				cy := (float64(p[1]) + float64(gy)) * float64(s)
				bw := math.Exp(float64(p[2])) * float64(s)
				bh := math.Exp(float64(p[3])) * float64(s)
				c := scored{class: class, score: score,
					x0: (cx - bw/2) / lb.scale, y0: (cy - bh/2) / lb.scale,
					x1: (cx + bw/2) / lb.scale, y1: (cy + bh/2) / lb.scale}
				if finite(c.x0, c.y0, c.x1, c.y1) {
					cs = append(cs, c)
				}
			}
		}
	}
	return suppress(cs, w, h)
}

func finite(vs ...float64) bool {
	for _, v := range vs {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return false
		}
	}
	return true
}

// suppress keeps the best box of each overlapping group within a class,
// best first, at most MaxDetections, as whole-pixel boxes clamped to the
// frame; a box with nothing left inside the frame is dropped.
func suppress(cs []scored, w, h int) []Seen {
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].score > cs[j].score })
	var kept []scored
	var out []Seen
	for _, c := range cs {
		if len(out) == vision.MaxDetections {
			break
		}
		b := vision.Box{
			X0: max(0, int(math.Floor(c.x0))), Y0: max(0, int(math.Floor(c.y0))),
			X1: min(w, int(math.Ceil(c.x1))), Y1: min(h, int(math.Ceil(c.y1))),
		}
		if b.X0 >= b.X1 || b.Y0 >= b.Y1 {
			continue
		}
		dup := false
		for _, k := range kept {
			if k.class == c.class && iou(k, c) > yoloxIoU {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		kept = append(kept, c)
		out = append(out, Seen{Detection: vision.Detection{Class: c.class, Box: b, Conf: percent(c.score)}})
	}
	return out
}

func iou(a, b scored) float64 {
	ix := math.Min(a.x1, b.x1) - math.Max(a.x0, b.x0)
	iy := math.Min(a.y1, b.y1) - math.Max(a.y0, b.y0)
	if ix <= 0 || iy <= 0 {
		return 0
	}
	in := ix * iy
	return in / ((a.x1-a.x0)*(a.y1-a.y0) + (b.x1-b.x0)*(b.y1-b.y0) - in)
}

// percent is a score from 0 to 1 as a whole percent from 1 to 100.
func percent(score float64) int {
	return min(100, max(1, int(math.Round(score*100))))
}
