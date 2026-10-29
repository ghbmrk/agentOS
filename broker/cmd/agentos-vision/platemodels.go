package main

import (
	"math"
	"sort"

	"github.com/ghbmrk/agentos/broker/vision"
)

// Plates are found by open-image-models' YOLOv9-t plate detector (MIT;
// yolo-v9-t-416-license-plate-end2end, its suppression inside the model)
// on each vehicle's box, and read by fast-plate-ocr's cct-xs-v2 global
// reader (MIT), as their Python packages run them (VIS-A33). Their pre-
// and post-processing are here, in plain Go, so the default build tests
// them without the runtime; only the sessions are in runtime_onnx.go.
const (
	// plateSize is the plate detector's square input.
	plateSize = 416
	// plateRow is one detector output row: batch index, box corners,
	// class and score.
	plateRow = 7
	// plateMinScore is the least plate score read.
	plateMinScore = 0.4
	// plateMinWidth is the least width, in frame pixels, of a plate that
	// is read: a narrower one is no text the reader can trust.
	plateMinWidth = 24
	// maxPlateVehicles bounds the vehicles searched for a plate on one
	// frame, best first, and plateMinVehicle is the least width, in frame
	// pixels, of a vehicle searched: a narrower one cannot hold a plate
	// plateMinWidth wide. Both bound the plate models' cost per frame
	// (VIS-A33).
	maxPlateVehicles = 4
	plateMinVehicle  = 96
	// readerW and readerH are the reader's input, readerSlots its
	// character slots, and readerMinProb the least probability of every
	// slot's best character for a read to stand.
	readerW, readerH = 128, 64
	readerSlots      = 10
	readerMinProb    = 0.7
)

// readerAlphabet is the reader's characters in its output order; the
// last, '_', pads a plate shorter than readerSlots.
const readerAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_"

// rect is a region of a frame in pixels, x1 and y1 exclusive.
type rect struct{ x0, y0, x1, y1 int }

// boxRect is the region of b inside a w by h frame, or false when it is
// empty.
func boxRect(b vision.Box, w, h int) (rect, bool) {
	r := rect{max(0, b.X0), max(0, b.Y0), min(w, b.X1), min(h, b.Y1)}
	return r, r.x1 > r.x0 && r.y1 > r.y0
}

// sample is f's channel c at (x, y), clamped to r, as a value from 0 to
// 255; a gray8 frame gives its one channel for all three.
func sample(f vision.Frame, r rect, x, y, c int) float64 {
	x = min(max(x, r.x0), r.x1-1)
	y = min(max(y, r.y0), r.y1-1)
	if f.Format == vision.FormatGray8 {
		return float64(f.Data[y*f.Width+x])
	}
	return float64(f.Data[(y*f.Width+x)*3+c])
}

// resize samples region r of f bilinearly onto a w by h grid, calling put
// with each pixel's red, green and blue values from 0 to 255.
func resize(f vision.Frame, r rect, w, h int, put func(x, y int, rgb [3]float64)) {
	sx := float64(r.x1-r.x0) / float64(w)
	sy := float64(r.y1-r.y0) / float64(h)
	for y := 0; y < h; y++ {
		fy := (float64(y)+0.5)*sy - 0.5
		y0 := int(math.Floor(fy))
		dy := fy - float64(y0)
		y0 += r.y0
		for x := 0; x < w; x++ {
			fx := (float64(x)+0.5)*sx - 0.5
			x0 := int(math.Floor(fx))
			dx := fx - float64(x0)
			x0 += r.x0
			var rgb [3]float64
			for c := range rgb {
				rgb[c] = (sample(f, r, x0, y0, c)*(1-dx)+sample(f, r, x0+1, y0, c)*dx)*(1-dy) +
					(sample(f, r, x0, y0+1, c)*(1-dx)+sample(f, r, x0+1, y0+1, c)*dx)*dy
			}
			put(x, y, rgb)
		}
	}
}

// plateBox is how region r was placed in the plate detector's input:
// scaled by scale and shifted by (dx, dy).
type plateBox struct {
	r      rect
	scale  float64
	dx, dy float64
}

// plateInput writes region r of f into dst, the plate detector's
// 1x3xSxS input: red, green and blue planes from 0 to 1, the region
// scaled to fit with its aspect kept, centred, and the rest padded grey
// (114), as open-image-models' letterbox.
func plateInput(f vision.Frame, r rect, dst []float32) plateBox {
	w, h := r.x1-r.x0, r.y1-r.y0
	scale := math.Min(float64(plateSize)/float64(w), float64(plateSize)/float64(h))
	nw := min(plateSize, max(1, int(math.Round(float64(w)*scale))))
	nh := min(plateSize, max(1, int(math.Round(float64(h)*scale))))
	dx := float64(plateSize-nw) / 2
	dy := float64(plateSize-nh) / 2
	left := int(math.Round(dx - 0.1))
	top := int(math.Round(dy - 0.1))
	plane := plateSize * plateSize
	for i := range dst[:3*plane] {
		dst[i] = 114.0 / 255
	}
	resize(f, r, nw, nh, func(x, y int, rgb [3]float64) {
		for c, v := range rgb {
			dst[c*plane+(top+y)*plateSize+left+x] = float32(v / 255)
		}
	})
	return plateBox{r: r, scale: float64(nw) / float64(w), dx: dx, dy: dy}
}

// plateDecode is the best plate in the detector's output rows, mapped
// back to the frame through pb: the highest-scoring finite row at or
// above plateMinScore whose box, inside pb's region, is at least
// plateMinWidth wide. false when there is none.
func plateDecode(out []float32, pb plateBox) (rect, bool) {
	best, bestScore := rect{}, -1.0
	for i := 0; i+plateRow <= len(out); i += plateRow {
		row := out[i : i+plateRow]
		score := float64(row[6])
		if !finite(float64(row[1]), float64(row[2]), float64(row[3]), float64(row[4]), score) || score < plateMinScore || score <= bestScore {
			continue
		}
		at := func(v float32, d float64, lo, hi int) int {
			p := int(math.Round((float64(v)-d)/pb.scale)) + lo
			return min(max(p, lo), hi)
		}
		r := rect{
			at(row[1], pb.dx, pb.r.x0, pb.r.x1), at(row[2], pb.dy, pb.r.y0, pb.r.y1),
			at(row[3], pb.dx, pb.r.x0, pb.r.x1), at(row[4], pb.dy, pb.r.y0, pb.r.y1),
		}
		if r.x1-r.x0 < plateMinWidth || r.y1 <= r.y0 {
			continue
		}
		best, bestScore = r, score
	}
	return best, bestScore >= 0
}

// readerInput writes plate region r of f into dst, the reader's
// 1xHxWx3 input of bytes: the region stretched to 128 by 64 (the reader
// keeps no aspect) by bilinear sampling, red first.
func readerInput(f vision.Frame, r rect, dst []uint8) {
	resize(f, r, readerW, readerH, func(x, y int, rgb [3]float64) {
		for c, v := range rgb {
			dst[(y*readerW+x)*3+c] = uint8(min(255, max(0, math.Round(v))))
		}
	})
}

// readerDecode is the plate text in the reader's output, readerSlots rows
// of len(readerAlphabet) probabilities: each slot's best character, the
// pads dropped. false when a slot's best is below readerMinProb or not
// finite, when a pad comes before a character, or when the text is not
// valid plate text (vision.ValidPlate).
func readerDecode(out []float32) (string, bool) {
	n := len(readerAlphabet)
	if len(out) != readerSlots*n {
		return "", false
	}
	text := make([]byte, 0, readerSlots)
	padded := false
	for s := 0; s < readerSlots; s++ {
		row := out[s*n : (s+1)*n]
		best := 0
		for i, p := range row {
			if !finite(float64(p)) {
				return "", false
			}
			if p > row[best] {
				best = i
			}
		}
		if float64(row[best]) < readerMinProb {
			return "", false
		}
		ch := readerAlphabet[best]
		switch {
		case ch == '_':
			padded = true
		case padded:
			return "", false
		default:
			text = append(text, ch)
		}
	}
	if !vision.ValidPlate(string(text)) {
		return "", false
	}
	return string(text), true
}

// plateVehicles is the indexes of the vehicles in seen to search for a
// plate: the best maxPlateVehicles by confidence of those at least
// plateMinVehicle wide.
func plateVehicles(seen []Seen) []int {
	var vs []int
	for i, d := range seen {
		if d.Class == vision.Vehicle && d.Box.X1-d.Box.X0 >= plateMinVehicle {
			vs = append(vs, i)
		}
	}
	sort.SliceStable(vs, func(a, b int) bool { return seen[vs[a]].Conf > seen[vs[b]].Conf })
	return vs[:min(len(vs), maxPlateVehicles)]
}
