package main

import (
	"math"
	"sort"

	"github.com/ghbmrk/agentos/broker/vision"
)

// Faces are found by YuNet (MIT, OpenCV Zoo face_detection_yunet_2023mar)
// and encoded by SFace (Apache-2.0, OpenCV Zoo
// face_recognition_sface_2021dec), as OpenCV's FaceDetectorYN and
// FaceRecognizerSF run them (VIS-A31). Their pre- and post-processing are
// here, in plain Go, so the default build tests them without the runtime;
// only the sessions are in runtime_onnx.go. An encoding never leaves the
// service: the service compares it with the lent templates and zeroes it
// (service.detect; DEV-7, D-207).
const (
	// yunetSize is the face detector's square input; the model's input
	// shape is fixed at it.
	yunetSize = 640
	// yunetMinScore is the least face score kept on a detect frame.
	yunetMinScore = 0.6
	// yunetIoU is the overlap above which a face is suppressed by a
	// better one, as FaceDetectorYN's default.
	yunetIoU = 0.3
	// faceMinSide is the least side, in frame pixels, of a face that is
	// encoded: a smaller one carries too little to name and is unknown.
	faceMinSide = 24
	// maxFaces bounds the encodings made for one frame; faces past it
	// are unknown. It bounds the encoder's cost per frame (VIS-A30).
	maxFaces = 8
	// enrolMinScore and enrolMinSide make an enrolment frame's face
	// clear: exactly one face at or above the score, and that face at
	// least this many pixels on its shorter side.
	enrolMinScore = 0.9
	enrolMinSide  = 80
	// sfaceSize is the encoder's aligned square input, and sfaceDim its
	// encoding's length.
	sfaceSize = 112
	sfaceDim  = 128
)

// yunetStrides are the face detector's three output grids, in the order
// of its outputs.
var yunetStrides = [...]int{8, 16, 32}

// yunetOutputs are the detector's output names, in the order yunetDecode
// takes them.
var yunetOutputs = []string{
	"cls_8", "cls_16", "cls_32",
	"obj_8", "obj_16", "obj_32",
	"bbox_8", "bbox_16", "bbox_32",
	"kps_8", "kps_16", "kps_32",
}

// yunetWidth is each output's values per anchor, in yunetOutputs' order.
var yunetWidth = [...]int{1, 1, 1, 1, 1, 1, 4, 4, 4, 10, 10, 10}

// face is one face in frame pixels: its box, its score from 0 to 1 and
// its five landmarks (right eye, left eye, nose tip, right and left mouth
// corner, as the person faces the camera).
type face struct {
	score          float64
	x0, y0, x1, y1 float64
	marks          [5][2]float64
}

func (f face) side() float64 { return math.Min(f.x1-f.x0, f.y1-f.y0) }

// yunetInput writes f into dst, the face detector's 1x3x640x640 input:
// blue, green and red planes of 0 to 255, letterboxed as the detector's
// (yoloxInput) with black padding, as FaceDetectorYN pads.
func yunetInput(f vision.Frame, dst []float32) letterbox {
	return letterboxInput(f, yunetSize, 0, dst)
}

// yunetDecode turns the detector's twelve outputs (yunetOutputs' order,
// each yunetWidth values per anchor of its grid) into the faces of the
// w by h frame scoring at least min: each anchor's score is the square
// root of its clamped class and objectness scores, its box and landmarks
// are decoded on its grid as FaceDetectorYN decodes them and mapped back
// through lb, and faces overlapping a better one by more than yunetIoU
// are suppressed. A face that is not finite or has no area inside the
// frame is dropped. They come best first, at most MaxDetections.
func yunetDecode(outs [][]float32, lb letterbox, w, h int, min float64) []face {
	var fs []face
	for i, s := range yunetStrides {
		g := yunetSize / s
		cls, obj, box, kps := outs[i], outs[3+i], outs[6+i], outs[9+i]
		for r := 0; r < g; r++ {
			for c := 0; c < g; c++ {
				k := r*g + c
				score := math.Sqrt(clamp01(float64(cls[k])) * clamp01(float64(obj[k])))
				if !(score >= min) {
					continue
				}
				b := box[4*k : 4*k+4]
				cx := (float64(c) + float64(b[0])) * float64(s)
				cy := (float64(r) + float64(b[1])) * float64(s)
				bw := math.Exp(float64(b[2])) * float64(s)
				bh := math.Exp(float64(b[3])) * float64(s)
				f := face{score: score,
					x0: (cx - bw/2) / lb.scale, y0: (cy - bh/2) / lb.scale,
					x1: (cx + bw/2) / lb.scale, y1: (cy + bh/2) / lb.scale}
				ok := finite(f.x0, f.y0, f.x1, f.y1)
				for m := 0; m < 5; m++ {
					f.marks[m][0] = (float64(kps[10*k+2*m]) + float64(c)) * float64(s) / lb.scale
					f.marks[m][1] = (float64(kps[10*k+2*m+1]) + float64(r)) * float64(s) / lb.scale
					ok = ok && finite(f.marks[m][0], f.marks[m][1])
				}
				f.x0, f.y0 = math.Max(0, f.x0), math.Max(0, f.y0)
				f.x1, f.y1 = math.Min(float64(w), f.x1), math.Min(float64(h), f.y1)
				if ok && f.x0 < f.x1 && f.y0 < f.y1 {
					fs = append(fs, f)
				}
			}
		}
	}
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].score > fs[j].score })
	var kept []face
	for _, f := range fs {
		if len(kept) == vision.MaxDetections {
			break
		}
		dup := false
		for _, k := range kept {
			if faceIoU(k, f) > yunetIoU {
				dup = true
				break
			}
		}
		if !dup {
			kept = append(kept, f)
		}
	}
	return kept
}

func clamp01(v float64) float64 {
	if !(v > 0) {
		return 0
	}
	return math.Min(v, 1)
}

func faceIoU(a, b face) float64 {
	return iou(scored{x0: a.x0, y0: a.y0, x1: a.x1, y1: a.y1}, scored{x0: b.x0, y0: b.y0, x1: b.x1, y1: b.y1})
}

// sfaceMarks are where SFace's training put the five landmarks in its
// 112-pixel input (FaceRecognizerSF::alignCrop).
var sfaceMarks = [5][2]float64{
	{38.2946, 51.6963}, {73.5318, 51.5014}, {56.0252, 71.7366},
	{41.5493, 92.3655}, {70.7299, 92.2041},
}

// similarity is the least-squares similarity (rotation, uniform scale
// and shift, no reflection) taking the face's landmarks onto sfaceMarks:
// x' = a*x - b*y + tx, y' = b*x + a*y + ty. ok is false when the
// landmarks are all one point.
func similarity(marks [5][2]float64) (a, b, tx, ty float64, ok bool) {
	var sx, sy, dx, dy float64
	for i := range marks {
		sx += marks[i][0]
		sy += marks[i][1]
		dx += sfaceMarks[i][0]
		dy += sfaceMarks[i][1]
	}
	sx, sy, dx, dy = sx/5, sy/5, dx/5, dy/5
	var num, cross, den float64
	for i := range marks {
		px, py := marks[i][0]-sx, marks[i][1]-sy
		qx, qy := sfaceMarks[i][0]-dx, sfaceMarks[i][1]-dy
		num += px*qx + py*qy
		cross += px*qy - py*qx
		den += px*px + py*py
	}
	if !(den > 1e-9) {
		return 0, 0, 0, 0, false
	}
	a, b = num/den, cross/den
	tx = dx - (a*sx - b*sy)
	ty = dy - (b*sx + a*sy)
	return a, b, tx, ty, finite(a, b, tx, ty)
}

// sfaceInput writes the face aligned onto sfaceMarks into dst, the
// encoder's 1x3x112x112 input: red, green and blue planes of 0 to 255
// (FaceRecognizerSF swaps OpenCV's blue-first order), each pixel sampled
// bilinearly from the frame through the inverse of the similarity, with
// black outside the frame, as OpenCV's warpAffine. A gray8 frame fills
// all three planes. ok is false when the landmarks give no transform.
func sfaceInput(f vision.Frame, fc face, dst []float32) bool {
	a, b, tx, ty, ok := similarity(fc.marks)
	if !ok {
		return false
	}
	bpp := 3
	if f.Format == vision.FormatGray8 {
		bpp = 1
	}
	at := func(x, y, c int) float64 {
		if x < 0 || y < 0 || x >= f.Width || y >= f.Height {
			return 0
		}
		if bpp == 1 {
			c = 0
		}
		return float64(f.Data[(y*f.Width+x)*bpp+c])
	}
	n := a*a + b*b
	plane := sfaceSize * sfaceSize
	for y := 0; y < sfaceSize; y++ {
		for x := 0; x < sfaceSize; x++ {
			ux, uy := float64(x)-tx, float64(y)-ty
			sx := (a*ux + b*uy) / n
			sy := (-b*ux + a*uy) / n
			x0, y0 := int(math.Floor(sx)), int(math.Floor(sy))
			fx, fy := sx-float64(x0), sy-float64(y0)
			for c := 0; c < 3; c++ {
				v := (at(x0, y0, c)*(1-fx)+at(x0+1, y0, c)*fx)*(1-fy) + (at(x0, y0+1, c)*(1-fx)+at(x0+1, y0+1, c)*fx)*fy
				// rgb24 holds red first, as the encoder's planes.
				dst[c*plane+y*sfaceSize+x] = float32(v)
			}
		}
	}
	return true
}

// facesOf gives each person detection at most one face: faces best
// first, each to the smallest person box holding its centre that has no
// face yet. It returns, per detection index, the face given to it.
func facesOf(seen []Seen, fs []face) map[int]face {
	out := map[int]face{}
	for _, f := range fs {
		cx, cy := (f.x0+f.x1)/2, (f.y0+f.y1)/2
		best, area := -1, math.Inf(1)
		for i, d := range seen {
			b := d.Box
			if d.Class != vision.Person || out[i].score > 0 {
				continue
			}
			if cx < float64(b.X0) || cx >= float64(b.X1) || cy < float64(b.Y0) || cy >= float64(b.Y1) {
				continue
			}
			if a := float64((b.X1 - b.X0) * (b.Y1 - b.Y0)); a < area {
				best, area = i, a
			}
		}
		if best >= 0 {
			out[best] = f
		}
	}
	return out
}

// encodeFaces gives each person in seen the face facesOf gives it, as an
// encoding in Seen.Face: the best faces first, up to maxFaces, encoded by
// enc. A face under faceMinSide, or past the bound, gets an empty
// encoding, which names it unknown (service.name). On an error every
// encoding made is zeroed.
func encodeFaces(seen []Seen, fs []face, enc func(face) ([]float32, error)) error {
	given := facesOf(seen, fs)
	order := make([]int, 0, len(given))
	for i := range given {
		order = append(order, i)
	}
	sort.Slice(order, func(a, b int) bool { return given[order[a]].score > given[order[b]].score })
	encoded := 0
	for _, i := range order {
		fc := given[i]
		seen[i].Face = []float32{}
		if fc.side() < faceMinSide || encoded == maxFaces {
			continue
		}
		v, err := enc(fc)
		if err != nil {
			for _, d := range seen {
				clear(d.Face)
			}
			return err
		}
		seen[i].Face = v
		encoded++
	}
	return nil
}

// clearFace is the enrolment frame's one clear face (enrolMinScore,
// enrolMinSide), or false when there is not exactly one.
func clearFace(fs []face) (face, bool) {
	var clear []face
	for _, f := range fs {
		if f.score >= enrolMinScore {
			clear = append(clear, f)
		}
	}
	if len(clear) != 1 || clear[0].side() < enrolMinSide {
		return face{}, false
	}
	return clear[0], true
}
