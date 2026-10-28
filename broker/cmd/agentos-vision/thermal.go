package main

import (
	"encoding/binary"
	"sort"

	"github.com/ghbmrk/agentos/broker/vision"
)

// Thermal frames are searched for warm bodies by their heat, with no model
// (brief question 2; VIS-A29): no thermal-trained detector with weights
// that allow use was found, and the visible stream and the drone say what
// a warm body is. A y16 sample is taken as a radiometric reading in
// hundredths of a kelvin (the Lepton's and Boson's linear output).
const (
	// thermalContrast is the least excess over the frame's background,
	// 3 K, that marks a sample warm: a clothed person outdoors reads a
	// few kelvin over the ground at night, more by day.
	thermalContrast = 300
	// thermalSpread is how many times the background's own spread a warm
	// sample must also exceed, so a noisy core marks no noise.
	thermalSpread = 6
	// thermalHot is the hottest sample a body may hold, 45 °C: an engine,
	// an exhaust, a vent or a fire is hotter and is not a body.
	thermalHot = 31815
	// thermalMinArea is the fewest samples a body covers: a person 30 m
	// from a 160-pixel-wide core covers about 24.
	thermalMinArea = 8
)

// heatBlobs returns the warm bodies in a y16 frame, best first, at most
// MaxDetections: each 8-connected region of warm samples (at least
// thermalContrast and thermalSpread times the background's spread over the
// frame's median, at most thermalHot) of at least thermalMinArea samples
// and at most a quarter of the frame, as a Warm detection whose confidence
// grows with its mean excess.
func heatBlobs(f vision.Frame) []Seen {
	n := f.Width * f.Height
	// v is a copy of the frame and label the bodies' outlines: both are
	// zeroed on return, as the service zeroes the frame (DEV-7, VIS-A7).
	v := make([]uint16, n)
	defer clear(v)
	for i := range v {
		v[i] = binary.LittleEndian.Uint16(f.Data[2*i:])
	}
	med, spread := background(v)
	limit := int(med) + max(thermalContrast, thermalSpread*spread)
	if limit > thermalHot {
		return nil // the scene is as hot as a body: nothing stands out
	}
	warm := func(i int) bool { return int(v[i]) >= limit && v[i] <= thermalHot }
	label := make([]int32, n)
	defer clear(label)
	type blob struct {
		x0, y0, x1, y1, area int
		excess               int
	}
	var blobs []blob
	stack := make([]int, 0, 64)
	for i := range v {
		if label[i] != 0 || !warm(i) {
			continue
		}
		id := int32(len(blobs) + 1)
		b := blob{x0: f.Width, y0: f.Height}
		label[i] = id
		stack = append(stack[:0], i)
		for len(stack) > 0 {
			j := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			x, y := j%f.Width, j/f.Width
			b.x0, b.y0, b.x1, b.y1 = min(b.x0, x), min(b.y0, y), max(b.x1, x+1), max(b.y1, y+1)
			b.area++
			b.excess += int(v[j]) - int(med)
			for dy := -1; dy <= 1; dy++ {
				for dx := -1; dx <= 1; dx++ {
					nx, ny := x+dx, y+dy
					if nx < 0 || ny < 0 || nx >= f.Width || ny >= f.Height {
						continue
					}
					k := ny*f.Width + nx
					if label[k] == 0 && warm(k) {
						label[k] = id
						stack = append(stack, k)
					}
				}
			}
		}
		blobs = append(blobs, b)
	}
	var out []Seen
	for _, b := range blobs {
		if b.area < thermalMinArea || b.area > n/4 {
			continue
		}
		// 50% at the threshold, 100% at four times it.
		conf := min(100, 50+50*(b.excess/b.area-(limit-int(med)))/(3*(limit-int(med))))
		out = append(out, Seen{Detection: vision.Detection{Class: vision.Warm,
			Box: vision.Box{X0: b.x0, Y0: b.y0, X1: b.x1, Y1: b.y1}, Conf: max(1, conf)}})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Conf > out[j].Conf })
	return out[:min(len(out), vision.MaxDetections)]
}

// background is the frame's median sample and the median distance of a
// sample from it, so warm bodies covering under half the frame move
// neither.
func background(v []uint16) (uint16, int) {
	hist := make([]int, 1<<16)
	for _, x := range v {
		hist[x]++
	}
	half := (len(v) + 1) / 2
	med, seen := 0, 0
	for med = range hist {
		if seen += hist[med]; seen >= half {
			break
		}
	}
	dev := make([]int, 1<<16)
	for x, c := range hist {
		if c > 0 {
			d := x - med
			if d < 0 {
				d = -d
			}
			dev[d] += c
		}
	}
	spread := 0
	seen = 0
	for spread = range dev {
		if seen += dev[spread]; seen >= half {
			break
		}
	}
	return uint16(med), spread
}
