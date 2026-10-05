package at

import "math"

// DTMF keypad decoding and muting for 8 kHz 16-bit mono call audio (CH-5,
// CH-17). Keys pressed during a call are decoded here, in the broker, and
// the tones are cut out of the audio before it reaches the speech service,
// so neither the speech service nor a guest can learn a code from the
// sound. The detector is a Goertzel filter bank, ported from the S2 test
// kit's dtmf.py so S2's keypad results speak for this code.

const (
	// Rate is the call audio sample rate.
	Rate = 8000
	// FrameSamples is one 20 ms audio frame; FrameBytes the same in bytes.
	FrameSamples = 160
	FrameBytes   = 2 * FrameSamples

	dtmfWindow = 205 // ~25.6 ms, the classic Goertzel block at 8 kHz
	dtmfHop    = 102
	// gateDelay frames are held back so a tone found late in a window can
	// still mute the frames before it.
	gateDelay = 3
)

var (
	dtmfRows = [4]float64{697, 770, 852, 941}
	dtmfCols = [4]float64{1209, 1336, 1477, 1633}
	dtmfKeys = [4]string{"123A", "456B", "789C", "*0#D"}
	dtmfCoef = func() (c [8]float64) {
		for i, f := range append(dtmfRows[:], dtmfCols[:]...) {
			c[i] = 2 * math.Cos(2*math.Pi*f/Rate)
		}
		return
	}()
)

// toneKey returns the key a window holds. strict is the decoding test (as
// in dtmf.py); the relaxed test, used for muting, also catches weak or
// partial tones.
func toneKey(x []float64, strict bool) (byte, bool) {
	var energy float64
	for _, v := range x {
		energy += v * v
	}
	minEnergy, dom, share := 1e4, 4.0, 0.5
	if !strict {
		minEnergy, dom, share = 1e3, 2.0, 0.3
	}
	if energy < float64(len(x))*minEnergy {
		return 0, false
	}
	var p [8]float64
	for i, k := range dtmfCoef {
		var s1, s2 float64
		for _, v := range x {
			s1, s2 = v+k*s1-s2, s1
		}
		p[i] = s1*s1 + s2*s2 - k*s1*s2
	}
	r, r2 := top2(p[:4])
	c, c2 := top2(p[4:])
	if p[r2]*dom > p[r] || p[4+c2]*dom > p[4+c] {
		return 0, false
	}
	if (p[r]+p[4+c])*2/float64(len(x)) < energy*share {
		return 0, false
	}
	if twist := p[r] / p[4+c]; twist <= 0.1 || twist >= 10 {
		return 0, false
	}
	return dtmfKeys[r][c], true
}

func top2(p []float64) (best, second int) {
	best, second = 0, 1
	if p[1] > p[0] {
		best, second = 1, 0
	}
	for i := 2; i < len(p); i++ {
		switch {
		case p[i] > p[best]:
			best, second = i, best
		case p[i] > p[second]:
			second = i
		}
	}
	return
}

// Gate decodes keys from uplink audio and mutes the tones. Push frames in
// order; each Push returns the frame from gateDelay frames earlier (nil
// while the delay fills) and any keys completed.
type Gate struct {
	hist    []float64    // samples not yet fully analyzed
	histAt  int          // absolute index of hist[0]
	nextWin int          // absolute start of the next window
	frames  [][]byte     // delay line
	first   int          // absolute frame index of frames[0]
	muteSet map[int]bool // frames to mute, by absolute index
	prev    byte
	run     int
	emitted bool
}

// NewGate returns an empty gate.
func NewGate() *Gate { return &Gate{muteSet: map[int]bool{}} }

// Push adds one FrameBytes frame of little-endian samples.
func (g *Gate) Push(frame []byte) (out []byte, keys []byte) {
	for i := 0; i+1 < len(frame); i += 2 {
		g.hist = append(g.hist, float64(int16(uint16(frame[i])|uint16(frame[i+1])<<8)))
	}
	g.frames = append(g.frames, append([]byte(nil), frame...))
	end := g.histAt + len(g.hist)
	for g.nextWin+dtmfWindow <= end {
		w := g.hist[g.nextWin-g.histAt : g.nextWin-g.histAt+dtmfWindow]
		if k, ok := toneKey(w, true); ok {
			if k == g.prev {
				g.run++
			} else {
				g.prev, g.run, g.emitted = k, 1, false
			}
			if g.run >= 2 && !g.emitted {
				keys = append(keys, k)
				g.emitted = true
			}
		} else {
			g.prev, g.run, g.emitted = 0, 0, false
		}
		if _, ok := toneKey(w, false); ok {
			// Mute every frame the window touches, plus one either side.
			for f := (g.nextWin - FrameSamples) / FrameSamples; f <= (g.nextWin+dtmfWindow+FrameSamples-1)/FrameSamples; f++ {
				if f >= g.first {
					g.muteSet[f] = true
				}
			}
		}
		g.nextWin += dtmfHop
	}
	if drop := g.nextWin - g.histAt; drop > 0 {
		g.hist = g.hist[drop:]
		g.histAt += drop
	}
	if len(g.frames) <= gateDelay {
		return nil, keys
	}
	out, g.frames = g.frames[0], g.frames[1:]
	if g.muteSet[g.first] {
		out = make([]byte, len(out))
	}
	delete(g.muteSet, g.first)
	g.first++
	return out, keys
}

func samples(pcm []byte) []float64 {
	out := make([]float64, len(pcm)/2)
	for i := range out {
		out[i] = float64(int16(uint16(pcm[2*i]) | uint16(pcm[2*i+1])<<8))
	}
	return out
}

// Decode returns the keys in a stretch of audio, each press once.
func Decode(pcm []byte) string {
	g := NewGate()
	var keys []byte
	for i := 0; i+FrameBytes <= len(pcm); i += FrameBytes {
		_, k := g.Push(pcm[i : i+FrameBytes])
		keys = append(keys, k...)
	}
	return string(keys)
}

// HasTone reports whether any window of the audio holds even a weak or
// partial keypad tone: the test the speech side's audio must fail.
func HasTone(pcm []byte) bool {
	x := samples(pcm)
	for i := 0; i+dtmfWindow <= len(x); i += dtmfHop / 2 {
		if _, ok := toneKey(x[i:i+dtmfWindow], false); ok {
			return true
		}
	}
	return false
}
