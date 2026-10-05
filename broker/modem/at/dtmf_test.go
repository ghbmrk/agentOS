package at

import (
	"math"
	"testing"
)

// REQ: CH-5, CH-17

func pcmOf(f func(i int) float64, n int) []byte {
	out := make([]byte, 0, 2*n)
	for i := 0; i < n; i++ {
		s := uint16(int16(f(i)))
		out = append(out, byte(s), byte(s>>8))
	}
	return out
}

func toneAt(key byte, ms, amp int) []byte {
	r, c := 0, 0
	for i, row := range dtmfKeys {
		for j := range row {
			if row[j] == key {
				r, c = i, j
			}
		}
	}
	return pcmOf(func(i int) float64 {
		return float64(amp) * (math.Sin(2*math.Pi*dtmfRows[r]*float64(i)/Rate) + math.Sin(2*math.Pi*dtmfCols[c]*float64(i)/Rate)) / 2
	}, Rate*ms/1000)
}

func voice(ms int) []byte {
	seed := uint32(1)
	return pcmOf(func(i int) float64 {
		seed = seed*1664525 + 1013904223
		t := float64(i) / Rate
		// A gliding fundamental with harmonics, like a talker.
		f0 := 140 + 40*math.Sin(2*math.Pi*3*t)
		return 2500*math.Sin(2*math.Pi*f0*t) + 1500*math.Sin(4*math.Pi*f0*t) + 800*math.Sin(6*math.Pi*f0*t) +
			float64(int32(seed>>16)%1200) - 600
	}, Rate*ms/1000)
}

func run(g *Gate, pcm []byte) (out []byte, keys string, muted int) {
	for i := 0; i+FrameBytes <= len(pcm); i += FrameBytes {
		o, k := g.Push(pcm[i : i+FrameBytes])
		keys += string(k)
		if o != nil {
			out = append(out, o...)
			zero := true
			for _, b := range o {
				if b != 0 {
					zero = false
					break
				}
			}
			if zero {
				muted++
			}
		}
	}
	return
}

func TestGateDecodesEveryKeyAndLeavesNoToneForSpeech(t *testing.T) {
	var in []byte
	for _, k := range []byte("0123456789*#") {
		in = append(in, voice(200)...)
		in = append(in, toneAt(k, 70, 8000)...) // short, phone-style press
	}
	// A weak press and a very short one still get muted.
	in = append(in, voice(200)...)
	in = append(in, toneAt('5', 120, 1500)...)
	in = append(in, voice(200)...)
	in = append(in, toneAt('7', 30, 8000)...)
	in = append(in, voice(400)...)
	out, keys, _ := run(NewGate(), in)
	if keys[:12] != "0123456789*#" {
		t.Fatalf("keys %q", keys)
	}
	if HasTone(out) || Decode(out) != "" {
		t.Fatalf("tones survive in the speech audio")
	}
	if len(out) != (len(in)/FrameBytes-gateDelay)*FrameBytes {
		t.Fatalf("out %d bytes, in %d", len(out), len(in))
	}
}

func TestGatePassesSpeechWithoutKeysUntouched(t *testing.T) {
	in := voice(5000)
	out, keys, muted := run(NewGate(), in)
	if keys != "" || muted != 0 {
		t.Fatalf("plain speech: keys %q, %d frames muted", keys, muted)
	}
	if string(out) != string(in[:len(out)]) {
		t.Fatal("speech altered")
	}
	// Around one press, at most the press and a frame or two either side go.
	in = append(append(voice(500), toneAt('9', 100, 8000)...), voice(500)...)
	_, keys, muted = run(NewGate(), in)
	if keys != "9" || muted > 100/20+4 {
		t.Fatalf("keys %q, %d frames muted for a 100 ms press", keys, muted)
	}
}
