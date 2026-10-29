package main

// REQ: DEV-8

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vision"
)

// readerOut is the reader's output reading text: each slot certain of
// its character, the rest certain of the pad.
func readerOut(text string, p float32) []float32 {
	n := len(readerAlphabet)
	out := make([]float32, readerSlots*n)
	for s := 0; s < readerSlots; s++ {
		ch := byte('_')
		if s < len(text) {
			ch = text[s]
		}
		out[s*n+strings.IndexByte(readerAlphabet, ch)] = p
	}
	return out
}

func TestReaderDecode(t *testing.T) {
	if got, ok := readerDecode(readerOut("AB12CDE", 0.95)); !ok || got != "AB12CDE" {
		t.Fatalf("clear read: %q %v", got, ok)
	}
	if got, ok := readerDecode(readerOut("0123456789", 0.95)); !ok || got != "0123456789" {
		t.Fatalf("ten slots: %q %v", got, ok)
	}
	for name, out := range map[string][]float32{
		"unsure slot":   readerOut("AB12CDE", readerMinProb-0.01),
		"all pads":      readerOut("", 0.95),
		"short output":  readerOut("AB1", 0.95)[1:],
		"pad then char": readerOut("AB_12", 0.95),
	} {
		if got, ok := readerDecode(out); ok {
			t.Errorf("%s read as %q", name, got)
		}
	}
	nan := readerOut("AB12", 0.95)
	nan[3] = float32(math.NaN())
	if got, ok := readerDecode(nan); ok {
		t.Errorf("a NaN read as %q", got)
	}
}

// TestPlateDecode: the best plate row maps back to the frame through the
// letterbox, below-score, too-narrow and non-finite rows are dropped.
func TestPlateDecode(t *testing.T) {
	f := vision.Frame{Format: vision.FormatRGB24, Width: 1000, Height: 500, Data: make([]byte, 1000*500*3)}
	r := rect{200, 100, 600, 300} // 400 by 200: scale 1.04, centred
	in := make([]float32, 3*plateSize*plateSize)
	pb := plateInput(f, r, in)
	if !near2(pb.scale, 1.04) || pb.dx != 0 || !near2(pb.dy, 104) {
		t.Fatalf("letterbox %+v", pb)
	}
	at := func(x, y float64) (float32, float32) {
		return float32((x-200)*pb.scale + pb.dx), float32((y-100)*pb.scale + pb.dy)
	}
	x0, y0 := at(300, 220)
	x1, y1 := at(420, 250)
	n0, m0 := at(250, 150)
	n1, m1 := at(260, 160)
	out := []float32{
		0, x0, y0, x1, y1, 0, 0.8,
		0, n0, m0, n1, m1, 0, 0.99, // 10 px wide: too narrow
		0, x0, y0, x1, y1, 0, 0.3, // below the score
		0, float32(math.Inf(1)), y0, x1, y1, 0, 0.95,
	}
	got, ok := plateDecode(out, pb)
	if !ok || got != (rect{300, 220, 420, 250}) {
		t.Fatalf("plate %+v %v", got, ok)
	}
	if _, ok := plateDecode(out[7:21], pb); ok {
		t.Fatal("a narrow or weak plate was kept")
	}
	// A box past the vehicle is clamped to it.
	ex0, ey0 := at(150, 50)
	ex1, ey1 := at(700, 320)
	got, ok = plateDecode([]float32{0, ex0, ey0, ex1, ey1, 0, 0.9}, pb)
	if !ok || got != r {
		t.Fatalf("clamped plate %+v %v", got, ok)
	}
}

// TestPlateInputPadsAndFills: the region fills the centre of the input as
// red, green and blue from 0 to 1, and the bands around it are grey.
func TestPlateInputPadsAndFills(t *testing.T) {
	f := vision.Frame{Format: vision.FormatRGB24, Width: 64, Height: 32, Data: make([]byte, 64*32*3)}
	for i := 0; i < len(f.Data); i += 3 {
		f.Data[i], f.Data[i+1], f.Data[i+2] = 255, 128, 0
	}
	in := make([]float32, 3*plateSize*plateSize)
	pb := plateInput(f, rect{0, 0, 64, 32}, in)
	plane := plateSize * plateSize
	mid := (plateSize/2)*plateSize + plateSize/2
	if in[mid] != 1 || !near2(float64(in[plane+mid]), 128.0/255) || in[2*plane+mid] != 0 {
		t.Fatalf("centre pixel %v %v %v", in[mid], in[plane+mid], in[2*plane+mid])
	}
	if in[0] != 114.0/255 || pb.dy != 104 {
		t.Fatalf("pad %v, dy %v", in[0], pb.dy)
	}
	g := vision.Frame{Format: vision.FormatGray8, Width: 64, Height: 32, Data: make([]byte, 64*32)}
	for i := range g.Data {
		g.Data[i] = 51
	}
	plateInput(g, rect{0, 0, 64, 32}, in)
	if !near2(float64(in[mid]), 0.2) || in[mid] != in[plane+mid] || in[mid] != in[2*plane+mid] {
		t.Fatal("a gray8 frame does not fill all three planes")
	}
	rin := make([]uint8, readerW*readerH*3)
	readerInput(f, rect{0, 0, 64, 32}, rin)
	if rin[0] != 255 || rin[1] != 128 || rin[2] != 0 {
		t.Fatalf("reader pixel %v", rin[:3])
	}
}

func TestPlateVehiclesBestFirstBounded(t *testing.T) {
	var seen []Seen
	for i := 0; i < 7; i++ {
		c := vision.Vehicle
		if i%3 == 0 {
			c = vision.Person
		}
		seen = append(seen, Seen{Detection: vision.Detection{Class: c, Box: vision.Box{X1: plateMinVehicle}, Conf: 10 + i}})
	}
	// A vehicle too narrow to hold a readable plate is not searched.
	seen = append(seen, Seen{Detection: vision.Detection{Class: vision.Vehicle, Box: vision.Box{X0: 1, X1: plateMinVehicle}, Conf: 99}})
	got := plateVehicles(seen)
	if want := []int{5, 4, 2, 1}; len(got) != len(want) || got[0] != 5 || got[1] != 4 || got[2] != 2 || got[3] != 1 {
		t.Fatalf("vehicles %v, want %v", got, want)
	}
}

func TestSoundInputAndDecode(t *testing.T) {
	pcm := make([]byte, 8)
	for i, v := range []int16{16384, -32768, 0, 32767} {
		binary.LittleEndian.PutUint16(pcm[2*i:], uint16(v))
	}
	dst := make([]float32, yamnetMinSamples)
	for i := range dst {
		dst[i] = 9
	}
	if n := soundInput(pcm, dst); n != yamnetMinSamples || dst[0] != 0.5 || dst[1] != -1 || dst[4] != 0 || dst[len(dst)-1] != 0 {
		t.Fatalf("samples %v ... %v (n %d)", dst[:5], dst[len(dst)-1], n)
	}
	scores := make([]float32, 3*yamnetClasses)
	bark := soundMinScore["dog-bark"] + 0.05
	scores[yamnetClasses+70] = float32(bark) // Bark, second window
	scores[2*yamnetClasses+0] = 0.99         // Speech: on no list
	scores[349] = float32(soundMinScore["doorbell"] - 0.01)
	scores[2*yamnetClasses+421] = float32(math.NaN())
	got := soundDecode(scores)
	if len(got) != 1 || got[0] != (vision.Sound{Label: "dog-bark", Conf: percent(bark)}) {
		t.Fatalf("sounds %+v", got)
	}
	if err := vision.CheckSounds(got); err != nil {
		t.Fatal(err)
	}
	if soundDecode(scores[1:]) != nil {
		t.Fatal("a ragged score array was decoded")
	}
}

// TestSoundClassesClosed: every label on the closed list has classes and
// a threshold, no other label does, and no class is one of YAMNet's
// speech and voice classes (indexes 0 to 10: speech, conversation,
// narration, babbling, shouts and yells; 11 is screaming).
func TestSoundClassesClosed(t *testing.T) {
	if len(soundClasses) != len(vision.SoundLabels()) || len(soundMinScore) != len(soundClasses) {
		t.Fatal("the label maps do not match the closed list")
	}
	for _, l := range vision.SoundLabels() {
		if len(soundClasses[l]) == 0 || soundMinScore[l] <= 0 {
			t.Errorf("%s has no classes or threshold", l)
		}
		for _, c := range soundClasses[l] {
			if c < 11 || c >= yamnetClasses {
				t.Errorf("%s: class %d", l, c)
			}
		}
	}
}
