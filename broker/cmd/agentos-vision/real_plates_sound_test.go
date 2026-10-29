//go:build linux && vision_onnx && vision_real

package main

// REQ: DEV-7, DEV-8, RES-2

import (
	"bufio"
	"context"
	"encoding/binary"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
	"time"

	ort "github.com/yalue/onnxruntime_go"

	"github.com/ghbmrk/agentos/broker/vision"
)

// The plate and sound figures (VIS-A33, VIS-A34), run by
// .github/workflows/vision-real.yml with the pinned plate set in
// AGENTOS_VISION_PLATES and the pinned sound set in AGENTOS_VISION_SOUNDS.
// They fail, never skip, without them.

// The figures' floors (VIS-A33, VIS-A34).
const (
	// A clean plate image, read whole by the reader.
	floorPlateCleanRight = 0.92
	floorPlateCleanWrong = 0.04
	// A plate blurred, tilted and noised on a 448-pixel background, found
	// by the plate detector and read: right reads of all, and wrong reads
	// of all reads.
	floorPlateSceneRight = 0.52
	floorPlateSceneWrong = 0.08
	// Sound: each scored label heard on its clips, and labels heard on
	// clips of none of them.
	floorSoundRecall = 0.60
	floorSoundFalse  = 0.09
	// Latency on CI's runner: the plate path on one vehicle, and a 10 s
	// clip.
	floorPlatePath = 150 * time.Millisecond
	floorSoundClip = 500 * time.Millisecond
)

type plateCase struct{ name, text string }

func loadPlates(t *testing.T, dir string) []plateCase {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "plates.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ps []plateCase
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Split(sc.Text(), "\t")
		if len(fs) != 2 || !vision.ValidPlate(fs[1]) {
			t.Fatalf("plate set line %q", sc.Text())
		}
		ps = append(ps, plateCase{fs[0], fs[1]})
	}
	if len(ps) < 400 {
		t.Fatalf("plate set has %d plates, want at least 400", len(ps))
	}
	return ps
}

// realLoad is the real runtime loaded from AGENTOS_VISION_MODELS, and a
// run begun on it.
func realLoad(t *testing.T) (*onnxLoad, *ort.RunOptions) {
	t.Helper()
	rt := newRuntime(realDir(t, "AGENTOS_VISION_MODELS"), 2).(*onnxRuntime)
	if _, err := rt.Load(); err != nil {
		t.Fatalf("the real runtime did not load: %v", err)
	}
	l, _ := rt.current()
	ro, ok := l.begin()
	if !ok {
		t.Fatal("no run")
	}
	t.Cleanup(func() { l.end(ro) })
	return l, ro
}

// TestRealPlates: the reader on clean synthetic plates, and the plate
// detector and reader together, through the runtime's own plate path, on
// the same plates blurred, tilted and noised on a background (VIS-A33).
// Plate text is compared without spaces, as the reader gives none.
func TestRealPlates(t *testing.T) {
	dir := realDir(t, "AGENTOS_VISION_PLATES")
	ps := loadPlates(t, dir)
	l, ro := realLoad(t)
	var cleanRight, cleanWrong, sceneRight, sceneWrong, scenes int
	out := make([]float32, readerSlots*len(readerAlphabet))
	rin := make([]uint8, readerW*readerH*3)
	for _, p := range ps {
		want := strings.ReplaceAll(p.text, " ", "")
		f := frameOf(t, filepath.Join(dir, p.name+"-clean.jpg"), false)
		readerInput(f, rect{0, 0, f.Width, f.Height}, rin)
		it, err := ort.NewTensor(ort.NewShape(1, readerH, readerW, 3), rin)
		if err != nil {
			t.Fatal(err)
		}
		ot, err := ort.NewTensor(ort.NewShape(1, readerSlots, int64(len(readerAlphabet))), out)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.reader.RunWithOptions([]ort.Value{it}, []ort.Value{ot}, ro); err != nil {
			t.Fatal(err)
		}
		it.Destroy()
		ot.Destroy()
		if got, ok := readerDecode(out); ok && got == want {
			cleanRight++
		} else if ok {
			cleanWrong++
		}
		for _, side := range []string{"front", "rear"} {
			f := frameOf(t, filepath.Join(dir, p.name+"-"+side+".jpg"), false)
			seen := []Seen{{Detection: vision.Detection{Class: vision.Vehicle, Box: vision.Box{X1: f.Width, Y1: f.Height}, Conf: 90}}}
			if err := l.plates(f, ro, seen); err != nil {
				t.Fatal(err)
			}
			scenes++
			switch got := seen[0].Plate; {
			case got == want:
				sceneRight++
			case got != "":
				sceneWrong++
			}
		}
	}
	n := float64(len(ps))
	cr, cw := float64(cleanRight)/n, float64(cleanWrong)/n
	sr := float64(sceneRight) / float64(scenes)
	sw := float64(sceneWrong) / float64(max(1, sceneRight+sceneWrong))
	t.Logf("plates: clean %d right (%.3f), %d wrong (%.3f) of %d; scene %d right (%.3f), %d wrong (%.3f of reads) of %d",
		cleanRight, cr, cleanWrong, cw, len(ps), sceneRight, sr, sceneWrong, sw, scenes)
	if cr < floorPlateCleanRight || cw > floorPlateCleanWrong || sr < floorPlateSceneRight || sw > floorPlateSceneWrong {
		t.Errorf("under the plate floors (%.2f, %.2f, %.2f, %.2f)", floorPlateCleanRight, floorPlateCleanWrong, floorPlateSceneRight, floorPlateSceneWrong)
	}
}

// soundScored maps the sound set's categories to the label each should be
// heard as; a category not here should be heard as none.
var soundScored = map[string]string{
	"dog": "dog-bark", "glass_breaking": "glass-break", "door_wood_knock": "knock",
	"clock_alarm": "alarm", "siren": "alarm", "car_horn": "vehicle",
}

// soundUnscored are categories that may fairly be heard as a label on
// the list, or not, so are scored neither way: a door knock's neighbour,
// bells, vehicles that are not road vehicles, and ESC-50's engines, which
// mix road vehicles with machines.
var soundUnscored = map[string]bool{
	"door_wood_creaks": true, "train": true, "airplane": true, "helicopter": true, "church_bells": true,
	"engine": true,
}

type soundClip struct{ file, category string }

func loadSounds(t *testing.T, dir string) []soundClip {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "clips.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var cs []soundClip
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Split(sc.Text(), "\t")
		if len(fs) != 2 {
			t.Fatalf("sound set line %q", sc.Text())
		}
		cs = append(cs, soundClip{fs[0], fs[1]})
	}
	if len(cs) < 400 {
		t.Fatalf("sound set has %d clips, want at least 400", len(cs))
	}
	return cs
}

// wavPCM16k reads a 16-bit mono WAV file and resamples it to AudioPCM16k.
func wavPCM16k(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 12 || string(b[:4]) != "RIFF" || string(b[8:12]) != "WAVE" {
		t.Fatalf("%s: not a WAV file", path)
	}
	var rate int
	var data []byte
	for i := 12; i+8 <= len(b); {
		id, n := string(b[i:i+4]), int(binary.LittleEndian.Uint32(b[i+4:]))
		body := b[i+8 : min(len(b), i+8+n)]
		switch id {
		case "fmt ":
			if len(body) < 16 || binary.LittleEndian.Uint16(body[0:]) != 1 || binary.LittleEndian.Uint16(body[2:]) != 1 || binary.LittleEndian.Uint16(body[14:]) != 16 {
				t.Fatalf("%s: not 16-bit mono PCM", path)
			}
			rate = int(binary.LittleEndian.Uint32(body[4:]))
		case "data":
			data = body
		}
		i += 8 + n + n%2
	}
	if rate == 0 || data == nil {
		t.Fatalf("%s: no format or data", path)
	}
	in := make([]float64, len(data)/2)
	for i := range in {
		in[i] = float64(int16(binary.LittleEndian.Uint16(data[2*i:])))
	}
	out := resample(in, rate, 16000)
	pcm := make([]byte, 2*len(out))
	for i, v := range out {
		binary.LittleEndian.PutUint16(pcm[2*i:], uint16(int16(math.Max(-32768, math.Min(32767, math.Round(v))))))
	}
	return pcm
}

// resample is a Hann-windowed sinc resampler from rate a to rate b, its
// cut-off at 0.45 of the lower rate.
func resample(x []float64, a, b int) []float64 {
	const half = 32
	ratio := float64(a) / float64(b)
	fc := 0.45 * float64(min(a, b)) / float64(a)
	y := make([]float64, int(float64(len(x))/ratio))
	for i := range y {
		ti := float64(i) * ratio
		c := int(math.Floor(ti))
		var s float64
		for k := max(0, c-half+1); k <= min(len(x)-1, c+half); k++ {
			d := ti - float64(k)
			arg := 2 * fc * d
			sinc := 1.0
			if arg != 0 {
				sinc = math.Sin(math.Pi*arg) / (math.Pi * arg)
			}
			s += x[k] * 2 * fc * sinc * (0.5 + 0.5*math.Cos(math.Pi*d/half))
		}
		y[i] = s
	}
	return y
}

// TestRealSound: YAMNet through the service and client on the pinned
// sound set (ESC-50 folds 3 and 4, held out from the folds the thresholds
// were set on): each scored label's recall on its clips, and the share of
// the other clips on which any label is heard (VIS-A34). The ESC-50
// categories with no label on the list give the false rate; no gunshot,
// scream or doorbell clip is in the set.
func TestRealSound(t *testing.T) {
	dir := realDir(t, "AGENTOS_VISION_SOUNDS")
	cs := loadSounds(t, dir)
	c, _ := realService(t)
	heard := map[string][2]int{}
	var falses, others int
	confusions := map[string]int{}
	for _, cl := range cs {
		if soundUnscored[cl.category] {
			continue
		}
		ss, err := c.Sound(context.Background(), wavPCM16k(t, filepath.Join(dir, "audio", cl.file)))
		if err != nil {
			t.Fatalf("%s: %v", cl.file, err)
		}
		want, scored := soundScored[cl.category]
		if !scored {
			others++
			if len(ss) > 0 {
				falses++
				confusions[cl.category+">"+ss[0].Label]++
			}
			continue
		}
		h := heard[want]
		h[1]++
		for _, s := range ss {
			if s.Label == want {
				h[0]++
				break
			}
		}
		heard[want] = h
	}
	var labels []string
	for l := range heard {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	fail := false
	for _, l := range labels {
		h := heard[l]
		r := float64(h[0]) / float64(h[1])
		t.Logf("sound %s: heard on %d of %d (%.3f)", l, h[0], h[1], r)
		fail = fail || r < floorSoundRecall
	}
	fr := float64(falses) / float64(max(1, others))
	t.Logf("sound: a label heard on %d of %d clips of none (%.3f); %v", falses, others, fr, confusions)
	if len(labels) != 5 || fail || fr > floorSoundFalse {
		t.Errorf("under the sound floors (recall %.2f each, false %.2f)", floorSoundRecall, floorSoundFalse)
	}
}

// TestFloorPlatesSound: the plate path on one vehicle and a 10 s clip are
// within the floor's limits (VIS-A30, VIS-A33, VIS-A34).
func TestFloorPlatesSound(t *testing.T) {
	ps := loadPlates(t, realDir(t, "AGENTOS_VISION_PLATES"))
	l, ro := realLoad(t)
	f := frameOf(t, filepath.Join(realDir(t, "AGENTOS_VISION_PLATES"), ps[0].name+"-front.jpg"), false)
	var times []time.Duration
	for i := 0; i < 20; i++ {
		seen := []Seen{{Detection: vision.Detection{Class: vision.Vehicle, Box: vision.Box{X1: f.Width, Y1: f.Height}, Conf: 90}}}
		t0 := time.Now()
		if err := l.plates(f, ro, seen); err != nil {
			t.Fatal(err)
		}
		times = append(times, time.Since(t0))
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	plate := times[len(times)*95/100]
	c, _ := realService(t)
	clip := make([]byte, vision.MaxAudioBytes)
	for i := 0; i < len(clip)/2; i++ {
		binary.LittleEndian.PutUint16(clip[2*i:], uint16(int16(3000*math.Sin(float64(i)/7))))
	}
	t0 := time.Now()
	const runs = 5
	for i := 0; i < runs; i++ {
		if _, err := c.Sound(context.Background(), append([]byte(nil), clip...)); err != nil {
			t.Fatal(err)
		}
	}
	sound := time.Since(t0) / runs
	t.Logf("floor figures: plate path on one vehicle p95 %s, 10 s clip %s", plate.Round(time.Millisecond), sound.Round(time.Millisecond))
	if plate > floorPlatePath || sound > floorSoundClip {
		t.Errorf("over the floor's limits: plate %s (%s), sound %s (%s)", plate, floorPlatePath, sound, floorSoundClip)
	}
}

// TestRealSoundOutputsScoresOnly: the loaded sound session's only output
// is the class scores (VIS-A34): asking it for the window embeddings
// fails, as the session was not built with them.
func TestRealSoundOutputsScoresOnly(t *testing.T) {
	l, ro := realLoad(t)
	in := make([]float32, yamnetMinSamples)
	it, err := ort.NewTensor(ort.NewShape(yamnetMinSamples), in)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Destroy()
	outs := []ort.Value{nil, nil}
	if err := l.yamnet.RunWithOptions([]ort.Value{it}, outs, ro); err == nil {
		t.Fatal("the sound session gave a second output")
	}
	one := []ort.Value{nil}
	if err := l.yamnet.RunWithOptions([]ort.Value{it}, one, ro); err != nil {
		t.Fatal(err)
	}
	defer one[0].Destroy()
	if s := one[0].GetShape(); len(s) != 2 || s[1] != yamnetClasses {
		t.Fatalf("score shape %v", s)
	}
}

// TestRealSoundLeavesNoSampleCopy (DEV-7, brief point 7: audio is never
// kept): once Sound has returned and the caller has zeroed the clip, no
// run of the clip's samples is left in memory, as 16-bit samples or as
// the float copy the model is given.
func TestRealSoundLeavesNoSampleCopy(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	rt := realRuntime(t)
	rng := rand.New(rand.NewSource(4))
	pcm := make([]byte, 2*16000*3)
	for i := 0; i < len(pcm)/2; i++ {
		binary.LittleEndian.PutUint16(pcm[2*i:], uint16(int16(rng.Intn(20000)-10000)))
	}
	// The run looked for: 16 samples from the middle of the clip, as the
	// clip holds them and as the floats the model is given.
	at := len(pcm) / 4
	f := make([]float32, 16)
	for i := range f {
		f[i] = float32(int16(binary.LittleEndian.Uint16(pcm[at+2*i:]))) / 32768
	}
	floats, fkey := maskEncoding(rng, f)
	clear(f)
	ints, ikey := make([]byte, 32), make([]byte, 32)
	rng.Read(ikey)
	for i := range ints {
		ints[i] = pcm[at+i] ^ ikey[i]
	}
	if scanMemory(t, ints, ikey) == 0 {
		t.Fatal("the scanner did not find the clip while the caller held it")
	}
	if _, err := rt.Sound(pcm); err != nil {
		t.Fatal(err)
	}
	clear(pcm)
	if n, m := scanMemory(t, ints, ikey), scanMemory(t, floats, fkey); n != 0 || m != 0 {
		t.Fatalf("the clip is left in memory after Sound: %d places as samples, %d as floats", n, m)
	}
}
