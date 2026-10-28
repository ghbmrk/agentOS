//go:build vision_onnx && vision_real

package main

// REQ: RES-2, RES-3

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"image"
	_ "image/jpeg"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/vision"
)

// The real runtime's tests (VIS-A27 to A30), run by
// .github/workflows/vision-real.yml with the pinned library and detector
// in AGENTOS_VISION_MODELS and the pinned scene set in
// AGENTOS_VISION_SCENES. Both must be set: these tests fail, never skip,
// without them.

func realDir(t *testing.T, env string) string {
	t.Helper()
	d := os.Getenv(env)
	if d == "" {
		t.Fatalf("%s is not set", env)
	}
	return d
}

// realService serves the real runtime from AGENTOS_VISION_MODELS and
// returns a client of it and how long its first load took.
func realService(t *testing.T) (vision.Client, time.Duration) {
	t.Helper()
	rt := newRuntime(realDir(t, "AGENTOS_VISION_MODELS"), 2)
	s := newService(Config{CallTimeout: 30 * time.Second}, rt, nil)
	start := time.Now()
	if l := s.ready(); l.cause != "" {
		t.Fatalf("the real runtime did not load: %s", l.cause)
	}
	return startClient(t, s), time.Since(start)
}

func startClient(t *testing.T, s *service) vision.Client {
	c := start(t, s)
	c.Timeout = 60 * time.Second
	return c
}

// sceneClass maps the scene set's labels onto the closed list; a label
// not here is not scored.
var sceneClass = map[string]vision.Class{
	"person": vision.Person,
	"car":    vision.Vehicle, "motorcycle": vision.Vehicle, "bus": vision.Vehicle, "truck": vision.Vehicle,
	"bird": vision.Bird, "cat": vision.Cat, "dog": vision.Dog, "bear": vision.Bear,
	"horse": vision.UnknownAnimal, "sheep": vision.UnknownAnimal, "cow": vision.UnknownAnimal,
	"elephant": vision.UnknownAnimal, "zebra": vision.UnknownAnimal, "giraffe": vision.UnknownAnimal,
}

// group is how recall is reported: people, vehicles, and every animal
// class together.
func group(c vision.Class) string {
	switch c {
	case vision.Person:
		return "person"
	case vision.Vehicle:
		return "vehicle"
	}
	return "animal"
}

type sceneObject struct {
	class vision.Class
	box   vision.Box
	// scored objects are at least 32x32 pixels and not a crowd; the
	// others neither count as misses nor make a detection false.
	scored bool
}

type scene struct {
	file    string
	objects []sceneObject
}

// loadScenes reads the scene set's annotations (COCO format).
func loadScenes(t *testing.T, dir string) []scene {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "instances.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Images []struct {
			ID   int    `json:"id"`
			File string `json:"file_name"`
		} `json:"images"`
		Annotations []struct {
			Image    int       `json:"image_id"`
			Category int       `json:"category_id"`
			Box      []float64 `json:"bbox"`
			Crowd    int       `json:"iscrowd"`
		} `json:"annotations"`
		Categories []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	names := map[int]string{}
	for _, c := range a.Categories {
		names[c.ID] = c.Name
	}
	byID := map[int]*scene{}
	var out []*scene
	for _, im := range a.Images {
		s := &scene{file: im.File}
		byID[im.ID] = s
		out = append(out, s)
	}
	for _, an := range a.Annotations {
		c, ok := sceneClass[names[an.Category]]
		s := byID[an.Image]
		if !ok || s == nil || len(an.Box) != 4 {
			continue
		}
		x, y, w, h := an.Box[0], an.Box[1], an.Box[2], an.Box[3]
		s.objects = append(s.objects, sceneObject{class: c,
			box:    vision.Box{X0: int(x), Y0: int(y), X1: int(x + w + 0.5), Y1: int(y + h + 0.5)},
			scored: an.Crowd == 0 && w >= 32 && h >= 32})
	}
	scenes := make([]scene, len(out))
	for i, s := range out {
		scenes[i] = *s
	}
	return scenes
}

// frameOf decodes a scene image as an rgb24 frame, or as a gray8 frame
// (an infrared night picture's format) when gray is set.
func frameOf(t *testing.T, path string, gray bool) vision.Frame {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	im, _, err := image.Decode(bufio.NewReader(fh))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	b := im.Bounds()
	f := vision.Frame{Format: vision.FormatRGB24, Width: b.Dx(), Height: b.Dy()}
	if gray {
		f.Format = vision.FormatGray8
	}
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := im.At(x, y).RGBA()
			if gray {
				f.Data = append(f.Data, byte((299*r+587*g+114*bl)/1000>>8))
			} else {
				f.Data = append(f.Data, byte(r>>8), byte(g>>8), byte(bl>>8))
			}
		}
	}
	return f
}

// tally is recall and precision over the scored objects of one group.
type tally struct{ found, objects, right, detections int }

func (t tally) recall() float64    { return float64(t.found) / float64(max(1, t.objects)) }
func (t tally) precision() float64 { return float64(t.right) / float64(max(1, t.detections)) }

// score matches one frame's detections to its objects: an object is found
// by a detection of its class overlapping it by at least half (IoU), each
// detection finding at most one; a detection is right when it overlaps an
// object of its class (scored or not) by at least half.
func score(ds []vision.Detection, objs []sceneObject, by map[string]*tally) {
	used := make([]bool, len(ds))
	for _, o := range objs {
		if !o.scored {
			continue
		}
		g := by[group(o.class)]
		g.objects++
		best, bi := 0.5, -1
		for i, d := range ds {
			if !used[i] && d.Class == o.class {
				if v := boxIoU(d.Box, o.box); v >= best {
					best, bi = v, i
				}
			}
		}
		if bi >= 0 {
			used[bi] = true
			g.found++
		}
	}
	for _, d := range ds {
		g := by[group(d.Class)]
		g.detections++
		for _, o := range objs {
			if o.class == d.Class && boxIoU(d.Box, o.box) >= 0.5 {
				g.right++
				break
			}
		}
	}
}

// The recorded figures (VIS-A30): the least recall and precision the
// detector must hold on the scene set, a little under what it measured
// when they were recorded, so a broken decode, a wrong channel order or a
// wrong letterbox fails while the same build passes.
var floorRecall = map[string]map[string]float64{
	vision.FormatRGB24: {"person": 0.80, "vehicle": 0.73, "animal": 0.80},
	vision.FormatGray8: {"person": 0.74, "vehicle": 0.70, "animal": 0.73},
}

const floorPrecision = 0.75

// TestRealRuntimeDetect: on the scene set, through the whole service on
// the real runtime, each group's recall and precision is at or above the
// recorded figure, in colour and as infrared-like gray frames; every
// reply passed the service's and the client's closed-vocabulary checks
// on the way.
func TestRealRuntimeDetect(t *testing.T) {
	dir := realDir(t, "AGENTOS_VISION_SCENES")
	c, _ := realService(t)
	scenes := loadScenes(t, dir)
	if len(scenes) < 400 {
		t.Fatalf("scene set has %d images, want at least 400", len(scenes))
	}
	for _, format := range []string{vision.FormatRGB24, vision.FormatGray8} {
		by := map[string]*tally{"person": {}, "vehicle": {}, "animal": {}}
		for _, s := range scenes {
			f := frameOf(t, filepath.Join(dir, "images", s.file), format == vision.FormatGray8)
			ds, err := c.Detect(context.Background(), f)
			if err != nil {
				t.Fatalf("%s %s: %v", s.file, format, err)
			}
			score(ds, s.objects, by)
		}
		for _, g := range []string{"person", "vehicle", "animal"} {
			r := by[g]
			t.Logf("%s %s: recall %d/%d = %.3f, precision %d/%d = %.3f", format, g,
				r.found, r.objects, r.recall(), r.right, r.detections, r.precision())
			if r.recall() < floorRecall[format][g] || r.precision() < floorPrecision {
				t.Errorf("%s %s: recall %.3f (floor %.2f), precision %.3f (floor %.2f)", format, g,
					r.recall(), floorRecall[format][g], r.precision(), floorPrecision)
			}
		}
	}
}

// The floor's limits (VIS-A30), on CI's 4-core runner with 2 runtime
// threads, with room for the N95 (HW-4), which VIS-A30 takes as about two
// times slower per core.
const (
	floorColdStart = 5 * time.Second
	floorFrameP95  = 400 * time.Millisecond // a 1920x1080 colour frame
	floorThermal   = 50 * time.Millisecond  // a 640x512 thermal frame
	floorRSS       = 400 << 20              // the runtime's resident growth
)

// TestFloorFigures: RSS, cold start and per-frame latency are recorded at
// the floor and within the limits above (brief, part e; RES-2).
func TestFloorFigures(t *testing.T) {
	before := rss(t)
	c, cold := realService(t)
	dir := realDir(t, "AGENTOS_VISION_SCENES")
	scenes := loadScenes(t, dir)
	// A full-HD frame made from a scene image, as an eave camera's.
	src := frameOf(t, filepath.Join(dir, "images", scenes[0].file), false)
	hd := vision.Frame{Format: vision.FormatRGB24, Width: 1920, Height: 1080, Data: make([]byte, 1920*1080*3)}
	for y := 0; y < 1080; y++ {
		for x := 0; x < 1920; x++ {
			sx, sy := x*src.Width/1920, y*src.Height/1080
			copy(hd.Data[(y*1920+x)*3:], src.Data[(sy*src.Width+sx)*3:(sy*src.Width+sx)*3+3])
		}
	}
	var times []time.Duration
	for i := 0; i < 40; i++ {
		t0 := time.Now()
		if _, err := c.Detect(context.Background(), hd); err != nil {
			t.Fatal(err)
		}
		times = append(times, time.Since(t0))
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	p50, p95 := times[len(times)/2], times[len(times)*95/100]
	th := thermalScene(rand.New(rand.NewSource(3)), 640, 512, 27315, []vision.Box{{X0: 100, Y0: 100, X1: 120, Y1: 160}})
	t0 := time.Now()
	const thermalRuns = 20
	for i := 0; i < thermalRuns; i++ {
		if ds, err := c.Detect(context.Background(), th); err != nil || len(ds) != 1 {
			t.Fatalf("thermal: %+v, %v", ds, err)
		}
	}
	thermal := time.Since(t0) / thermalRuns
	grown := rss(t) - before
	t.Logf("floor figures: cold start %s, 1920x1080 frame p50 %s p95 %s, 640x512 thermal frame %s, resident growth %d MiB",
		cold.Round(time.Millisecond), p50.Round(time.Millisecond), p95.Round(time.Millisecond), thermal.Round(time.Millisecond), grown>>20)
	if cold > floorColdStart || p95 > floorFrameP95 || thermal > floorThermal || grown > floorRSS {
		t.Errorf("over the floor's limits: cold start %s (%s), p95 %s (%s), thermal %s (%s), resident growth %d MiB (%d)",
			cold, floorColdStart, p95, floorFrameP95, thermal, floorThermal, grown>>20, floorRSS>>20)
	}
}

// rss is the test process's resident set, from /proc.
func rss(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == "VmRSS:" {
			kb, err := strconv.Atoi(f[1])
			if err != nil {
				t.Fatal(err)
			}
			return kb << 10
		}
	}
	t.Fatal("no VmRSS")
	return 0
}

// TestRealRuntimeRefusesOffPinDetector: with the real, pinned library in
// place, a detector one byte off its pin is refused and never loaded
// (VIS-A27; #3774 Security 2).
func TestRealRuntimeRefusesOffPinDetector(t *testing.T) {
	src := realDir(t, "AGENTOS_VISION_MODELS")
	dir := t.TempDir()
	lib, err := os.ReadFile(filepath.Join(src, ortLibrary))
	if err != nil {
		t.Fatal(err)
	}
	det, err := os.ReadFile(filepath.Join(src, detectorFile))
	if err != nil {
		t.Fatal(err)
	}
	det[len(det)/2] ^= 1
	if os.WriteFile(filepath.Join(dir, ortLibrary), lib, 0o755) != nil || os.WriteFile(filepath.Join(dir, detectorFile), det, 0o644) != nil {
		t.Fatal("cannot write the test's model directory")
	}
	if _, err := newRuntime(dir, 1).Load(); !errors.Is(err, ErrRefused) {
		t.Fatalf("detector off its pin: %v, want ErrRefused", err)
	}
}
