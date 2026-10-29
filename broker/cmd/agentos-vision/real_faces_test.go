//go:build vision_onnx && vision_real

package main

// REQ: DEV-7

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/vision"
)

// The real face path's tests (VIS-A31, VIS-A32), run by
// .github/workflows/vision-real.yml with the pinned face set in
// AGENTOS_VISION_FACES: synthetic people (SFHQ part 1, generated faces of
// no one; faces.pins), one portrait each. Each person's other sightings
// are made from their portrait: mirrored, turned, scaled into a wider
// scene, relit and noised, as an eave camera would see them. They fail,
// never skip, without the set.

// faceNames are the face set's portraits, in name order.
func faceNames(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(filepath.Join(dir, "images"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		if strings.HasSuffix(e.Name(), ".jpg") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) < 900 {
		t.Fatalf("face set has %d portraits, want at least 900", len(names))
	}
	return names
}

// sighting is a scene of w by h holding the portrait p, as a camera sees
// a person: on a noisy background, mirrored or not, turned by up to 15
// degrees, scaled so the portrait is between lo and hi of the scene's
// height, relit by a gain of 0.7 to 1.3 and an offset of up to 20, with
// pixel noise. A gray scene (an infrared night picture) is the luma.
func sighting(rng *rand.Rand, p vision.Frame, w, h int, lo, hi float64, grayOut bool) vision.Frame {
	side := (lo + rng.Float64()*(hi-lo)) * float64(h)
	scale := side / float64(p.Height)
	angle := (rng.Float64()*30 - 15) * math.Pi / 180
	mirror := rng.Intn(2) == 1
	cx := side/2 + rng.Float64()*(float64(w)-side)
	cy := side/2 + rng.Float64()*(float64(h)-side)
	gain, offset := 0.7+rng.Float64()*0.6, rng.Float64()*40-20
	cos, sin := math.Cos(angle), math.Sin(angle)
	bg := 90 + rng.Float64()*70
	out := vision.Frame{Format: vision.FormatRGB24, Width: w, Height: h}
	bpp := 3
	if grayOut {
		out.Format, bpp = vision.FormatGray8, 1
	}
	out.Data = make([]byte, w*h*bpp)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			// The scene pixel's place in the portrait.
			dx, dy := (float64(x)-cx)/scale, (float64(y)-cy)/scale
			px := cos*dx + sin*dy + float64(p.Width)/2
			py := -sin*dx + cos*dy + float64(p.Height)/2
			if mirror {
				px = float64(p.Width) - 1 - px
			}
			var rgb [3]float64
			if px >= 0 && py >= 0 && px < float64(p.Width-1) && py < float64(p.Height-1) {
				x0, y0 := int(px), int(py)
				fx, fy := px-float64(x0), py-float64(y0)
				for c := 0; c < 3; c++ {
					at := func(x, y int) float64 { return float64(p.Data[(y*p.Width+x)*3+c]) }
					rgb[c] = (at(x0, y0)*(1-fx)+at(x0+1, y0)*fx)*(1-fy) + (at(x0, y0+1)*(1-fx)+at(x0+1, y0+1)*fx)*fy
				}
			} else {
				rgb = [3]float64{bg, bg, bg}
			}
			n := rng.NormFloat64() * 4
			for c := range rgb {
				rgb[c] = math.Max(0, math.Min(255, rgb[c]*gain+offset+n))
			}
			if grayOut {
				out.Data[y*w+x] = byte(0.299*rgb[0] + 0.587*rgb[1] + 0.114*rgb[2])
			} else {
				i := (y*w + x) * 3
				out.Data[i], out.Data[i+1], out.Data[i+2] = byte(rgb[0]), byte(rgb[1]), byte(rgb[2])
			}
		}
	}
	return out
}

// faceTwins is faces.pins' twins: each portrait that is a copy of
// another, to the one it copies.
func faceTwins(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("faces.pins")
	if err != nil {
		t.Fatal(err)
	}
	twins := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == "twin" {
			twins[f[1]] = f[2]
		}
	}
	if len(twins) == 0 {
		t.Fatal("faces.pins names no twins")
	}
	return twins
}

// realFaceService serves the real runtime on a feed and a control socket.
func realFaceService(t *testing.T, enrolled func(string) bool) (vision.Client, vision.ControlClient) {
	t.Helper()
	rt := newRuntime(realDir(t, "AGENTOS_VISION_MODELS"), 2)
	s := newService(Config{CallTimeout: 30 * time.Second}, rt, nil)
	if l := s.ready(); l.cause != "" {
		t.Fatalf("the real runtime did not load: %s", l.cause)
	}
	dir := t.TempDir()
	feed, ctl := filepath.Join(dir, "v.sock"), filepath.Join(dir, "v.ctl")
	for path, serve := range map[string]func(net.Listener) error{feed: s.Serve, ctl: s.ServeControl} {
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go serve(ln)
	}
	return vision.Client{Path: feed, Timeout: 60 * time.Second, Enrolled: enrolled},
		vision.ControlClient{Path: ctl, Timeout: 60 * time.Second}
}

// faceCount is what sightings of people gave: a face named rightly, a
// face named as someone else, a face unknown, or no face on any person.
type faceCount struct{ right, wrong, unknown, none int }

func (c faceCount) total() int { return c.right + c.wrong + c.unknown + c.none }

// faceOf is the face reported on a sighting: the face of its one person
// with a face, "" when no person has one.
func faceOf(t *testing.T, ds []vision.Detection) string {
	face := ""
	for _, d := range ds {
		if d.Face != "" {
			if face != "" {
				t.Fatalf("two faces on one person's sighting: %+v", ds)
			}
			face = d.Face
		}
	}
	return face
}

// The recorded figures (VIS-A32), a little under what was measured when
// they were recorded, so a wrong alignment, channel order or threshold
// fails while the same build passes.
const (
	floorFaceFound = 0.95 // sightings of a person whose face is reported
	floorNamed     = 0.95 // of those, the share named rightly (colour)
	floorNamedGray = 0.90 // the same as gray frames
	// No sighting of someone not enrolled, and no sighting of an
	// enrolled person, may be named as anyone else.
	ceilWrong = 0
)

// TestRealFaces: through the whole service on the real runtime, the face
// set's first MaxEnrolled people are enrolled from their portraits and
// lent; sightings of each are named rightly at or above the recorded
// figure, in colour and as gray frames; and no sighting of anyone else,
// nor of an enrolled person, is named as someone it is not.
func TestRealFaces(t *testing.T) {
	dir := realDir(t, "AGENTOS_VISION_FACES")
	names := faceNames(t, dir)
	ids := map[string]bool{}
	c, ctl := realFaceService(t, func(id string) bool { return ids[id] })
	var ts []vision.Template
	for i, n := range names[:vision.MaxEnrolled] {
		p := frameOf(t, filepath.Join(dir, "images", n), false)
		tpl, err := ctl.Enrol(context.Background(), p)
		if err != nil {
			t.Fatalf("enrolling %s: %v", n, err)
		}
		id := fmt.Sprintf("p%02d", i)
		ids[id] = true
		ts = append(ts, vision.Template{ID: id, Vec: tpl})
	}
	if err := ctl.Lend(context.Background(), ts); err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	const sightings = 4
	look := func(p vision.Frame, gray bool) string {
		f := sighting(rng, p, 1280, 720, 0.25, 0.9, gray)
		ds, err := c.Detect(context.Background(), f)
		if err != nil {
			t.Fatalf("detect: %v", err)
		}
		return faceOf(t, ds)
	}
	tally := func(c *faceCount, got, want string) {
		switch got {
		case "":
			c.none++
		case vision.FaceUnknown:
			c.unknown++
		case want:
			c.right++
		default:
			c.wrong++
		}
	}
	var colour, gray, others faceCount
	for i, n := range names[:vision.MaxEnrolled] {
		p := frameOf(t, filepath.Join(dir, "images", n), false)
		want := vision.FaceEnrolledAs + fmt.Sprintf("p%02d", i)
		for k := 0; k < sightings; k++ {
			tally(&colour, look(p, false), want)
			tally(&gray, look(p, true), want)
		}
	}
	twins := faceTwins(t)
	enrolledAs := map[string]string{}
	for i, n := range names[:vision.MaxEnrolled] {
		enrolledAs[n] = vision.FaceEnrolledAs + fmt.Sprintf("p%02d", i)
	}
	var twinNamed int
	for _, n := range names[vision.MaxEnrolled:] {
		got := look(frameOf(t, filepath.Join(dir, "images", n), false), false)
		if as, ok := enrolledAs[twins[n]]; ok && got == as {
			twinNamed++ // a copy of an enrolled person, named as them
			continue
		}
		tally(&others, got, vision.FaceUnknown)
	}
	found := func(c faceCount) float64 { return 1 - float64(c.none)/float64(max(1, c.total())) }
	named := func(c faceCount) float64 { return float64(c.right) / float64(max(1, c.total()-c.none)) }
	t.Logf("enrolled, colour: %+v (face found %.3f, named %.3f)", colour, found(colour), named(colour))
	t.Logf("enrolled, gray: %+v (face found %.3f, named %.3f)", gray, found(gray), named(gray))
	t.Logf("not enrolled: %+v (face found %.3f); copies of enrolled people named as them: %d", others, found(others), twinNamed)
	if found(colour) < floorFaceFound || found(others) < floorFaceFound {
		t.Errorf("faces found: enrolled %.3f, others %.3f (floor %.2f)", found(colour), found(others), floorFaceFound)
	}
	if named(colour) < floorNamed || named(gray) < floorNamedGray {
		t.Errorf("named rightly: colour %.3f (floor %.2f), gray %.3f (floor %.2f)", named(colour), floorNamed, named(gray), floorNamedGray)
	}
	if w := colour.wrong + gray.wrong + others.wrong; w > ceilWrong {
		t.Errorf("%d sightings named as someone they are not", w)
	}
}

// TestRealEnrolNeedsOneClearFace: an enrolment frame with no face, with
// two clear faces, or with a face too small to be clear is NoFace, and a
// portrait enrols.
func TestRealEnrolNeedsOneClearFace(t *testing.T) {
	dir := realDir(t, "AGENTOS_VISION_FACES")
	names := faceNames(t, dir)
	_, ctl := realFaceService(t, nil)
	p := frameOf(t, filepath.Join(dir, "images", names[0]), false)
	q := frameOf(t, filepath.Join(dir, "images", names[1]), false)
	if _, err := ctl.Enrol(context.Background(), p); err != nil {
		t.Fatalf("a portrait: %v", err)
	}
	blank := vision.Frame{Format: vision.FormatRGB24, Width: 640, Height: 480, Data: make([]byte, 640*480*3)}
	two := vision.Frame{Format: vision.FormatRGB24, Width: 2 * p.Width, Height: p.Height, Data: make([]byte, 2*p.Width*p.Height*3)}
	for y := 0; y < p.Height; y++ {
		copy(two.Data[y*two.Width*3:], p.Data[y*p.Width*3:(y+1)*p.Width*3])
		copy(two.Data[(y*two.Width+p.Width)*3:], q.Data[y*q.Width*3:(y+1)*q.Width*3])
	}
	small := sighting(rand.New(rand.NewSource(2)), p, 1280, 720, 0.12, 0.12, false)
	for name, f := range map[string]vision.Frame{"no face": blank, "two faces": two, "a small face": small} {
		if _, err := ctl.Enrol(context.Background(), f); vision.CauseOf(err) != vision.NoFace {
			t.Errorf("%s: %v, want %s", name, err, vision.NoFace)
		}
	}
	if _, err := ctl.Enrol(context.Background(), vision.Frame{Format: vision.FormatY16, Width: 64, Height: 64, Data: make([]byte, 64*64*2)}); vision.CauseOf(err) != vision.NoFace {
		t.Errorf("a thermal frame: %v, want %s", err, vision.NoFace)
	}
}

// floorFaceFrame bounds a full-HD frame holding maxFaces people whose
// faces are all encoded, on CI's runner (VIS-A30, VIS-A32).
const floorFaceFrame = 800 * time.Millisecond

// TestFloorFaces: a 1920x1080 frame of maxFaces people, each face
// encoded and compared because a template is lent, takes at most
// floorFaceFrame at the 95th percentile (RES-2).
func TestFloorFaces(t *testing.T) {
	dir := realDir(t, "AGENTOS_VISION_FACES")
	names := faceNames(t, dir)
	c, ctl := realFaceService(t, func(id string) bool { return id == "p00" })
	p := frameOf(t, filepath.Join(dir, "images", names[0]), false)
	tpl, err := ctl.Enrol(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctl.Lend(context.Background(), []vision.Template{{ID: "p00", Vec: tpl}}); err != nil {
		t.Fatal(err)
	}
	// Four by two portraits, each scaled into a 480 by 540 cell.
	hd := vision.Frame{Format: vision.FormatRGB24, Width: 1920, Height: 1080, Data: make([]byte, 1920*1080*3)}
	for k := 0; k < maxFaces; k++ {
		q := frameOf(t, filepath.Join(dir, "images", names[1+k]), false)
		ox, oy := 480*(k%4), 540*(k/4)
		for y := 0; y < 480; y++ {
			for x := 0; x < 480; x++ {
				sx, sy := x*q.Width/480, y*q.Height/480
				copy(hd.Data[((oy+30+y)*1920+ox+x)*3:], q.Data[(sy*q.Width+sx)*3:(sy*q.Width+sx)*3+3])
			}
		}
	}
	var times []time.Duration
	faces := 0
	for i := 0; i < 20; i++ {
		t0 := time.Now()
		ds, err := c.Detect(context.Background(), hd)
		if err != nil {
			t.Fatal(err)
		}
		times = append(times, time.Since(t0))
		faces = 0
		for _, d := range ds {
			if d.Face != "" {
				faces++
			}
		}
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	p50, p95 := times[len(times)/2], times[len(times)*95/100]
	t.Logf("face floor: 1920x1080 frame of %d faces, p50 %s p95 %s", faces, p50.Round(time.Millisecond), p95.Round(time.Millisecond))
	if faces != maxFaces {
		t.Errorf("%d faces reported, want %d", faces, maxFaces)
	}
	if p95 > floorFaceFrame {
		t.Errorf("p95 %s over %s", p95, floorFaceFrame)
	}
}
