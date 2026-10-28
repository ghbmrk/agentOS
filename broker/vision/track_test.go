package vision

// REQ: DEV-7, DEV-8

import (
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const frameStep = 200 * time.Millisecond

func fref(i int) FrameRef {
	return FrameRef{At: t0.Add(time.Duration(i) * frameStep), Width: 640, Height: 480, Segment: "seg-1"}
}

// walker is a person's box at frame i, walking right 4 px a frame.
func walker(x0, i int) Box { return Box{X0: x0 + 4*i, Y0: 100, X1: x0 + 4*i + 40, Y1: 200} }

func observe(t *testing.T, tr *Tracker, cam string, i int, ds ...Detection) Update {
	t.Helper()
	u, err := tr.Observe(cam, fref(i), ds)
	if err != nil {
		t.Fatalf("frame %d: %v", i, err)
	}
	return u
}

// A person walking across the frame is one track from its third frame on,
// numbered by the tracker, and ends once unseen for Lost.
func TestTrackerFollowsOneWalker(t *testing.T) {
	tr := NewTracker()
	var ids []uint64
	for i := range 20 {
		u := observe(t, tr, "front", i, Detection{Class: Person, Box: walker(10, i), Conf: 80})
		if i < DefaultConfirm-1 && len(u.Tracks) != 0 {
			t.Fatalf("frame %d: confirmed before %d frames", i, DefaultConfirm)
		}
		for _, s := range u.Tracks {
			ids = append(ids, s.Key.Track)
			if s.Box != walker(10, i) || s.Class != Person || s.Key.Camera != "front" {
				t.Fatalf("frame %d: %+v", i, s)
			}
		}
	}
	if len(ids) != 20-(DefaultConfirm-1) {
		t.Fatalf("%d confirmed frames", len(ids))
	}
	for _, id := range ids {
		if id != 1 {
			t.Fatalf("track ids %v, want all 1", ids)
		}
	}
	if tr.Drops() != 0 {
		t.Fatalf("%d drops on a clean walk", tr.Drops())
	}
	// Unseen for Lost: the track ends.
	u := observe(t, tr, "front", 19+int(DefaultLost/frameStep)+1)
	if len(u.Ended) != 1 || u.Ended[0] != (TrackKey{"front", 1}) {
		t.Fatalf("ended %v", u.Ended)
	}
}

// A detection joins only a track of its own class, and two walkers far
// apart are two tracks.
func TestTrackerKeepsClassesAndWalkersApart(t *testing.T) {
	tr := NewTracker()
	var u Update
	for i := range 5 {
		u = observe(t, tr, "front", i,
			Detection{Class: Person, Box: walker(10, i), Conf: 80},
			Detection{Class: Person, Box: walker(400, i), Conf: 80},
			Detection{Class: Dog, Box: walker(10, i), Conf: 80})
	}
	if len(u.Tracks) != 3 {
		t.Fatalf("tracks %+v, want 3", u.Tracks)
	}
	// A dog where the person was does not carry the person's track on.
	tr = NewTracker()
	for i := range 3 {
		observe(t, tr, "front", i, Detection{Class: Person, Box: walker(10, i), Conf: 80})
	}
	if u := observe(t, tr, "front", 3, Detection{Class: Dog, Box: walker(10, 3), Conf: 80}); len(u.Tracks) != 0 {
		t.Fatalf("a dog joined a person's track: %+v", u.Tracks)
	}
	seen := map[uint64]bool{}
	for _, s := range u.Tracks {
		seen[s.Key.Track] = true
	}
	if len(seen) != 3 {
		t.Fatalf("tracks share a number: %+v", u.Tracks)
	}
}

// A low-confidence detection keeps a confirmed track going (ByteTrack's
// second pass), but never starts one.
func TestTrackerLowConfidence(t *testing.T) {
	tr := NewTracker()
	for i := range 3 {
		observe(t, tr, "front", i, Detection{Class: Person, Box: walker(10, i), Conf: 80})
	}
	u := observe(t, tr, "front", 3, Detection{Class: Person, Box: walker(10, 3), Conf: 20})
	if len(u.Tracks) != 1 || u.Tracks[0].Key.Track != 1 || u.Dropped != 0 {
		t.Fatalf("a low detection on a track: %+v", u)
	}
	tr = NewTracker()
	for i := range 10 {
		if u := observe(t, tr, "front", i, Detection{Class: Person, Box: walker(10, i), Conf: 20}); len(u.Tracks) != 0 || u.Dropped != 1 {
			t.Fatalf("frame %d: low detections started a track: %+v", i, u)
		}
	}
}

// The prediction follows a mover that speeds up: past the first frames a
// 40 px box moves 70 px a frame, beyond the gate around its last box but
// near its predicted one.
func TestTrackerPredictsMotion(t *testing.T) {
	tr := NewTracker()
	x := 10
	for i := range 8 {
		if i > 0 {
			x += 30
			if i > 3 {
				x += 40
			}
		}
		u := observe(t, tr, "front", i, Detection{Class: Person, Box: Box{X0: x, Y0: 100, X1: x + 40, Y1: 140}, Conf: 80})
		if i >= 2 && (len(u.Tracks) != 1 || u.Tracks[0].Key.Track != 1) {
			t.Fatalf("frame %d: lost the mover: %+v", i, u)
		}
	}
}

// The gate grows with time: at the floor rate, a walker moving more than
// its own width a frame stays one track.
func TestTrackerAtTheFloorRate(t *testing.T) {
	tr := NewTracker()
	for i := range 6 {
		f := FrameRef{At: t0.Add(time.Duration(i) * time.Second), Width: 640, Height: 480}
		u, err := tr.Observe("front", f, []Detection{{Class: Person, Box: Box{X0: 10 + 60*i, Y0: 100, X1: 50 + 60*i, Y1: 200}, Conf: 80}})
		if err != nil {
			t.Fatal(err)
		}
		if i >= 2 && (len(u.Tracks) != 1 || u.Tracks[0].Key.Track != 1) {
			t.Fatalf("second %d: lost the walker: %+v", i, u)
		}
	}
	// A box of another size is another thing.
	tr = NewTracker()
	for i := range 6 {
		side := 40
		if i%2 == 1 {
			side = 100
		}
		if u := observe(t, tr, "front", i, Detection{Class: Person, Box: Box{X0: 10, Y0: 10, X1: 10 + side, Y1: 10 + side}, Conf: 80}); len(u.Tracks) != 0 {
			t.Fatalf("frame %d: boxes changing size by 2.5 times made a track", i)
		}
	}
}

// TestInconsistentBoxesDropped (brief, part b): detections that join no
// temporally consistent track are dropped and counted, a sustained drop
// rate marks the service as faulty, and no raw box reaches a planner or
// the bus: the bus's and a planner's types hold no box.
func TestInconsistentBoxesDropped(t *testing.T) {
	var faulty atomic.Int32
	tr := NewTracker()
	tr.Faulty = func() { faulty.Add(1) }
	// A service scattering boxes: each frame's boxes are somewhere new,
	// so no tentative track lives to its third frame.
	scatter := func(i int) []Detection {
		var ds []Detection
		for k := range 4 {
			x := (i*97 + k*151) % 560
			ds = append(ds, Detection{Class: Person, Box: Box{X0: x, Y0: (k * 113) % 380, X1: x + 30, Y1: (k*113)%380 + 60}, Conf: 90})
		}
		return ds
	}
	frames := int(DefaultDropWindow/frameStep) + 1
	confirmed := 0
	for i := range frames {
		u := observe(t, tr, "front", i, scatter(i)...)
		confirmed += len(u.Tracks)
	}
	if confirmed != 0 {
		t.Fatalf("%d confirmed tracks from scattered boxes", confirmed)
	}
	if d := tr.Drops(); d < 4*(frames-2) {
		t.Fatalf("drops %d, want about %d", d, 4*frames)
	}
	if faulty.Load() != 1 {
		t.Fatalf("faulty called %d times after a window of scatter", faulty.Load())
	}
	// A clean window after it is not faulty.
	for i := frames; i < 2*frames; i++ {
		observe(t, tr, "front", i, Detection{Class: Person, Box: walker(10, i%100), Conf: 80})
	}
	if faulty.Load() != 1 {
		t.Fatalf("faulty called %d times, a clean window included", faulty.Load())
	}
	// Under DropMin detections, a window is never faulty.
	tr2 := NewTracker()
	tr2.Faulty = func() { faulty.Add(10) }
	for i := range frames {
		if i%20 == 0 {
			observe(t, tr2, "front", i, scatter(i)...)
		} else {
			observe(t, tr2, "front", i)
		}
	}
	if faulty.Load() != 1 {
		t.Fatal("a quiet window of scatter marked the service faulty")
	}
	for _, v := range []any{ZoneEvent{}, Count{}, PlateEvent{}, SoundEvent{}} {
		if f, ok := boxField(reflect.TypeOf(v)); ok {
			t.Fatalf("%T.%s can carry a box to the bus or a planner", v, f)
		}
	}
}

// A tentative track of a scattering service that happens to hit three
// frames in a row is confirmed; the drop rule is about the rate, not one
// lucky track, and the tentative track's earlier hits are not drops.
func TestTentativeHitsCountOnlyWhenTheyDie(t *testing.T) {
	tr := NewTracker()
	observe(t, tr, "front", 0, Detection{Class: Person, Box: walker(10, 0), Conf: 80})
	u := observe(t, tr, "front", 1, Detection{Class: Person, Box: walker(10, 1), Conf: 80})
	if u.Dropped != 0 {
		t.Fatalf("dropped %d while tentative", u.Dropped)
	}
	u = observe(t, tr, "front", 2)
	if u.Dropped != 2 {
		t.Fatalf("a dead tentative track dropped %d, want its 2 hits", u.Dropped)
	}
}

// One camera's tracks are bounded: past MaxTracks, a new detection is
// dropped rather than starting a track.
func TestTrackerBoundsTracks(t *testing.T) {
	tr := NewTracker()
	observe(t, tr, "front", 0)
	c := &camTracks{}
	for range MaxTracks {
		c.tracks = append(c.tracks, &track{class: Cat, box: Box{X0: 0, Y0: 0, X1: 1, Y1: 1}, at: t0, id: 1})
	}
	tr.cams["full"] = c
	u, _ := tr.Observe("full", FrameRef{At: t0, Width: 640, Height: 480}, []Detection{{Class: Person, Box: Box{X0: 100, Y0: 100, X1: 140, Y1: 200}, Conf: 90}})
	if u.Dropped != 1 {
		t.Fatalf("a detection past MaxTracks: %+v", u)
	}
}

// The tracker checks detections against the frame itself, refuses a
// camera id outside its alphabet, and refuses a frame older than the
// camera's last.
func TestTrackerChecksItsInput(t *testing.T) {
	tr := NewTracker()
	f := FrameRef{At: t0, Width: 64, Height: 48}
	for _, ds := range [][]Detection{
		{{Class: Person, Box: Box{X0: 0, Y0: 0, X1: 65, Y1: 10}, Conf: 50}},
		{{Class: "man", Box: Box{X0: 0, Y0: 0, X1: 6, Y1: 10}, Conf: 50}},
		{{Class: Person, Box: Box{X0: 0, Y0: 0, X1: 6, Y1: 10}, Conf: 0}},
	} {
		if _, err := tr.Observe("front", f, ds); err == nil {
			t.Fatalf("%+v accepted", ds)
		}
	}
	if _, err := tr.Observe("Front Door", f, nil); err == nil {
		t.Fatal("a camera id outside the alphabet")
	}
	if _, err := tr.Observe("front", FrameRef{At: t0, Width: 0, Height: 48}, nil); err == nil {
		t.Fatal("a frame without a size")
	}
	if _, err := tr.Observe("front", f, nil); err != nil {
		t.Fatal(err)
	}
	f.At = t0.Add(-time.Second)
	if _, err := tr.Observe("front", f, nil); err != ErrFrameOrder {
		t.Fatalf("an older frame: %v", err)
	}
}

// Part (d)'s carry-over: each vehicle detection on a track goes to
// Plates.Read under the tracker's own number, and the track's end to
// Plates.End, so a plate is reported once per track.
func TestTrackerFeedsPlatesOncePerTrack(t *testing.T) {
	tr := NewTracker()
	tr.Plates = NewPlates()
	tr.Plates.Now = func() time.Time { return t0 }
	car := func(i int) Box { return Box{X0: 100 + 2*i, Y0: 300, X1: 260 + 2*i, Y1: 400} }
	var got []PlateEvent
	for i := range 12 {
		u := observe(t, tr, "drive", i, Detection{Class: Vehicle, Box: car(i), Conf: 90, Plate: "ABC 1234"})
		got = append(got, u.Plates...)
	}
	if len(got) != 1 || got[0].Track != 1 || got[0].Camera != "drive" || got[0].Plate != `"ABC 1234"` {
		t.Fatalf("plate events %+v", got)
	}
	// The track ends and a new car with the same plate is a new track,
	// which reports again.
	last := 11 + int(DefaultLost/frameStep) + 1
	u := observe(t, tr, "drive", last)
	if len(u.Ended) != 1 {
		t.Fatalf("ended %v", u.Ended)
	}
	tr.Plates.mu.Lock()
	_, held := tr.Plates.tracks[TrackKey{"drive", 1}]
	tr.Plates.mu.Unlock()
	if held {
		t.Fatal("Plates still holds the ended track")
	}
	got = nil
	for i := last + 1; i < last+10; i++ {
		got = append(got, observe(t, tr, "drive", i, Detection{Class: Vehicle, Box: car(i - last), Conf: 90, Plate: "ABC 1234"}).Plates...)
	}
	if len(got) != 1 || got[0].Track != 2 {
		t.Fatalf("second car's plate events %+v", got)
	}
	// Plates on a tentative track are not read: a scattering service gets
	// no plate out.
	tr = NewTracker()
	tr.Plates = NewPlates()
	for i := range 40 {
		x := (i * 211) % 400
		if u := observe(t, tr, "drive", i, Detection{Class: Vehicle, Box: Box{X0: x, Y0: 0, X1: x + 50, Y1: 50}, Conf: 90, Plate: "ZZZ 999"}); len(u.Plates) != 0 {
			t.Fatalf("a plate from an unconfirmed track: %+v", u.Plates)
		}
	}
}

// Brief point 4 (VIS-A18): a visit by someone not enrolled leaves one
// evidence reference when it ends, its clearest frame; a visit with an
// enrolled face, or with no face, leaves none.
func TestEvidenceForUnknownVisitsOnly(t *testing.T) {
	tr := NewTracker()
	var ev []Evidence
	for i := range 10 {
		b := walker(10, i)
		conf := 60
		if i == 6 {
			conf = 95 // the clearest frame
		}
		u, err := tr.Observe("front", FrameRef{At: fref(i).At, Width: 640, Height: 480, Segment: "seg-" + string(rune('a'+i))}, []Detection{
			{Class: Person, Box: b, Conf: conf, Face: FaceUnknown},
			{Class: Person, Box: walker(400, i), Conf: 80, Face: "enrolled:alice"},
			{Class: Person, Box: Box{X0: 10, Y0: 300, X1: 50, Y1: 400}, Conf: 80},
		})
		if err != nil {
			t.Fatal(err)
		}
		ev = append(ev, u.Evidence...)
	}
	u := tr.Expire(fref(9).At.Add(DefaultLost + time.Millisecond))
	ev = append(ev, u.Evidence...)
	if len(u.Ended) != 3 {
		t.Fatalf("ended %v", u.Ended)
	}
	if len(ev) != 1 {
		t.Fatalf("evidence %+v, want the unknown visit's only", ev)
	}
	e := ev[0]
	if e.Camera != "front" || e.Track == 0 || e.Segment != "seg-g" || e.Conf != 95 || e.Box != walker(10, 6) || !e.At.Equal(fref(6).At) {
		t.Fatalf("evidence %+v, want frame 6's", e)
	}
	// A track that is enrolled in any frame is a household visit: none.
	tr = NewTracker()
	for i := range 6 {
		face := FaceUnknown
		if i == 4 {
			face = "enrolled:alice"
		}
		observe(t, tr, "front", i, Detection{Class: Person, Box: walker(10, i), Conf: 80, Face: face})
	}
	if u := tr.Expire(fref(5).At.Add(time.Hour)); len(u.Evidence) != 0 {
		t.Fatalf("evidence for an enrolled visit: %+v", u.Evidence)
	}
}

// boxField names a field of t, at any depth, that is a Box or has Box in
// its name.
func boxField(t reflect.Type) (string, bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Type == reflect.TypeOf(Box{}) || strings.Contains(f.Name, "Box") {
			return f.Name, true
		}
		if f.Type.Kind() == reflect.Struct {
			if n, ok := boxField(f.Type); ok {
				return f.Name + "." + n, true
			}
		}
	}
	return "", false
}
