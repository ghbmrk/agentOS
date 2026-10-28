package vision

// REQ: DEV-7, DEV-8, NET-2

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// downCam looks straight down from 10 m over the origin with a 640x480
// image at 320 px focal length: pixel (u, v) is the ground point
// ((u-320)/32, (240-v)/32) metres.
var downCam = Pose{X: 0, Y: 0, Z: 10, Yaw: 0, Pitch: 90, FX: 320, FY: 320, CX: 320, CY: 240}

// sideCam is another camera over the same ground, 1 m east, turned.
var sideCam = Pose{X: 1, Y: 0, Z: 10, Yaw: 90, Pitch: 90, FX: 320, FY: 320, CX: 320, CY: 240}

// pixel is where ground point (x, y) shows on downCam.
func pixel(x, y float64) (int, int) { return int(math.Round(320 + 32*x)), int(math.Round(240 - 32*y)) }

// footBox is a box standing at ground point (x, y) on downCam: its
// bottom edge's middle is there.
func footBox(x, y float64) Box {
	u, v := pixel(x, y)
	return Box{X0: u - 10, Y0: v - 40, X1: u + 10, Y1: v}
}

func newSite(t *testing.T, zones ...Zone) *Site {
	t.Helper()
	s, err := NewSite(41.0, -73.9, map[string]Pose{"down": downCam, "side": sideCam}, zones)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var porch = Zone{ID: "porch", Ground: [][2]float64{{0, 0}, {4, 0}, {4, 4}, {0, 4}}}

func state(cam string, id uint64, class Class, b Box, at time.Time) TrackState {
	return TrackState{Key: TrackKey{cam, id}, Class: class, Box: b, At: at}
}

// The pose model: a camera looking straight down maps its centre below it
// and the image's top to the north; one looking north and 45 degrees down
// from 3 m sees its centre 3 m north; a ray above the horizon meets no
// ground.
func TestPosePlacesOnTheGround(t *testing.T) {
	g, ok := downCam.at(320, 240, 0)
	if !ok || math.Abs(g[0]) > 1e-9 || math.Abs(g[1]) > 1e-9 {
		t.Fatalf("centre at %v", g)
	}
	if g, _ := downCam.at(320, 208, 0); math.Abs(g[1]-1) > 1e-9 || math.Abs(g[0]) > 1e-9 {
		t.Fatalf("32 px up at %v, want 1 m north", g)
	}
	if g, _ := downCam.at(352, 240, 0); math.Abs(g[0]-1) > 1e-9 {
		t.Fatalf("32 px right at %v, want 1 m east", g)
	}
	tilt := Pose{Z: 3, Pitch: 45, FX: 500, FY: 500, CX: 320, CY: 240}
	if g, ok := tilt.at(320, 240, 0); !ok || math.Abs(g[0]) > 1e-9 || math.Abs(g[1]-3) > 1e-9 {
		t.Fatalf("tilted centre at %v", g)
	}
	east := tilt
	east.Yaw = 90
	if g, _ := east.at(320, 240, 0); math.Abs(g[0]-3) > 1e-9 || math.Abs(g[1]) > 1e-9 {
		t.Fatalf("east-facing centre at %v", g)
	}
	rolled := downCam
	rolled.Roll = 90
	if g, _ := rolled.at(352, 240, 0); math.Abs(g[1]+1) > 1e-9 && math.Abs(g[1]-1) > 1e-9 {
		t.Fatalf("rolled 90 degrees, 32 px right at %v, want 1 m north or south", g)
	}
	if _, ok := (Pose{Z: 3, Pitch: 10, FX: 500, FY: 500, CX: 320, CY: 240}).at(320, 0, 0); ok {
		t.Fatal("a ray above the horizon met the ground")
	}
	level := Pose{Z: 3, Pitch: 0.5, FX: 500, FY: 500, CX: 320, CY: 240}
	if _, ok := level.at(320, 240, 0); ok {
		t.Fatal("a point past MaxRange was placed")
	}
	// The drone's plane: from 10 m up, the centre meets 4 m up 6 m down
	// the ray, so a 45-degree camera at 10 m sees it 6 m out.
	high := Pose{Z: 10, Pitch: 45, FX: 500, FY: 500, CX: 320, CY: 240}
	if g, ok := high.at(320, 240, 4); !ok || math.Abs(g[1]-6) > 1e-9 {
		t.Fatalf("centre at 4 m up: %v", g)
	}
}

// NewSite refuses poses and zones outside their bounds: owner data, but
// still checked.
func TestNewSiteChecksOwnerData(t *testing.T) {
	bad := []Pose{
		{Z: 0, Pitch: 90, FX: 1, FY: 1},
		{Z: 3, Pitch: 90, FX: 0, FY: 1},
		{Z: 3, Pitch: math.NaN(), FX: 1, FY: 1},
		{Z: 3, Pitch: -90, FX: 1, FY: 1},
		{Z: 3, Pitch: 45, FX: 1, FY: 1, CX: MaxWidth + 1},
		{Z: 3, Pitch: 45, FX: 1, FY: 1, X: math.Inf(1)},
	}
	for _, p := range bad {
		if _, err := NewSite(41, -73, map[string]Pose{"cam": p}, nil); err == nil {
			t.Errorf("pose %+v accepted", p)
		}
	}
	if _, err := NewSite(41, -73, map[string]Pose{"Front Door": downCam}, nil); err == nil {
		t.Error("a camera id outside the alphabet")
	}
	if _, err := NewSite(math.NaN(), -73, nil, nil); err == nil {
		t.Error("a NaN origin")
	}
	for _, zs := range [][]Zone{
		{{ID: "a", Ground: [][2]float64{{0, 0}, {1, 0}}}},
		{porch, porch},
		{{ID: "the porch", Ground: porch.Ground}},
		{{ID: "a", Ground: [][2]float64{{0, 0}, {1, math.NaN()}, {1, 1}}}},
	} {
		if _, err := NewSite(41, -73, nil, zs); err == nil {
			t.Errorf("zones %+v accepted", zs)
		}
	}
}

// TestDistinctCountWithoutIdentity (brief, part b): a count of distinct
// people comes from tracks, and the counting path has no access to faces.
// One person seen by two cameras at one spot is one; two people side by
// side are two, whatever faces the service named for them.
func TestDistinctCountWithoutIdentity(t *testing.T) {
	for _, ty := range []reflect.Type{reflect.TypeOf(TrackState{}), reflect.TypeOf(object{}), reflect.TypeOf(Site{}), reflect.TypeOf(Count{}), reflect.TypeOf(ZoneEvent{})} {
		for i := range ty.NumField() {
			if n := strings.ToLower(ty.Field(i).Name); strings.Contains(n, "face") || strings.Contains(n, "enrol") || strings.Contains(n, "templat") {
				t.Fatalf("%s.%s: the counting path can see a face", ty.Name(), ty.Field(i).Name)
			}
		}
	}
	// End to end through the tracker: two people walking side by side,
	// both named the same enrolled person by a lying service, on the
	// down camera; the side camera sees the first of them too.
	tr := NewTracker()
	s := newSite(t, porch)
	var all []ZoneEvent
	for i := range 6 {
		at := fref(i)
		for _, cam := range []string{"down", "side"} {
			ds := []Detection{{Class: Person, Box: footBox(1, 1+0.1*float64(i)), Conf: 90, Face: "enrolled:alice"}}
			if cam == "down" {
				ds = append(ds, Detection{Class: Person, Box: footBox(3, 1+0.1*float64(i)), Conf: 90, Face: "enrolled:alice"})
			} else {
				// The side camera's view of the first person: the
				// same ground point through its own pose.
				ds[0].Box = sideBox(t, 1, 1+0.1*float64(i))
			}
			u, err := tr.Observe(cam, at, ds)
			if err != nil {
				t.Fatal(err)
			}
			all = append(all, s.Apply(u)...)
		}
	}
	c, err := s.Answer(Ask{Op: "count", Zone: "porch", Class: Person}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if c.N != 2 {
		t.Fatalf("count %d, want 2 people", c.N)
	}
	if c, _ := s.Answer(Ask{Op: "count", Camera: "side"}, t0); c.N != 1 {
		t.Fatalf("count on the side camera %d, want 1", c.N)
	}
	enters := 0
	for _, e := range all {
		if e.Kind == ZoneEnter {
			enters++
		}
	}
	if enters != 2 {
		t.Fatalf("enter events %+v, want 2", all)
	}
}

// sideBox is a box standing at ground point (x, y) as sideCam sees it.
func sideBox(t *testing.T, x, y float64) Box {
	t.Helper()
	// sideCam looks down with its image's top to the east: pixel (u, v)
	// is ground (1 + (240-v)/32, -(u-320)/32).
	u := int(math.Round(320 - 32*y))
	v := int(math.Round(240 - 32*(x-1)))
	b := Box{X0: u - 10, Y0: v - 40, X1: u + 10, Y1: v}
	if g, ok := sideCam.at(float64(b.X0+b.X1)/2, float64(b.Y1), 0); !ok || math.Hypot(g[0]-x, g[1]-y) > 0.05 {
		t.Fatalf("side camera's box for (%v, %v) stands at %v", x, y, g)
	}
	return b
}

// Fusion joins tracks on different cameras within FuseRadius only, of one
// class only, and never two tracks of one camera.
func TestFusionRules(t *testing.T) {
	s := newSite(t)
	s.Apply(Update{Camera: "down", Tracks: []TrackState{state("down", 1, Person, footBox(1, 1), t0), state("down", 2, Person, footBox(1.5, 1), t0)}})
	if len(s.objects) != 2 {
		t.Fatalf("two tracks on one camera fused: %d objects", len(s.objects))
	}
	s.Apply(Update{Camera: "side", Tracks: []TrackState{state("side", 1, Dog, sideBox(t, 1, 1), t0)}})
	if len(s.objects) != 3 {
		t.Fatal("a dog fused with a person")
	}
	s.Apply(Update{Camera: "side", Tracks: []TrackState{state("side", 2, Person, sideBox(t, 1, 3), t0)}})
	if len(s.objects) != 4 {
		t.Fatal("tracks 2 m apart fused")
	}
	s.Apply(Update{Camera: "side", Tracks: []TrackState{state("side", 3, Person, sideBox(t, 1.1, 1), t0)}})
	if len(s.objects) != 4 {
		t.Fatal("tracks 0.1 m apart on two cameras did not fuse")
	}
	// An object goes when its last track ends.
	s.Apply(Update{Ended: []TrackKey{{"down", 1}}})
	if len(s.objects) != 4 {
		t.Fatal("an object went with one of its two tracks")
	}
	s.Apply(Update{Ended: []TrackKey{{"side", 3}}})
	if len(s.objects) != 3 {
		t.Fatal("an object outlived its tracks")
	}
	// A stale object is not fused with.
	s.Apply(Update{Camera: "side", Tracks: []TrackState{state("side", 4, Person, sideBox(t, 1.5, 1), t0.Add(fuseAge+time.Second))}})
	if len(s.objects) != 4 {
		t.Fatal("fused with an object not seen for longer than fuseAge")
	}
}

// Zone events: an object entering a zone gives an enter event, one
// standing in it for Dwell a dwell event, once per stay; leaving and
// coming back enters again.
func TestZoneEnterAndDwell(t *testing.T) {
	s := newSite(t, porch)
	step := func(at time.Time, x, y float64) []ZoneEvent {
		return s.Apply(Update{Camera: "down", Tracks: []TrackState{state("down", 1, Person, footBox(x, y), at)}})
	}
	if es := step(t0, -2, 2); len(es) != 0 {
		t.Fatalf("outside the zone: %+v", es)
	}
	es := step(t0.Add(time.Second), 2, 2)
	if len(es) != 1 || es[0].Kind != ZoneEnter || es[0].Zone != "porch" || es[0].Class != Person || es[0].Count != 1 || es[0].Object == 0 {
		t.Fatalf("enter %+v", es)
	}
	if es := step(t0.Add(30*time.Second), 2, 2); len(es) != 0 {
		t.Fatalf("before Dwell: %+v", es)
	}
	es = step(t0.Add(61*time.Second), 2, 2)
	if len(es) != 1 || es[0].Kind != ZoneDwell {
		t.Fatalf("dwell %+v", es)
	}
	if es := step(t0.Add(200*time.Second), 2, 2); len(es) != 0 {
		t.Fatalf("a second dwell in one stay: %+v", es)
	}
	if z, ok := s.ZoneOf(es0Object(t, s)); !ok || z != "porch" {
		t.Fatalf("ZoneOf %q %v", z, ok)
	}
	step(t0.Add(201*time.Second), -2, 2)
	if _, ok := s.ZoneOf(es0Object(t, s)); ok {
		t.Fatal("ZoneOf after leaving")
	}
	if es := step(t0.Add(202*time.Second), 2, 2); len(es) != 1 || es[0].Kind != ZoneEnter {
		t.Fatalf("coming back: %+v", es)
	}
	// A camera with no pose places nothing, so it gives no zone events.
	if es := s.Apply(Update{Camera: "attic", Tracks: []TrackState{state("attic", 1, Person, footBox(2, 2), t0)}}); len(es) != 0 {
		t.Fatalf("an unposed camera: %+v", es)
	}
}

func es0Object(t *testing.T, s *Site) uint64 {
	t.Helper()
	id, ok := s.links[TrackKey{"down", 1}]
	if !ok {
		t.Fatal("no object")
	}
	return id
}

// TestZoneEventsRateLimited (DEV-8): each zone's repeat events are capped
// at PerMinute a minute, the excess coalesced and counted on the class's
// next event; a class's first event in a minute always passes, so a
// stream of deer cannot starve a person's entry; and in any minute a zone
// gives at most PerMinute plus one per class.
func TestZoneEventsRateLimited(t *testing.T) {
	s := newSite(t, porch)
	var got []ZoneEvent
	// A flood: a new deer track walks into the porch every second for
	// two minutes, as a lying service could make.
	for i := range 120 {
		at := t0.Add(time.Duration(i) * time.Second)
		id := uint64(i + 1)
		s.Apply(Update{Camera: "down", Tracks: []TrackState{state("down", id, Deer, footBox(-1, 2), at)}})
		got = append(got, s.Apply(Update{Camera: "down", Tracks: []TrackState{state("down", id, Deer, footBox(2, 2), at)}, Ended: []TrackKey{{"down", id - 1}}})...)
		if i == 30 {
			es := s.Apply(Update{Camera: "down", Tracks: []TrackState{state("down", 1000, Person, footBox(1, 1), at)}})
			if len(es) != 1 || es[0].Class != Person {
				t.Fatalf("a person's entry in a deer flood: %+v", es)
			}
			got = append(got, es...)
		}
	}
	for i := range got {
		at := got[i].At
		n := 0
		for _, e := range got {
			if e.At >= at && e.At < at+60 {
				n++
			}
		}
		if n > DefaultZoneEventsPerMinute+len(classes)-1 { // the drone is never zoned
			t.Fatalf("%d events in a minute from %d", n, at)
		}
	}
	deer, coalesced := 0, 0
	for _, e := range got {
		if e.Class == Deer {
			deer++
			coalesced += e.Coalesced
		}
	}
	if deer > 2*DefaultZoneEventsPerMinute+2 || deer < 2*(DefaultZoneEventsPerMinute-1) {
		t.Fatalf("%d deer events in two minutes", deer)
	}
	if coalesced == 0 || deer+coalesced+s.rates["porch"].coalesced[Deer] != 120 {
		t.Fatalf("deer: %d events carrying %d coalesced, %d held, want 120 in all", deer, coalesced, s.rates["porch"].coalesced[Deer])
	}
}

// The edge of the minute: a class's repeat at 59 s is held while the zone
// is full, and passes at 60 s.
func TestZoneRateWindowEdge(t *testing.T) {
	s := newSite(t)
	s.PerMinute = 1
	if _, ok := s.pass("porch", Deer, t0); !ok {
		t.Fatal("first event held")
	}
	if _, ok := s.pass("porch", Person, t0.Add(30*time.Second)); !ok {
		t.Fatal("a person's first event held")
	}
	if _, ok := s.pass("porch", Deer, t0.Add(59*time.Second)); ok {
		t.Fatal("a repeat at 59 s passed a full zone")
	}
	e, ok := s.pass("porch", Deer, t0.Add(60*time.Second))
	if !ok || e.Coalesced != 1 {
		t.Fatalf("at 60 s, with the zone still full: %+v %v", e, ok)
	}
}

// A planner's asks: "count" is the only op, it needs a camera or a zone,
// its answer type could carry nothing but ids and a number, and past
// AsksPerMinute a minute it is ErrBusy.
func TestPlannerCountAsks(t *testing.T) {
	s := newSite(t, porch)
	if _, err := s.Answer(Ask{Op: "count"}, t0); !errors.Is(err, ErrNotOffered) {
		t.Fatalf("a count of nothing: %v", err)
	}
	if _, err := s.Answer(Ask{Op: "find", Zone: "porch"}, t0); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("a find: %v", err)
	}
	for i := range DefaultAsksPerMinute {
		if _, err := s.Answer(Ask{Op: "count", Zone: "porch"}, t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("ask %d: %v", i, err)
		}
	}
	if _, err := s.Answer(Ask{Op: "count", Zone: "porch"}, t0.Add(59*time.Second)); !errors.Is(err, ErrBusy) {
		t.Fatalf("ask past the limit: %v", err)
	}
	if _, err := s.Answer(Ask{Op: "count", Zone: "porch"}, t0.Add(61*time.Second)); err != nil {
		t.Fatalf("a minute on: %v", err)
	}
	ty := reflect.TypeOf(Count{})
	for i := range ty.NumField() {
		if k := ty.Field(i).Type.Kind(); k != reflect.String && k != reflect.Int {
			t.Fatalf("Count.%s is a %s", ty.Field(i).Name, k)
		}
	}
}

// TestDroneOutputsAreDisplayAndFixesOnly (NET-2 Drones): the drone's
// outputs are a zone name for the owner's tap and a fix that is a position
// only; no output type carries a waypoint, route, heading, speed or
// command, and nothing a planner gets reaches either. A fix comes only
// from cameras that each see exactly one drone, and a drone is never
// fused, zoned or counted.
func TestDroneOutputsAreDisplayAndFixesOnly(t *testing.T) {
	ty := reflect.TypeOf(Fix{})
	if ty.NumField() != 2 || ty.Field(0).Name != "Lat" || ty.Field(1).Name != "Lon" {
		t.Fatalf("Fix has fields beyond a position: %v", ty)
	}
	steer := []string{"waypoint", "route", "goto", "target", "heading", "speed", "command", "mission", "alt", "follow"}
	for _, v := range []any{Fix{}, ZoneEvent{}, Count{}, PlateEvent{}, SoundEvent{}, Evidence{}, TrackState{}, Update{}} {
		ty := reflect.TypeOf(v)
		for i := range ty.NumField() {
			n := strings.ToLower(ty.Field(i).Name)
			for _, w := range steer {
				if strings.Contains(n, w) {
					t.Fatalf("%s.%s could steer a flight", ty.Name(), ty.Field(i).Name)
				}
			}
		}
	}
	for _, ty := range []reflect.Type{reflect.TypeOf(&Site{}), reflect.TypeOf(&Tracker{})} {
		for i := range ty.NumMethod() {
			n := strings.ToLower(ty.Method(i).Name)
			for _, w := range steer {
				if strings.Contains(n, w) {
					t.Fatalf("%s.%s could steer a flight", ty, ty.Method(i).Name)
				}
			}
		}
	}
	for _, op := range PlannerOps {
		if strings.Contains(op, "drone") || strings.Contains(op, "fix") || strings.Contains(op, "fly") {
			t.Fatalf("planner op %q reaches the drone", op)
		}
	}

	s := newSite(t, porch)
	// The drone 4 m up over (2, 2): on the down camera from 10 m, the
	// ray through (2, 2) on the ground meets 4 m up at (1.2, 1.2).
	u, v := pixel(2, 2)
	box := Box{X0: u - 5, Y0: v - 5, X1: u + 5, Y1: v + 5}
	es := s.Apply(Update{Camera: "down", Tracks: []TrackState{state("down", 1, Drone, box, t0)}})
	if len(es) != 0 || len(s.objects) != 0 {
		t.Fatalf("a drone was zoned or counted: %+v", es)
	}
	f, ok := s.DroneFix(t0.Add(500*time.Millisecond), 4)
	if !ok {
		t.Fatal("no fix")
	}
	want := s.degrees(1.2, 1.2)
	if math.Abs(f.Lat-want.Lat) > 2e-6 || math.Abs(f.Lon-want.Lon) > 2e-6 {
		t.Fatalf("fix %+v, want %+v", f, want)
	}
	if f.Lat != math.Round(f.Lat*1e6)/1e6 {
		t.Fatalf("fix %v not to six places", f.Lat)
	}
	if _, ok := s.DroneFix(t0.Add(2*time.Second), 4); ok {
		t.Fatal("a fix from a stale sighting")
	}
	if _, ok := s.DroneFix(t0, -1); ok {
		t.Fatal("a fix below the ground")
	}
	// Two drones on one camera: that camera gives nothing.
	s.Apply(Update{Camera: "down", Tracks: []TrackState{state("down", 2, Drone, Box{X0: 10, Y0: 10, X1: 20, Y1: 20}, t0)}})
	if _, ok := s.DroneFix(t0, 4); ok {
		t.Fatal("a fix from a camera seeing two drones")
	}
	s.Apply(Update{Ended: []TrackKey{{"down", 2}}})
	if _, ok := s.DroneFix(t0, 4); !ok {
		t.Fatal("no fix once the second drone track ended")
	}
	// The fix is in degrees about the origin: 111.32 km a degree north.
	if f := s.degrees(0, 111.32); math.Abs(f.Lat-41.001) > 1e-9 || f.Lon != -73.9 {
		t.Fatalf("111.32 m north is %+v", f)
	}
}
