package vision

import (
	"errors"
	"math"
	"slices"
	"sync"
	"time"
)

// The site (part b, VIS-track; brief points 5 and 6, DEV-8, NET-2 Drones,
// VIS-A23 to A25). Each camera's confirmed tracks are placed on one ground
// plane through the camera's pose, which the owner sets once (owner data
// in the sealed store, never in git), and tracks of one class that stand
// within FuseRadius of each other on different cameras are fused into one
// object. Zone entries and dwell go to the bus as ZoneEvents, rate-limited
// per zone with the excess coalesced and counted. A planner gets counts
// only, through Answer. Distinct people are counted as objects, which come
// from tracks alone: no face reaches the site.
//
// The drone's outputs are display data and fixes only: ZoneOf names the
// zone an object stands in, for the owner's per-flight tap, and DroneFix is
// where the cameras see the drone, for the GPS cross-check. Nothing here
// steers a flight; the only drone message the core sends is return to dock.

// Site defaults and bounds.
const (
	// DefaultFuseRadius is the ground distance, in metres, within which
	// tracks of one class on different cameras are one object.
	DefaultFuseRadius = 1.5
	// DefaultDwell is how long an object stays in a zone before its
	// dwell event.
	DefaultDwell = time.Minute
	// DefaultZoneEventsPerMinute bounds one zone's repeat events a
	// minute.
	DefaultZoneEventsPerMinute = 6
	// DefaultAsksPerMinute bounds a planner's asks of the site a minute.
	DefaultAsksPerMinute = 12
	// MaxCount caps every count and coalesced count leaving the site: a
	// number at the cap means that many or more. Uncapped, each is a
	// number a hostile service chooses by how many tracks it fakes.
	MaxCount = 10
	// MaxRange is the farthest ground point, in metres from its camera,
	// a track is placed at; past it a ray is too near the horizon to
	// place anything.
	MaxRange = 300.0
	// MaxZones and MaxZoneVertices bound the owner's zones.
	MaxZones        = 64
	MaxZoneVertices = 64
	// fuseAge is how recently an object must have been seen for a track
	// on another camera to fuse with it.
	fuseAge = 2 * time.Second
	// fixAge is how recently a camera must have seen the drone for its
	// fix to count.
	fixAge = time.Second
)

// Zone event kinds.
const (
	ZoneEnter = "enter"
	ZoneDwell = "dwell"
)

// Pose places one camera: its position in metres (X east, Y north, Z up
// from the ground plane at the site's origin), where it points (Yaw, the
// compass bearing of its axis in degrees clockwise from north; Pitch,
// degrees below the horizontal; Roll, degrees clockwise about its axis as
// seen from behind), and its lens in pixels (FX, FY focal lengths; CX, CY
// the image centre).
type Pose struct {
	X, Y, Z          float64
	Yaw, Pitch, Roll float64
	FX, FY, CX, CY   float64
}

// Zone is one of the owner's named areas on the ground plane: a polygon
// of points (X east, Y north) in metres.
type Zone struct {
	ID     string
	Ground [][2]float64
}

// ZoneEvent is one object entering, or dwelling in, a zone, as the bus
// carries it (DEV-8): no box, frame or face, only the zone, the kind, the
// class, the client's own object number and the class's count in the zone.
// Coalesced counts that zone's events of the class the rate limit dropped
// since its last one. Count and Coalesced are capped at MaxCount. At is
// unix seconds.
type ZoneEvent struct {
	Zone      string
	Kind      string
	Class     Class
	Object    uint64
	Count     int
	Coalesced int
	At        int64
}

// Count is the answer to a planner's "count" ask: how many objects of the
// class (every class but the drone when empty) stand in the zone, and are
// seen by the camera if one is named, now, capped at MaxCount. A count
// names a zone, so the objects it counts entered the zone, and each entry
// was a zone event the owner can see.
type Count struct {
	Camera string
	Zone   string
	Class  Class
	N      int
}

// Fix is where the cameras see the drone, in decimal degrees to six
// places: a measured position the drone's own GPS is checked against,
// never a place to fly to.
type Fix struct {
	Lat, Lon float64
}

// ErrBusy is Answer's refusal past the planner's asks a minute.
var ErrBusy = errors.New("vision: asked too often; ask again in a minute")

// Site holds the ground plane's objects. The zero value is not ready; use
// NewSite.
type Site struct {
	// FuseRadius, Dwell, PerMinute and AsksPerMinute are the rule.
	FuseRadius    float64
	Dwell         time.Duration
	PerMinute     int
	AsksPerMinute int

	lat0, lon0 float64
	poses      map[string]Pose
	zones      []Zone

	mu      sync.Mutex
	next    uint64
	objects map[uint64]*object
	links   map[TrackKey]uint64
	drone   map[TrackKey]TrackState
	rates   map[string]*zoneRate
	asks    []time.Time
}

type object struct {
	class  Class
	tracks map[TrackKey]bool
	pos    [2]float64
	placed bool
	at     time.Time
	since  map[string]time.Time // zone it stands in, since when
	dwelt  map[string]bool
}

type zoneRate struct {
	sent      []time.Time
	last      map[Class]time.Time
	coalesced map[Class]int
}

// NewSite checks the owner's origin (decimal degrees), camera poses and
// zones, and returns a Site with the default rule.
func NewSite(lat, lon float64, poses map[string]Pose, zones []Zone) (*Site, error) {
	if !finite(lat, lon) || math.Abs(lat) > 89 || math.Abs(lon) > 180 {
		return nil, badRequest("site origin outside its range")
	}
	for id, p := range poses {
		if !ValidEnrolledID(id) || !p.valid() {
			return nil, badRequest("camera pose outside its bounds")
		}
	}
	if len(zones) > MaxZones {
		return nil, badRequest("too many zones")
	}
	seen := map[string]bool{}
	for _, z := range zones {
		if !ValidEnrolledID(z.ID) || seen[z.ID] || len(z.Ground) < 3 || len(z.Ground) > MaxZoneVertices {
			return nil, badRequest("zone outside its bounds")
		}
		seen[z.ID] = true
		for _, p := range z.Ground {
			if !finite(p[0], p[1]) || math.Abs(p[0]) > 10*MaxRange || math.Abs(p[1]) > 10*MaxRange {
				return nil, badRequest("zone outside its bounds")
			}
		}
	}
	s := &Site{
		FuseRadius: DefaultFuseRadius, Dwell: DefaultDwell,
		PerMinute: DefaultZoneEventsPerMinute, AsksPerMinute: DefaultAsksPerMinute,
		lat0: lat, lon0: lon, poses: map[string]Pose{},
		objects: map[uint64]*object{}, links: map[TrackKey]uint64{},
		drone: map[TrackKey]TrackState{}, rates: map[string]*zoneRate{},
	}
	for id, p := range poses {
		s.poses[id] = p
	}
	for _, z := range zones {
		s.zones = append(s.zones, Zone{ID: z.ID, Ground: slices.Clone(z.Ground)})
	}
	return s, nil
}

func (p Pose) valid() bool {
	return finite(p.X, p.Y, p.Z, p.Yaw, p.Pitch, p.Roll, p.FX, p.FY, p.CX, p.CY) &&
		math.Abs(p.X) <= 10*MaxRange && math.Abs(p.Y) <= 10*MaxRange && p.Z > 0 && p.Z <= 100 &&
		p.Pitch > -90 && p.Pitch <= 90 && math.Abs(p.Yaw) <= 360 && math.Abs(p.Roll) <= 180 &&
		p.FX > 0 && p.FY > 0 && p.FX <= 100*MaxWidth && p.FY <= 100*MaxWidth &&
		p.CX >= 0 && p.CX <= MaxWidth && p.CY >= 0 && p.CY <= MaxHeight
}

func finite(fs ...float64) bool {
	for _, f := range fs {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return false
		}
	}
	return true
}

// ray is the direction, in ground coordinates, of pixel (u, v) of the
// camera at p.
func (p Pose) ray(u, v float64) [3]float64 {
	rad := math.Pi / 180
	sy, cy := math.Sincos(p.Yaw * rad)
	sp, cp := math.Sincos(p.Pitch * rad)
	sr, cr := math.Sincos(p.Roll * rad)
	fwd := [3]float64{sy * cp, cy * cp, -sp}
	right0 := [3]float64{cy, -sy, 0}
	down0 := [3]float64{-sy * sp, -cy * sp, -cp}
	var right, down [3]float64
	for i := range 3 {
		right[i] = right0[i]*cr + down0[i]*sr
		down[i] = down0[i]*cr - right0[i]*sr
	}
	xn, yn := (u-p.CX)/p.FX, (v-p.CY)/p.FY
	var d [3]float64
	for i := range 3 {
		d[i] = fwd[i] + right[i]*xn + down[i]*yn
	}
	return d
}

// at is where pixel (u, v) of the camera at p meets the plane at height h,
// if it does, in front of the camera and within MaxRange.
func (p Pose) at(u, v, h float64) ([2]float64, bool) {
	d := p.ray(u, v)
	if d[2] == 0 {
		return [2]float64{}, false
	}
	k := (h - p.Z) / d[2]
	if k <= 0 {
		return [2]float64{}, false
	}
	x, y := p.X+k*d[0], p.Y+k*d[1]
	if math.Hypot(x-p.X, y-p.Y) > MaxRange {
		return [2]float64{}, false
	}
	return [2]float64{x, y}, true
}

// Apply takes a tracker's update and returns the zone events it gives.
func (s *Site) Apply(u Update) []ZoneEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range u.Ended {
		s.unlink(k)
	}
	pose, posed := s.poses[u.Camera]
	var out []ZoneEvent
	for _, ts := range u.Tracks {
		if ts.Key.Camera != u.Camera {
			continue
		}
		if ts.Class == Drone {
			s.drone[ts.Key] = ts
			continue
		}
		var pos [2]float64
		placed := false
		if posed {
			// A thing stands where its box meets the ground: the
			// middle of the box's bottom edge.
			pos, placed = pose.at(float64(ts.Box.X0+ts.Box.X1)/2, float64(ts.Box.Y1), 0)
		}
		o := s.object(ts, pos, placed)
		o.at = ts.At
		if placed {
			o.pos, o.placed = pos, true
		}
		out = append(out, s.zoneEvents(s.links[ts.Key], o, ts.At)...)
	}
	return out
}

// object returns the object track ts belongs to, fusing it with one of
// its class near pos on another camera, or making a new one. The caller
// holds mu.
func (s *Site) object(ts TrackState, pos [2]float64, placed bool) *object {
	if id, ok := s.links[ts.Key]; ok {
		return s.objects[id]
	}
	var best uint64
	if placed {
		r := s.FuseRadius
		if r <= 0 {
			r = DefaultFuseRadius
		}
		near := math.Inf(1)
		for id, o := range s.objects {
			if o.class != ts.Class || !o.placed || ts.At.Sub(o.at) > fuseAge || o.on(ts.Key.Camera) {
				continue
			}
			if d := math.Hypot(o.pos[0]-pos[0], o.pos[1]-pos[1]); d <= r && (d < near || d == near && id < best) {
				best, near = id, d
			}
		}
	}
	if best == 0 {
		s.next++
		best = s.next
		s.objects[best] = &object{class: ts.Class, tracks: map[TrackKey]bool{}, since: map[string]time.Time{}, dwelt: map[string]bool{}}
	}
	o := s.objects[best]
	o.tracks[ts.Key] = true
	s.links[ts.Key] = best
	return o
}

func (o *object) on(camera string) bool {
	for k := range o.tracks {
		if k.Camera == camera {
			return true
		}
	}
	return false
}

// unlink forgets track k; an object with no track left is gone. The
// caller holds mu.
func (s *Site) unlink(k TrackKey) {
	delete(s.drone, k)
	id, ok := s.links[k]
	if !ok {
		return
	}
	delete(s.links, k)
	o := s.objects[id]
	delete(o.tracks, k)
	if len(o.tracks) == 0 {
		delete(s.objects, id)
	}
}

// zoneEvents updates o's zones at now and returns the events that pass the
// rate limit. The caller holds mu.
func (s *Site) zoneEvents(id uint64, o *object, now time.Time) []ZoneEvent {
	var out []ZoneEvent
	dwell := s.Dwell
	if dwell <= 0 {
		dwell = DefaultDwell
	}
	for _, z := range s.zones {
		if !o.placed || !inside(o.pos, z.Ground) {
			delete(o.since, z.ID)
			delete(o.dwelt, z.ID)
			continue
		}
		since, in := o.since[z.ID]
		kind := ""
		switch {
		case !in:
			o.since[z.ID] = now
			kind = ZoneEnter
		case !o.dwelt[z.ID] && now.Sub(since) >= dwell:
			o.dwelt[z.ID] = true
			kind = ZoneDwell
		}
		if kind == "" {
			continue
		}
		if e, ok := s.pass(z.ID, o.class, now); ok {
			e.Kind, e.Object, e.Count = kind, id, min(s.countZone(z.ID, o.class), MaxCount)
			out = append(out, e)
		}
	}
	return out
}

// pass applies zone's rate limit at now to an event of class: a class with
// no event in the zone in the last minute always passes, so a deer's
// repeats cannot starve a person's entry; repeats past PerMinute events a
// minute are dropped and counted. The caller holds mu.
func (s *Site) pass(zone string, class Class, now time.Time) (ZoneEvent, bool) {
	r := s.rates[zone]
	if r == nil {
		r = &zoneRate{last: map[Class]time.Time{}, coalesced: map[Class]int{}}
		s.rates[zone] = r
	}
	keep := r.sent[:0]
	for _, at := range r.sent {
		if now.Sub(at) < time.Minute {
			keep = append(keep, at)
		}
	}
	r.sent = keep
	at, sent := r.last[class]
	if sent && now.Sub(at) < time.Minute && len(r.sent) >= max(s.PerMinute, 1) {
		r.coalesced[class]++
		return ZoneEvent{}, false
	}
	r.last[class] = now
	r.sent = append(r.sent, now)
	e := ZoneEvent{Zone: zone, Class: class, Coalesced: min(r.coalesced[class], MaxCount), At: now.Unix()}
	delete(r.coalesced, class)
	return e, true
}

// countZone is the objects of class standing in zone. The caller holds mu.
func (s *Site) countZone(zone string, class Class) int {
	n := 0
	for _, o := range s.objects {
		if _, in := o.since[zone]; in && (class == "" || o.class == class) {
			n++
		}
	}
	return n
}

// Answer answers a planner's ask: "count" is the only op, and its answer
// a Count, whose fields hold ids, a class and a number from 0 to MaxCount
// only. Every ask is checked by CheckAsk and must name one of the owner's
// zones, and past AsksPerMinute a minute is ErrBusy, so a planner polling
// counts gets under 4 bits an ask, and only by fake tracks that also
// show as visitors in the zone (the #3730 Security review).
func (s *Site) Answer(a Ask, now time.Time) (Count, error) {
	if err := CheckAsk(a); err != nil {
		return Count{}, err
	}
	if !slices.ContainsFunc(s.zones, func(z Zone) bool { return z.ID == a.Zone }) {
		return Count{}, ErrNotOffered
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := s.asks[:0]
	for _, at := range s.asks {
		if now.Sub(at) < time.Minute {
			keep = append(keep, at)
		}
	}
	s.asks = keep
	if len(s.asks) >= max(s.AsksPerMinute, 1) {
		return Count{}, ErrBusy
	}
	s.asks = append(s.asks, now)
	c := Count{Camera: a.Camera, Zone: a.Zone, Class: a.Class}
	for _, o := range s.objects {
		if a.Class != "" && o.class != a.Class {
			continue
		}
		if _, in := o.since[a.Zone]; a.Zone != "" && !in {
			continue
		}
		if a.Camera != "" && !o.on(a.Camera) {
			continue
		}
		c.N++
	}
	c.N = min(c.N, MaxCount)
	return c, nil
}

// ZoneOf is the first of the owner's zones object stands in, for the
// owner's per-flight tap to show (display data only).
func (s *Site) ZoneOf(object uint64) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.objects[object]
	if o == nil {
		return "", false
	}
	for _, z := range s.zones {
		if _, in := o.since[z.ID]; in {
			return z.ID, true
		}
	}
	return "", false
}

// DroneFix is where the cameras see the drone at now, flying at altitude
// metres above the ground plane (the flight's barometric height, which the
// GPS does not give): each camera that has seen exactly one drone track
// within the last second places the middle of its box at that height, and
// the fix is their mean. A camera seeing two drones gives nothing, so a
// bird taken for a drone cannot pull the fix. A wrong fix can only make the
// GPS cross-check return the drone (DRONE-sim brief decision 10).
func (s *Site) DroneFix(now time.Time, altitude float64) (Fix, bool) {
	if !finite(altitude) || altitude < 0 || altitude > 120 {
		return Fix{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string][]TrackState{}
	for k, ts := range s.drone {
		if d := now.Sub(ts.At); d >= 0 && d <= fixAge {
			seen[k.Camera] = append(seen[k.Camera], ts)
		}
	}
	var sx, sy float64
	n := 0
	for cam, ts := range seen {
		p, ok := s.poses[cam]
		if !ok || len(ts) != 1 {
			continue
		}
		b := ts[0].Box
		g, ok := p.at(float64(b.X0+b.X1)/2, float64(b.Y0+b.Y1)/2, altitude)
		if !ok {
			continue
		}
		sx, sy, n = sx+g[0], sy+g[1], n+1
	}
	if n == 0 {
		return Fix{}, false
	}
	return s.degrees(sx/float64(n), sy/float64(n)), true
}

// degrees turns ground metres into decimal degrees about the origin, to
// six places: over a few hundred metres the earth is flat enough.
func (s *Site) degrees(x, y float64) Fix {
	const perDegree = 111_320.0
	lat := s.lat0 + y/perDegree
	lon := s.lon0 + x/(perDegree*math.Cos(s.lat0*math.Pi/180))
	round := func(f float64) float64 { return math.Round(f*1e6) / 1e6 }
	return Fix{Lat: round(lat), Lon: round(lon)}
}

// inside reports p inside polygon g, by the even-odd rule.
func inside(p [2]float64, g [][2]float64) bool {
	in := false
	for i, j := 0, len(g)-1; i < len(g); j, i = i, i+1 {
		a, b := g[i], g[j]
		if (a[1] > p[1]) != (b[1] > p[1]) && p[0] < (b[0]-a[0])*(p[1]-a[1])/(b[1]-a[1])+a[0] {
			in = !in
		}
	}
	return in
}
