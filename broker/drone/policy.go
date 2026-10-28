package drone

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
)

// Point is a WGS84 position in degrees.
type Point struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// Waypoint is a route position; AltM is metres above the dock.
type Waypoint struct {
	Lat  float64 `json:"lat"`
	Lon  float64 `json:"lon"`
	AltM float64 `json:"alt_m"`
}

// Route is a named route of the policy (NET-2: a flight is on one named
// route). A flight leaves the dock, flies the waypoints in order and returns.
type Route struct {
	Name      string     `json:"name"`
	Waypoints []Waypoint `json:"waypoints"`
}

// Dock is where the aircraft lands; RadiusM is how close a landing counts
// as at the dock.
type Dock struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	RadiusM float64 `json:"radius_m"`
}

// Policy is the owner-signed flight policy (brief decision 5). Every field is
// required: the record is canonical JSON, so a missing field fails the
// canonical-form check at load.
type Policy struct {
	Version         uint64    `json:"version"`
	Boundary        []Point   `json:"boundary"`
	CeilingM        float64   `json:"ceiling_m"`
	FenceMarginM    float64   `json:"fence_margin_m"`
	NoFly           [][]Point `json:"no_fly"`
	Routes          []Route   `json:"routes"`
	Dock            Dock      `json:"dock"`
	LowBatteryV     float64   `json:"low_battery_v"`
	LostLinkS       float64   `json:"lost_link_s"`
	GPSCameraBoundM float64   `json:"gps_camera_bound_m"`

	raw []byte // the signed canonical bytes
}

// Bounds the policy is held to. The ceiling is the Part 107 limit (400 ft);
// the lost-link range is FS_GCS_TIMEOUT's documented range at the pin.
const (
	maxCeilingM     = 121.0
	minFenceMarginM = 1.0
	maxFenceMarginM = 10.0
	minRTLAltM      = 5.0
	minWaypointAltM = 2.0
	maxDockRadiusM  = 20.0
	maxLowBatteryV  = 60.0
	minLostLinkS    = 2.0
	maxLostLinkS    = 120.0
	maxGPSBoundM    = 100.0
	maxSpanM        = 10000.0
	maxVertices     = 64
	maxNoFly        = 16
	maxRoutes       = 32
	maxWaypoints    = 100
	maxEnvelope     = 1 << 20
)

// policyDomain separates a policy signature from any other use of the owner key.
const policyDomain = "agentos/drone/policy/v1\x00"

var routeName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

type envelope struct {
	Policy json.RawMessage `json:"policy"`
	Sig    string          `json:"sig"`
}

// policyMessage is what the owner signs: the domain, then the canonical record.
func policyMessage(raw []byte) []byte {
	return append([]byte(policyDomain), raw...)
}

// LoadPolicy verifies a signed policy envelope against the owner's key and
// returns the policy, or nil and an error; nothing is derived from a policy
// that fails. loaded is the policy in force (nil if none): an older version is
// refused, and the same version only when its bytes are identical (NET-4: a
// new limit or route comes only as a newer signed version).
func LoadPolicy(env []byte, owner ed25519.PublicKey, loaded *Policy) (*Policy, error) {
	if len(owner) != ed25519.PublicKeySize {
		return nil, errors.New("drone: policy: owner key is not an Ed25519 public key")
	}
	if len(env) > maxEnvelope {
		return nil, errors.New("drone: policy: envelope too large")
	}
	var e envelope
	if err := strictDecode(env, &e); err != nil {
		return nil, fmt.Errorf("drone: policy: envelope: %w", err)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(e.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("drone: policy: signature is malformed")
	}
	if len(e.Policy) == 0 || !ed25519.Verify(owner, policyMessage(e.Policy), sig) {
		return nil, errors.New("drone: policy: signature does not verify under the owner key")
	}
	var p Policy
	if err := strictDecode(e.Policy, &p); err != nil {
		return nil, fmt.Errorf("drone: policy: record: %w", err)
	}
	canon, err := json.Marshal(&p)
	if err != nil || !bytes.Equal(canon, e.Policy) {
		return nil, errors.New("drone: policy: record is not in canonical form (a field missing, extra, reordered or respelled)")
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("drone: policy: %w", err)
	}
	if loaded != nil {
		switch {
		case p.Version < loaded.Version:
			return nil, fmt.Errorf("drone: policy: version %d is older than the loaded %d", p.Version, loaded.Version)
		case p.Version == loaded.Version && !bytes.Equal(e.Policy, loaded.raw):
			return nil, fmt.Errorf("drone: policy: version %d differs from the loaded record of the same version", p.Version)
		}
	}
	p.raw = append([]byte(nil), e.Policy...)
	return &p, nil
}

// Raw returns the policy's signed canonical bytes.
func (p *Policy) Raw() []byte { return append([]byte(nil), p.raw...) }

// Route returns the named route.
func (p *Policy) Route(name string) (Route, bool) {
	for _, r := range p.Routes {
		if r.Name == name {
			return r, true
		}
	}
	return Route{}, false
}

func strictDecode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errors.New("malformed JSON or an unknown field")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing data after the object")
	}
	return nil
}

func (p *Policy) validate() error {
	if p.Version < 1 {
		return errors.New("version must be at least 1")
	}
	if err := checkPoint(Point{p.Dock.Lat, p.Dock.Lon}); err != nil {
		return fmt.Errorf("dock: %w", err)
	}
	pr := newProjection(Point{p.Dock.Lat, p.Dock.Lon})
	if !inRange(p.CeilingM, 0, maxCeilingM) || p.CeilingM == 0 {
		return fmt.Errorf("ceiling %v m is outside (0, %v]", p.CeilingM, maxCeilingM)
	}
	if !inRange(p.FenceMarginM, minFenceMarginM, maxFenceMarginM) {
		return fmt.Errorf("fence margin %v m is outside [%v, %v]", p.FenceMarginM, minFenceMarginM, maxFenceMarginM)
	}
	if p.CeilingM-2*p.FenceMarginM < minRTLAltM {
		return fmt.Errorf("ceiling %v m leaves no return altitude of %v m below the fence margin", p.CeilingM, minRTLAltM)
	}
	if !inRange(p.Dock.RadiusM, 0, maxDockRadiusM) || p.Dock.RadiusM == 0 {
		return fmt.Errorf("dock radius %v m is outside (0, %v]", p.Dock.RadiusM, maxDockRadiusM)
	}
	if !inRange(p.LowBatteryV, 0, maxLowBatteryV) || p.LowBatteryV == 0 {
		return fmt.Errorf("low-battery threshold %v V is outside (0, %v]", p.LowBatteryV, maxLowBatteryV)
	}
	if !inRange(p.LostLinkS, minLostLinkS, maxLostLinkS) {
		return fmt.Errorf("lost-link timeout %v s is outside [%v, %v]", p.LostLinkS, minLostLinkS, maxLostLinkS)
	}
	if !inRange(p.GPSCameraBoundM, 0, maxGPSBoundM) || p.GPSCameraBoundM == 0 {
		return fmt.Errorf("GPS/camera bound %v m is outside (0, %v]", p.GPSCameraBoundM, maxGPSBoundM)
	}
	boundary, err := polygon(pr, p.Boundary)
	if err != nil {
		return fmt.Errorf("boundary: %w", err)
	}
	if len(p.NoFly) > maxNoFly {
		return fmt.Errorf("%d no-fly zones, at most %d", len(p.NoFly), maxNoFly)
	}
	var zones [][]vec
	for i, z := range p.NoFly {
		poly, err := polygon(pr, z)
		if err != nil {
			return fmt.Errorf("no-fly zone %d: %w", i, err)
		}
		zones = append(zones, poly)
	}
	m := p.FenceMarginM
	dock := pr.local(Point{p.Dock.Lat, p.Dock.Lon})
	if err := pointClear(dock, boundary, zones, m); err != nil {
		return fmt.Errorf("dock: %w", err)
	}
	if len(p.Routes) == 0 || len(p.Routes) > maxRoutes {
		return fmt.Errorf("%d routes, want 1 to %d", len(p.Routes), maxRoutes)
	}
	for i, r := range p.Routes {
		if !routeName.MatchString(r.Name) {
			return fmt.Errorf("route %d: name %q is not [a-z0-9-], at most 32", i, r.Name)
		}
		if i > 0 && r.Name <= p.Routes[i-1].Name {
			return fmt.Errorf("route %q: routes must be sorted by name with no repeat", r.Name)
		}
		if len(r.Waypoints) == 0 || len(r.Waypoints) > maxWaypoints {
			return fmt.Errorf("route %q: %d waypoints, want 1 to %d", r.Name, len(r.Waypoints), maxWaypoints)
		}
		path := []vec{dock}
		for j, w := range r.Waypoints {
			if err := checkPoint(Point{w.Lat, w.Lon}); err != nil {
				return fmt.Errorf("route %q waypoint %d: %w", r.Name, j, err)
			}
			if !inRange(w.AltM, minWaypointAltM, p.CeilingM-m) {
				return fmt.Errorf("route %q waypoint %d: altitude %v m is outside [%v, ceiling %v less margin %v]", r.Name, j, w.AltM, minWaypointAltM, p.CeilingM, m)
			}
			v := pr.local(Point{w.Lat, w.Lon})
			if err := pointClear(v, boundary, zones, m); err != nil {
				return fmt.Errorf("route %q waypoint %d: %w", r.Name, j, err)
			}
			path = append(path, v)
		}
		path = append(path, dock)
		for j := 1; j < len(path); j++ {
			if err := segmentClear(path[j-1], path[j], boundary, zones, m); err != nil {
				return fmt.Errorf("route %q leg %d: %w", r.Name, j, err)
			}
		}
	}
	return nil
}

func inRange(v, lo, hi float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= lo && v <= hi
}

func checkPoint(q Point) error {
	if !inRange(q.Lat, -90, 90) || !inRange(q.Lon, -180, 180) {
		return fmt.Errorf("position %v,%v is not a valid latitude and longitude", q.Lat, q.Lon)
	}
	return nil
}

// polygon checks and projects a polygon: 3 to maxVertices valid vertices
// within maxSpanM of the dock, no repeated vertex, no self-intersection.
func polygon(pr projection, pts []Point) ([]vec, error) {
	if len(pts) < 3 || len(pts) > maxVertices {
		return nil, fmt.Errorf("%d vertices, want 3 to %d", len(pts), maxVertices)
	}
	out := make([]vec, len(pts))
	for i, q := range pts {
		if err := checkPoint(q); err != nil {
			return nil, fmt.Errorf("vertex %d: %w", i, err)
		}
		out[i] = pr.local(q)
		if math.Hypot(out[i].x, out[i].y) > maxSpanM {
			return nil, fmt.Errorf("vertex %d is over %v m from the dock", i, maxSpanM)
		}
	}
	if !simple(out) {
		return nil, errors.New("polygon repeats a vertex or crosses itself")
	}
	return out, nil
}

// pointClear holds a point inside the boundary and outside every no-fly zone,
// at least m from every edge.
func pointClear(v vec, boundary []vec, zones [][]vec, m float64) error {
	if !inside(v, boundary) || edgeDist(v, boundary) < m {
		return fmt.Errorf("is not inside the boundary by the %v m margin", m)
	}
	for i, z := range zones {
		if inside(v, z) || edgeDist(v, z) < m {
			return fmt.Errorf("is not outside no-fly zone %d by the %v m margin", i, m)
		}
	}
	return nil
}

// segmentClear holds a leg at least m from every boundary and zone edge; with
// both ends clear, it then never leaves the boundary or enters a zone.
func segmentClear(a, b vec, boundary []vec, zones [][]vec, m float64) error {
	if polySegDist(a, b, boundary) < m {
		return fmt.Errorf("comes within the %v m margin of the boundary or crosses it", m)
	}
	for i, z := range zones {
		if polySegDist(a, b, z) < m {
			return fmt.Errorf("comes within the %v m margin of no-fly zone %d or crosses it", m, i)
		}
	}
	return nil
}
