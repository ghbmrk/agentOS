package drone

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Flight is an owner-signed flight record: one turn-on of the aircraft on
// one named route of the policy, used once, before NotAfter (NET-6, brief
// decision 6). Animals are the kinds the onboard vision may follow; empty
// means it follows none.
type Flight struct {
	ID       string   `json:"id"`
	Route    string   `json:"route"`
	Animals  []string `json:"animals"`
	NotAfter int64    `json:"not_after"` // Unix seconds
}

// flightDomain separates a flight signature from a policy signature made
// with the same owner key.
const flightDomain = "agentos/drone/flight/v1\x00"

// maxFlightAhead bounds how far ahead a record may be signed, so a record
// cannot be kept for a later day.
const (
	maxFlightAhead = 24 * time.Hour
	maxAnimals     = 8
	maxFlightEnv   = 4096
)

var (
	flightID   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	animalKind = regexp.MustCompile(`^[a-z][a-z-]{0,31}$`)
)

type flightEnvelope struct {
	Flight json.RawMessage `json:"flight"`
	Sig    string          `json:"sig"`
}

// flightMessage is what the owner signs: the domain, then the canonical record.
func flightMessage(raw []byte) []byte {
	return append([]byte(flightDomain), raw...)
}

// LoadFlight verifies a signed flight record against the owner's key and the
// policy in force, at time now. It does not check whether the record was
// used; the holder does, under its lock.
func LoadFlight(env []byte, owner ed25519.PublicKey, p *Policy, now time.Time) (*Flight, error) {
	if len(owner) != ed25519.PublicKeySize {
		return nil, errors.New("drone: flight: owner key is not an Ed25519 public key")
	}
	if p == nil {
		return nil, errors.New("drone: flight: no policy loaded")
	}
	if len(env) > maxFlightEnv {
		return nil, errors.New("drone: flight: envelope too large")
	}
	var e flightEnvelope
	if err := strictDecode(env, &e); err != nil {
		return nil, fmt.Errorf("drone: flight: envelope: %w", err)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(e.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("drone: flight: signature is malformed")
	}
	if len(e.Flight) == 0 || !ed25519.Verify(owner, flightMessage(e.Flight), sig) {
		return nil, errors.New("drone: flight: signature does not verify under the owner key")
	}
	var f Flight
	if err := strictDecode(e.Flight, &f); err != nil {
		return nil, fmt.Errorf("drone: flight: record: %w", err)
	}
	canon, err := json.Marshal(&f)
	if err != nil || !bytes.Equal(canon, e.Flight) {
		return nil, errors.New("drone: flight: record is not in canonical form")
	}
	if !flightID.MatchString(f.ID) {
		return nil, errors.New("drone: flight: id is not 32 lowercase hex digits")
	}
	if f.Animals == nil || len(f.Animals) > maxAnimals {
		return nil, fmt.Errorf("drone: flight: animals must be a list of at most %d kinds", maxAnimals)
	}
	for _, a := range f.Animals {
		if !animalKind.MatchString(a) {
			return nil, fmt.Errorf("drone: flight: animal kind %q is not plain", a)
		}
	}
	end := time.Unix(f.NotAfter, 0)
	switch {
	case !now.Before(end):
		return nil, fmt.Errorf("drone: flight %s: expired at %s", f.ID, end.UTC().Format(time.RFC3339))
	case end.Sub(now) > maxFlightAhead:
		return nil, fmt.Errorf("drone: flight %s: expires more than %s ahead", f.ID, maxFlightAhead)
	}
	if _, ok := p.Route(f.Route); !ok {
		return nil, fmt.Errorf("drone: flight %s: the policy has no route %q", f.ID, f.Route)
	}
	return &f, nil
}

// MAVLink mission commands (common.xml).
const (
	cmdNavWaypoint = 16 // MAV_CMD_NAV_WAYPOINT
	cmdNavRTL      = 20 // MAV_CMD_NAV_RETURN_TO_LAUNCH
	cmdNavTakeoff  = 22 // MAV_CMD_NAV_TAKEOFF
)

// FlightMission is the mission for a route: item 0 is home (the aircraft
// replaces it with its own), then take-off to the first waypoint's height,
// the waypoints, and a return, which lands at the dock's rally point.
func FlightMission(p *Policy, r Route) []Item {
	items := []Item{{Command: cmdNavWaypoint, Lat: e7(p.Dock.Lat), Lon: e7(p.Dock.Lon)},
		{Command: cmdNavTakeoff, AltM: float32(r.Waypoints[0].AltM)}}
	for _, w := range r.Waypoints {
		items = append(items, Item{Command: cmdNavWaypoint, Lat: e7(w.Lat), Lon: e7(w.Lon), AltM: float32(w.AltM)})
	}
	return append(items, Item{Command: cmdNavRTL})
}
