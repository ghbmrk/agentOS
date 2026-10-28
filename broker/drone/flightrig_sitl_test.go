//go:build sitl

package drone

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/bluenviron/gomavlib/v3/pkg/dialects/common"
)

// Helpers for the part b SITL tests: flights, and watching the aircraft
// through an observer link that sends no heartbeat after it dials, so that
// it never holds off the aircraft's lost-link return.

// flightRig is a rig with the fixture policy in force, the key-holder's
// heartbeat running, an observer link on another port, and the aircraft
// ready to arm.
func flightRig(t *testing.T) (*rig, *Link) {
	t.Helper()
	r := newRig(t, true)
	stop := r.link.KeepAlive()
	t.Cleanup(stop)
	// Its own signing stream: two links on one stream would race each
	// other's timestamps, and the aircraft refuses the older.
	obs, err := dial(r.sim.Dial(r.sim.Ports()[1]), r.key, time.Now, holderLinkID+1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { obs.Close() })
	if _, err := obs.WaitHeartbeat(time.Time{}, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	waitReady(t, obs)
	return r, obs
}

// waitReady waits until the aircraft reports its pre-arm checks passing (it
// needs a GPS fix and an EKF origin after boot), so a refused arm is not a
// slow EKF.
func waitReady(t *testing.T, obs *Link) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		st, err := obs.SysStatus()
		if err == nil && st.OnboardControlSensorsHealth&common.MAV_SYS_STATUS_PREARM_CHECK != 0 {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("the aircraft's pre-arm checks did not pass in 3 minutes")
}

// newFlight is a fresh flight record for route, following animals.
func newFlight(t *testing.T, route string, animals ...string) Flight {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	if animals == nil {
		animals = []string{}
	}
	return Flight{ID: hex.EncodeToString(id[:]), Route: route, Animals: animals, NotAfter: time.Now().Add(time.Hour).Unix()}
}

// where is the aircraft's reported position and height above home.
type where struct {
	At   Point
	AltM float64
}

func position(t *testing.T, l *Link) where {
	t.Helper()
	p, err := l.Position()
	if err != nil {
		t.Fatalf("reading the aircraft's position: %v", err)
	}
	return where{Point{Lat: float64(p.Lat) / 1e7, Lon: float64(p.Lon) / 1e7}, float64(p.RelativeAlt) / 1000}
}

// metres is the ground distance between two points.
func metres(a, b Point) float64 {
	v := newProjection(a).local(b)
	return math.Hypot(v.x, v.y)
}

// heartbeat is the aircraft's next signed heartbeat on l.
func heartbeat(t *testing.T, l *Link) Heartbeat {
	t.Helper()
	hb, err := l.WaitHeartbeat(time.Now(), 10*time.Second)
	if err != nil {
		t.Fatalf("no signed heartbeat: %v", err)
	}
	return hb
}

// waitFor polls the aircraft once a second until cond holds.
func waitFor(t *testing.T, l *Link, what string, timeout time.Duration, cond func(Heartbeat, where) bool) (Heartbeat, where) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var hb Heartbeat
	var w where
	for time.Now().Before(deadline) {
		hb, w = heartbeat(t, l), position(t, l)
		if cond(hb, w) {
			return hb, w
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s: not within %s (last: mode %d armed %v at %+v)", what, timeout, hb.CustomMode, hb.Armed, w)
	return hb, w
}

// airborne waits for the take-off to finish.
func airborne(t *testing.T, l *Link) {
	t.Helper()
	waitFor(t, l, "take-off", 2*time.Minute, func(hb Heartbeat, w where) bool { return hb.Armed && w.AltM > 20 })
}

// requireLandedAtDock waits for the aircraft to land and disarm, and
// requires it within the policy's dock radius.
func requireLandedAtDock(t *testing.T, l *Link, what string) {
	t.Helper()
	_, w := waitFor(t, l, what+": landed and disarmed", 4*time.Minute, func(hb Heartbeat, w where) bool { return !hb.Armed })
	if d := metres(testDock, w.At); d > testPolicy().Dock.RadiusM {
		t.Errorf("%s: landed %.1f m from the dock, outside its %g m radius", what, d, testPolicy().Dock.RadiusM)
	}
}

// requireDisarmed requires the aircraft on the ground, disarmed.
func requireDisarmed(t *testing.T, l *Link, what string) {
	t.Helper()
	if hb := heartbeat(t, l); hb.Armed {
		t.Fatalf("%s: the aircraft is armed", what)
	}
}

// logged waits briefly for the key-holder to log want after mark.
func (r *rig) logged(mark int, want string) bool {
	for i := 0; i < 20; i++ {
		if strings.Contains(r.logs.String()[mark:], want) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// follow walks a target along path at speedMS, feeding it to the key-holder
// as the vision stand-in does, twice a second, and records the aircraft's
// track. It stops at the end of the path plus settle, or at the first
// refused follow, whose error it returns.
func follow(t *testing.T, r *rig, obs *Link, path []Point, speedMS float64, settle time.Duration) ([]where, error) {
	t.Helper()
	var track []where
	start := time.Now()
	for {
		target, done := along(path, time.Since(start).Seconds()*speedMS)
		if done && time.Since(start) > time.Duration(pathLength(path)/speedMS*float64(time.Second))+settle {
			return track, nil
		}
		if err := r.h.Follow(target); err != nil {
			return track, err
		}
		track = append(track, position(t, obs))
		time.Sleep(500 * time.Millisecond)
	}
}

func pathLength(path []Point) float64 {
	var n float64
	for i := 1; i < len(path); i++ {
		n += metres(path[i-1], path[i])
	}
	return n
}

// along is the point d metres along path, and whether d is past its end.
func along(path []Point, d float64) (Point, bool) {
	for i := 1; i < len(path); i++ {
		leg := metres(path[i-1], path[i])
		if d <= leg {
			f := d / leg
			return Point{Lat: path[i-1].Lat + f*(path[i].Lat-path[i-1].Lat),
				Lon: path[i-1].Lon + f*(path[i].Lon-path[i-1].Lon)}, false
		}
		d -= leg
	}
	return path[len(path)-1], true
}
