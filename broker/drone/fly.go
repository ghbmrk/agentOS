package drone

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bluenviron/gomavlib/v3/pkg/dialects/common"
)

// usedFile records the flight ids already flown, each with its expiry, so a
// record flies once (P4). Only this process writes it.
const usedFile = "flights-used"

// Follow and GPS/camera check settings.
const (
	followGain         = 0.5 // metres per second of approach per metre of distance
	followMaxSpeedMS   = 5.0
	followStopM        = 2.0
	cameraFixesToRTL   = 3 // consecutive disagreeing camera fixes that send the aircraft home
	followHeartbeatAge = 3 * time.Second
)

// Fly starts one flight from an owner-signed flight record: it verifies the
// record, refuses one already flown, reads the aircraft back against the
// policy, records the id as used, uploads the route's mission and arms in
// AUTO. Nothing else arms the aircraft or uploads a mission (P4). The caller
// keeps the link's heartbeat going (Link.KeepAlive) for the whole flight.
func (h *Holder) Fly(env []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	f, err := LoadFlight(env, h.owner, h.policy, now)
	if err != nil {
		h.log.Printf("drone: flight refused: %v", err)
		return err
	}
	used, err := h.readUsed(now)
	if err != nil {
		return err
	}
	if _, ok := used[f.ID]; ok {
		err := fmt.Errorf("drone: flight %s: already flown", f.ID)
		h.log.Printf("drone: flight refused: %v", err)
		return err
	}
	if err := h.readBackLocked(); err != nil {
		return fmt.Errorf("drone: flight %s refused: %w", f.ID, err)
	}
	used[f.ID] = f.NotAfter
	if err := h.writeUsed(used); err != nil {
		return err
	}
	r, _ := h.policy.Route(f.Route)
	if err := h.link.Upload(MissionMission, FlightMission(h.policy, r)); err != nil {
		return fmt.Errorf("drone: flight %s: %w", f.ID, err)
	}
	if err := h.link.SetMode(ModeAuto); err != nil {
		return fmt.Errorf("drone: flight %s: %w", f.ID, err)
	}
	if err := h.link.accepted(common.MAV_CMD_COMPONENT_ARM_DISARM, [7]float32{1}); err != nil {
		return fmt.Errorf("drone: flight %s: arming: %w", f.ID, err)
	}
	if err := h.link.accepted(common.MAV_CMD_MISSION_START, [7]float32{}); err != nil {
		h.returnLocked("the mission did not start")
		return fmt.Errorf("drone: flight %s: %w", f.ID, err)
	}
	h.flight, h.disagree = f, 0
	h.log.Printf("drone: flight %s on route %q started", f.ID, f.Route)
	return nil
}

// Return sends the aircraft home: RTL to the dock's rally point, where it
// lands and disarms (brief decision 8). It is the only command the core side
// can cause (P5).
func (h *Holder) Return(why string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.returnLocked(why)
}

func (h *Holder) returnLocked(why string) error {
	h.log.Printf("drone: return to dock: %s", why)
	h.flight = nil
	return h.link.SetMode(ModeRTL)
}

// Follow steers the aircraft toward a target the onboard vision reports, by
// a guided velocity the caller renews; it is the stand-in for the vision path
// (#3516 question 1). Only a flight whose record names animals follows. The
// fence bounds it, not the vision: a target outside the boundary leads the
// aircraft to the fence, and the breach returns it (brief decision 9).
func (h *Holder) Follow(target Point) error {
	// Leaving AUTO goes on a heartbeat the aircraft signed after this call
	// began (Link.FreshHeartbeat): one merely received late can predate a
	// return it started since, and ArduPilot starts a low-battery return once. It is asked for
	// outside the lock, so a return never waits behind it.
	var fresh *Heartbeat
	if hb, ok := h.link.LastHeartbeat(); !ok || hb.CustomMode != ModeGuided {
		if f, err := h.link.FreshHeartbeat(); err == nil {
			fresh = &f
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.flight == nil || len(h.flight.Animals) == 0 {
		return errors.New("drone: follow refused: no flight that follows animals")
	}
	if err := checkPoint(target); err != nil {
		return fmt.Errorf("drone: follow refused: %w", err)
	}
	// A return the aircraft started itself (a fence breach, low battery, lost
	// link) ends the flight: follow never takes it out of a return.
	hb, ok := h.link.LastHeartbeat()
	if fresh != nil {
		hb, ok = *fresh, true
	}
	if !ok || time.Since(hb.At) > followHeartbeatAge {
		return errors.New("drone: follow refused: no recent signed heartbeat from the aircraft")
	}
	if !hb.Armed || (hb.CustomMode != ModeAuto && hb.CustomMode != ModeGuided) {
		h.flight = nil
		return errors.New("drone: follow refused: the aircraft is not flying the flight")
	}
	if hb.CustomMode != ModeGuided {
		if fresh == nil {
			return errors.New("drone: follow refused: the aircraft did not answer for its heartbeat")
		}
		if err := h.link.SetMode(ModeGuided); err != nil {
			return err
		}
	}
	pos, err := h.link.Position()
	if err != nil {
		return err
	}
	d := newProjection(Point{Lat: float64(pos.Lat) / 1e7, Lon: float64(pos.Lon) / 1e7}).local(target)
	dist := math.Hypot(d.x, d.y)
	if dist < followStopM {
		return h.link.Velocity(0, 0, 0)
	}
	speed := math.Min(dist*followGain, followMaxSpeedMS)
	return h.link.Velocity(float32(d.y/dist*speed), float32(d.x/dist*speed), 0)
}

// CameraFix compares a camera fix of the aircraft, from the core side and so
// untrusted, with the aircraft's own position. After cameraFixesToRTL
// consecutive fixes further apart than the policy's bound it sends the
// aircraft home. A lying core can therefore only cause a return, the secure
// direction (brief decision 10). It reports whether it sent a return.
func (h *Holder) CameraFix(fix Point) (bool, error) {
	if err := checkPoint(fix); err != nil {
		return false, fmt.Errorf("drone: camera fix refused: %w", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.flight == nil || h.policy == nil {
		return false, nil
	}
	pos, err := h.link.Position()
	if err != nil {
		return false, err
	}
	d := newProjection(fix).local(Point{Lat: float64(pos.Lat) / 1e7, Lon: float64(pos.Lon) / 1e7})
	if math.Hypot(d.x, d.y) <= h.policy.GPSCameraBoundM {
		h.disagree = 0
		return false, nil
	}
	h.disagree++
	if h.disagree < cameraFixesToRTL {
		return false, nil
	}
	return true, h.returnLocked(fmt.Sprintf("%d camera fixes disagree with the aircraft's position by more than %g m",
		h.disagree, h.policy.GPSCameraBoundM))
}

// readUsed reads the used flight ids, dropping those already expired: an
// expired record is refused anyway.
func (h *Holder) readUsed(now time.Time) (map[string]int64, error) {
	used := map[string]int64{}
	b, err := os.ReadFile(filepath.Join(h.state, usedFile))
	if errors.Is(err, os.ErrNotExist) {
		return used, nil
	}
	if err != nil {
		return nil, fmt.Errorf("drone: reading used flights: %w", pathErr(err))
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		id, end, ok := strings.Cut(sc.Text(), " ")
		t, err := strconv.ParseInt(end, 10, 64)
		if !ok || err != nil || !flightID.MatchString(id) {
			return nil, errors.New("drone: the used-flights record is corrupt")
		}
		if now.Before(time.Unix(t, 0)) {
			used[id] = t
		}
	}
	return used, nil
}

func (h *Holder) writeUsed(used map[string]int64) error {
	var b strings.Builder
	for id, t := range used {
		fmt.Fprintf(&b, "%s %d\n", id, t)
	}
	return writeAtomic(filepath.Join(h.state, usedFile), []byte(b.String()))
}
